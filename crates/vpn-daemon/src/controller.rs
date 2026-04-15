use anyhow::{anyhow, Result};
use parking_lot::{Mutex, RwLock};
use rand::random;
use serde_json::json;
use std::{
    env,
    net::ToSocketAddrs,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinHandle,
};
use uuid::Uuid;
use vpn_config::load_default_config;
use vpn_ipc::{DaemonMetrics, DaemonStatus, IpcRequest, IpcResponse};
use vpn_logger::{EventLogger, LoggerConfig};

#[derive(Clone, Debug)]
struct ControllerSettings {
    ipc_addr: String,
    server: String,
    mode: String,
    admin_secret: Option<String>,
    log_file: Option<PathBuf>,
    connect_delay: Duration,
    packet_tick: Duration,
}

struct ControllerState {
    status: Arc<RwLock<DaemonStatus>>,
    metrics: Arc<RwLock<DaemonMetrics>>,
    logger: Arc<EventLogger>,
    started_at: Instant,
    settings: ControllerSettings,
    simulation_stop: Mutex<Option<watch::Sender<bool>>>,
}

pub async fn run_controller() -> Result<()> {
    let settings = load_settings()?;
    validate_ipc_addr(&settings.ipc_addr)?;

    let logger = Arc::new(
        EventLogger::new(LoggerConfig {
            service_name: "vpn-daemon".to_string(),
            json_log_path: settings.log_file.clone(),
            mysql_url: None,
            chain_key: random(),
        })
        .await?,
    );

    let initial_timestamp = unix_millis_string();
    let state = Arc::new(ControllerState {
        status: Arc::new(RwLock::new(DaemonStatus {
            connected: false,
            server: Some(settings.server.clone()),
            session_id: None,
            active_circuit: None,
            rotation_state: Some("Idle".to_string()),
            mode: Some(settings.mode.clone()),
            last_error: None,
            last_transition_at: Some(initial_timestamp.clone()),
        })),
        metrics: Arc::new(RwLock::new(DaemonMetrics {
            mode: settings.mode.clone(),
            uptime_secs: 0,
            last_connect_latency_ms: None,
            packets_tx: 0,
            packets_rx: 0,
            request_count: 0,
            error_count: 0,
            error_rate: 0.0,
            connect_count: 0,
            disconnect_count: 0,
            last_transition_at: Some(initial_timestamp.clone()),
        })),
        logger: Arc::clone(&logger),
        started_at: Instant::now(),
        settings: settings.clone(),
        simulation_stop: Mutex::new(None),
    });

    logger
        .log(
            "daemon",
            "controller_starting",
            json!({
                "ipc_addr": settings.ipc_addr,
                "server": settings.server,
                "mode": settings.mode,
            }),
        )
        .await?;

    let (ipc_tx, mut ipc_rx) =
        mpsc::channel::<(IpcRequest, tokio::sync::oneshot::Sender<IpcResponse>)>(32);
    let ipc_addr = settings.ipc_addr.clone();
    let mut ipc_server: JoinHandle<Result<()>> =
        tokio::spawn(async move { vpn_ipc::serve(&ipc_addr, ipc_tx).await });

    loop {
        tokio::select! {
            maybe_request = ipc_rx.recv() => {
                let Some((request, response_tx)) = maybe_request else {
                    break;
                };

                increment_request_count(&state);
                let response = handle_request(&state, request).await;
                let _ = response_tx.send(response);
            }
            result = &mut ipc_server => {
                let server_result = result.map_err(|error| anyhow!("ipc server task join error: {error}"))?;
                server_result?;
                break;
            }
            signal = tokio::signal::ctrl_c() => {
                if signal.is_ok() {
                    let _ = disconnect_mock(&state, None).await;
                }
                break;
            }
        }
    }

    logger
        .log(
            "daemon",
            "controller_stopped",
            json!({
                "mode": state.settings.mode,
                "uptime_secs": state.started_at.elapsed().as_secs(),
            }),
        )
        .await?;

    Ok(())
}

async fn handle_request(state: &Arc<ControllerState>, request: IpcRequest) -> IpcResponse {
    match request {
        IpcRequest::Status => IpcResponse::Status {
            status: state.status.read().clone(),
        },
        IpcRequest::Metrics => IpcResponse::Metrics {
            metrics: snapshot_metrics(state),
        },
        IpcRequest::Connect => match connect_mock(state).await {
            Ok(message) => IpcResponse::Ok { message },
            Err(error) => {
                record_error(state, &error.to_string());
                IpcResponse::Error {
                    message: error.to_string(),
                }
            }
        },
        IpcRequest::Disconnect { admin_secret } => match disconnect_mock(state, admin_secret).await
        {
            Ok(message) => IpcResponse::Ok { message },
            Err(error) => {
                record_error(state, &error.to_string());
                IpcResponse::Error {
                    message: error.to_string(),
                }
            }
        },
    }
}

async fn connect_mock(state: &Arc<ControllerState>) -> Result<String> {
    if state.status.read().connected {
        return Ok("daemon is already connected".to_string());
    }

    let start = Instant::now();
    state
        .logger
        .log(
            "connection",
            "connect_requested",
            json!({
                "mode": state.settings.mode,
                "server": state.settings.server,
            }),
        )
        .await?;

    tokio::time::sleep(state.settings.connect_delay).await;

    let transition_at = unix_millis_string();
    let session_id = random::<u64>();
    let active_circuit = Uuid::new_v4().to_string();
    let latency_ms = start.elapsed().as_millis() as u64;

    {
        let mut status = state.status.write();
        status.connected = true;
        status.server = Some(state.settings.server.clone());
        status.session_id = Some(session_id);
        status.active_circuit = Some(active_circuit.clone());
        status.rotation_state = Some("Stable".to_string());
        status.mode = Some(state.settings.mode.clone());
        status.last_error = None;
        status.last_transition_at = Some(transition_at.clone());
    }

    {
        let mut metrics = state.metrics.write();
        metrics.last_connect_latency_ms = Some(latency_ms);
        metrics.connect_count = metrics.connect_count.saturating_add(1);
        metrics.last_transition_at = Some(transition_at.clone());
    }

    start_simulation_loop(Arc::clone(state), session_id, active_circuit.clone());

    state
        .logger
        .log(
            "connection",
            "connected",
            json!({
                "mode": state.settings.mode,
                "server": state.settings.server,
                "session_id": session_id,
                "active_circuit": active_circuit,
                "latency_ms": latency_ms,
            }),
        )
        .await?;

    Ok(format!(
        "connected to {} in {}ms ({})",
        state.settings.server, latency_ms, state.settings.mode
    ))
}

async fn disconnect_mock(
    state: &Arc<ControllerState>,
    admin_secret: Option<String>,
) -> Result<String> {
    if !authorize_disconnect(
        state.settings.admin_secret.as_deref(),
        admin_secret.as_deref(),
    ) {
        return Err(anyhow!("admin authorization failed"));
    }

    if !state.status.read().connected {
        return Ok("daemon is already disconnected".to_string());
    }

    if let Some(stop_tx) = state.simulation_stop.lock().take() {
        let _ = stop_tx.send(true);
    }

    let transition_at = unix_millis_string();
    {
        let mut status = state.status.write();
        status.connected = false;
        status.session_id = None;
        status.active_circuit = None;
        status.rotation_state = Some("Idle".to_string());
        status.last_error = None;
        status.last_transition_at = Some(transition_at.clone());
    }

    {
        let mut metrics = state.metrics.write();
        metrics.disconnect_count = metrics.disconnect_count.saturating_add(1);
        metrics.last_transition_at = Some(transition_at.clone());
    }

    state
        .logger
        .log_warn(
            "connection",
            "disconnected",
            json!({
                "mode": state.settings.mode,
                "server": state.settings.server,
            }),
        )
        .await?;

    Ok("disconnect completed".to_string())
}

fn start_simulation_loop(state: Arc<ControllerState>, session_id: u64, active_circuit: String) {
    if let Some(stop_tx) = state.simulation_stop.lock().take() {
        let _ = stop_tx.send(true);
    }

    let (stop_tx, mut stop_rx) = watch::channel(false);
    *state.simulation_stop.lock() = Some(stop_tx);
    let packet_tick = state.settings.packet_tick;
    let logger = Arc::clone(&state.logger);

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(packet_tick);
        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    break;
                }
                _ = interval.tick() => {
                    let (packets_tx, packets_rx) = {
                        let mut metrics = state.metrics.write();
                        metrics.packets_tx = metrics.packets_tx.saturating_add(8);
                        metrics.packets_rx = metrics.packets_rx.saturating_add(6);
                        (metrics.packets_tx, metrics.packets_rx)
                    };

                    let _ = logger.log_debug(
                        "traffic",
                        "mock_traffic_tick",
                        json!({
                            "session_id": session_id,
                            "active_circuit": active_circuit,
                            "packets_tx": packets_tx,
                            "packets_rx": packets_rx,
                        }),
                    ).await;
                }
            }
        }
    });
}

fn load_settings() -> Result<ControllerSettings> {
    let server = env::var("AEGIS_SERVER_ENDPOINT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            load_default_config()
                .ok()
                .map(|config| config.client.server_endpoint)
        })
        .unwrap_or_else(|| "mock://local-simulator".to_string());

    let connect_delay_ms = env::var("AEGIS_CONNECT_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(350);
    let packet_tick_ms = env::var("AEGIS_PACKET_TICK_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(1_000);

    Ok(ControllerSettings {
        ipc_addr: env::var("AEGIS_DAEMON_IPC_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:7788".to_string()),
        server,
        mode: env::var("AEGIS_DAEMON_MODE").unwrap_or_else(|_| "mock".to_string()),
        admin_secret: env::var("AEGIS_ADMIN_SECRET")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        log_file: Some(PathBuf::from(
            env::var("AEGIS_LOG_PATH").unwrap_or_else(|_| "logs/aegis-daemon.jsonl".to_string()),
        )),
        connect_delay: Duration::from_millis(connect_delay_ms),
        packet_tick: Duration::from_millis(packet_tick_ms),
    })
}

fn snapshot_metrics(state: &Arc<ControllerState>) -> DaemonMetrics {
    let mut metrics = state.metrics.read().clone();
    metrics.uptime_secs = state.started_at.elapsed().as_secs();
    metrics.mode = state.settings.mode.clone();
    metrics.error_rate = if metrics.request_count == 0 {
        0.0
    } else {
        metrics.error_count as f64 / metrics.request_count as f64
    };
    metrics
}

fn increment_request_count(state: &Arc<ControllerState>) {
    let mut metrics = state.metrics.write();
    metrics.request_count = metrics.request_count.saturating_add(1);
}

fn record_error(state: &Arc<ControllerState>, message: &str) {
    let timestamp = unix_millis_string();
    {
        let mut metrics = state.metrics.write();
        metrics.error_count = metrics.error_count.saturating_add(1);
        metrics.last_transition_at = Some(timestamp.clone());
    }
    {
        let mut status = state.status.write();
        status.last_error = Some(message.to_string());
        status.last_transition_at = Some(timestamp);
    }
}

fn authorize_disconnect(expected: Option<&str>, supplied: Option<&str>) -> bool {
    match expected {
        None => true,
        Some(expected) => supplied
            .map(|candidate| constant_time_eq(expected.as_bytes(), candidate.as_bytes()))
            .unwrap_or(false),
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (lhs, rhs) in left.iter().zip(right.iter()) {
        diff |= lhs ^ rhs;
    }
    diff == 0
}

fn unix_millis_string() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string()
}

fn validate_ipc_addr(addr: &str) -> Result<()> {
    if env::var("AEGIS_ALLOW_NON_LOOPBACK_IPC")
        .ok()
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
    {
        return Ok(());
    }

    let socket = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("ipc address {addr} did not resolve to a socket address"))?;
    if !socket.ip().is_loopback() {
        return Err(anyhow!(
            "ipc address {addr} must resolve to a loopback interface for local-only control"
        ));
    }
    Ok(())
}
