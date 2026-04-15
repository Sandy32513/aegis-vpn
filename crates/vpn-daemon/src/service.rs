use crate::{
    cleanup::{self, CleanupState, StateMachine, TransitionEvent},
    cleanup_manager::{CleanupManager, RouteCleanup, TunCleanup, WfpCleanup},
    config::RunConfig,
    control_plane::resolve_run_settings,
    runtime_mode::RuntimeMode,
};
use anyhow::{anyhow, Result};
use parking_lot::{Mutex, RwLock};
use rand::random;
use serde_json::json;
use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{error, info, warn};
use uuid::Uuid;
use vpn_crypto::{
    build_confirm, derive_session_keys, random_nonce, verify_confirm, verify_server_static_proof,
    EphemeralKeyPair, Role, SessionCrypto,
};
use vpn_ipc::{DaemonStatus, IpcRequest, IpcResponse};
use vpn_logger::{EventLogger, LoggerConfig};
use vpn_rotation::{CircuitDescriptor, RotationManager, RotationState};
use vpn_routing::{FlowKey, FlowTable, PolicySet, RuleAction};
use vpn_transport::{DataFrame, UdpTransport, WireFrame};
use vpn_tun::{TunConfig, TunDevice};

#[derive(Clone)]
struct ClientCircuit {
    descriptor: CircuitDescriptor,
    crypto: Arc<SessionCrypto>,
    transport: UdpTransport,
}

#[derive(Clone)]
struct CircuitHandle {
    circuit: Arc<ClientCircuit>,
    stop_tx: watch::Sender<bool>,
}

struct DaemonRuntime {
    status: Arc<RwLock<DaemonStatus>>,
    logger: Arc<EventLogger>,
    flow_table: Arc<FlowTable>,
    policy: PolicySet,
    rotation: Arc<Mutex<RotationManager>>,
    circuits: Arc<RwLock<HashMap<Uuid, CircuitHandle>>>,
    shutdown: Arc<AtomicBool>,
    admin_secret: Option<String>,
    trusted_server_public_key: Option<[u8; 32]>,
    started_at: Instant,
    connect_latency_ms: u64,
    packets_tx: AtomicU64,
    packets_rx: AtomicU64,
    request_count: AtomicU64,
    error_count: AtomicU64,
}

pub async fn run_daemon(config: RunConfig) -> Result<()> {
    let settings = resolve_run_settings(&config)?;

    // PART 3: Detect runtime mode
    let runtime_mode = RuntimeMode::detect(settings.safe_mode);
    info!("daemon: runtime mode = {}", runtime_mode);

    validate_ipc_addr(&settings.ipc_addr)?;

    // PART 6: Initialize CleanupManager
    let mut cleanup_mgr = CleanupManager::new();
    cleanup_mgr.register(Box::new(RouteCleanup::new(&settings.tun_name)));
    if settings.kill_switch {
        cleanup_mgr.register(Box::new(WfpCleanup::new()));
    }
    cleanup_mgr.register(Box::new(TunCleanup::new(&settings.tun_name)));
    let cleanup_mgr = Arc::new(cleanup_mgr);

    let server: SocketAddr = settings.server.parse()?;

    let cleanup_state = Arc::new(CleanupState {
        tun_name: settings.tun_name.clone(),
        kill_switch: settings.kill_switch,
        server_bind: Some(settings.bind.clone()),
    });

    // PART 1.4: Orphan detection — scan for leftover resources from previous crash
    cleanup::detect_and_clean_orphans(&settings.tun_name, settings.kill_switch);

    // PART 1.1: Install panic hook for crash-time cleanup
    cleanup::install_panic_hook(Arc::clone(&cleanup_state));

    // PART 1.1: Register signal handlers (SIGINT/SIGTERM on Linux, CTRL+C on Windows)
    cleanup::register_signal_handlers().await?;

    // PART 3: Initialize state machine
    let state_machine = Arc::new(StateMachine::new());

    let logger = Arc::new(
        EventLogger::new(LoggerConfig {
            service_name: "vpn-daemon".to_string(),
            json_log_path: settings.log_file.clone(),
            mysql_url: settings.mysql_url.clone(),
            chain_key: random(),
        })
        .await?,
    );

    // Log runtime mode info
    let is_admin = {
        #[cfg(windows)]
        {
            vpn_platform_windows::admin::is_admin()
        }
        #[cfg(not(windows))]
        {
            false
        }
    };

    logger
        .log(
            "daemon",
            "starting",
            json!({
                "server": settings.server.clone(),
                "hops": settings.hops,
                "identity": settings.identity.as_ref().map(|id| id.fingerprint.clone()),
                "runtime_mode": runtime_mode.to_string(),
                "is_admin": is_admin
            }),
        )
        .await?;

    if settings.trusted_server_public_key.is_none() {
        logger
            .log_warn(
                "security",
                "server_trust_anchor_missing",
                json!({ "server": settings.server.clone() }),
            )
            .await?;
    }

    // PART 3: Transition to Connecting
    state_machine
        .try_transition(TransitionEvent::ConnectInitiated)
        .map_err(|e| anyhow!("{e}"))?;

    // PART 3: In Limited/Safe mode, log and degrade gracefully
    if runtime_mode.is_limited() {
        warn!("daemon: running in LIMITED mode — TUN creation and WFP kill switch are disabled");
        warn!("daemon: daemon will run in IPC-only mode for status/control");
    }
    if runtime_mode.is_safe() {
        info!("daemon: running in SAFE mode — all OS operations are simulated");
    }

    let tun_config = TunConfig {
        name: settings.tun_name.clone(),
        address_cidr: settings.tun_addr.clone(),
        mtu: settings.mtu,
    };

    let tun = match create_platform_tun_mode(&tun_config, server, &runtime_mode) {
        Ok(tun) => tun,
        Err(e) => {
            state_machine
                .try_transition(TransitionEvent::ConnectFailed(e.to_string()))
                .ok();
            // Cleanup any partial resources
            cleanup::perform_cleanup(&cleanup_state);
            // Also run CleanupManager
            let mgr_errors = cleanup_mgr.cleanup_all();
            if !mgr_errors.is_empty() {
                warn!(
                    "daemon: cleanup manager reported {} errors during failure cleanup",
                    mgr_errors.len()
                );
            }
            return Err(e);
        }
    };
    let tun = Arc::new(Mutex::new(tun));

    let connect_started = Instant::now();

    // In Safe mode, simulate circuit establishment
    let initial = if runtime_mode.is_simulation() {
        info!("daemon: simulating circuit establishment (safe mode)");
        ClientCircuit {
            descriptor: CircuitDescriptor::new(0, server, settings.hops, 1),
            crypto: Arc::new(SessionCrypto::new(vpn_crypto::SessionKeys {
                send_key: [0u8; 32],
                recv_key: [0u8; 32],
                send_iv: [0u8; 12],
                recv_iv: [0u8; 12],
                confirm_key: [0u8; 32],
            })),
            transport: UdpTransport::connect("0.0.0.0:0", server).await?,
        }
    } else {
        match establish_circuit(
            &settings.bind,
            server,
            settings.hops,
            1,
            settings.trusted_server_public_key,
        )
        .await
        {
            Ok(circuit) => circuit,
            Err(e) => {
                state_machine
                    .try_transition(TransitionEvent::ConnectFailed(e.to_string()))
                    .ok();
                cleanup::perform_cleanup(&cleanup_state);
                let _ = cleanup_mgr.cleanup_all();
                return Err(e);
            }
        }
    };

    let tun_name = tun.lock().name().to_string();
    if let Err(e) =
        activate_platform_tun_mode(&tun_name, server, settings.kill_switch, &runtime_mode)
    {
        state_machine
            .try_transition(TransitionEvent::ConnectFailed(e.to_string()))
            .ok();
        cleanup::perform_cleanup(&cleanup_state);
        let _ = cleanup_mgr.cleanup_all();
        return Err(e);
    }

    // PART 3: Connection succeeded
    state_machine
        .try_transition(TransitionEvent::ConnectSucceeded)
        .map_err(|e| anyhow!("{e}"))?;

    let initial_id = initial.descriptor.id;
    let (initial_stop_tx, initial_stop_rx) = watch::channel(false);

    let status = Arc::new(RwLock::new(DaemonStatus {
        connected: true,
        server: Some(server.to_string()),
        session_id: Some(initial.descriptor.session_id),
        active_circuit: Some(initial.descriptor.id.to_string()),
        rotation_state: Some("Stable".to_string()),
        mode: Some("live".to_string()),
        last_error: None,
        last_transition_at: Some(unix_millis_string()),
    }));

    let rotation = Arc::new(Mutex::new(RotationManager::new(
        Duration::from_secs(settings.rotation_interval_secs),
        Duration::from_secs(90),
    )));
    rotation.lock().install_initial(initial.descriptor.clone());

    let circuits = Arc::new(RwLock::new(HashMap::new()));
    circuits.write().insert(
        initial_id,
        CircuitHandle {
            circuit: Arc::new(initial),
            stop_tx: initial_stop_tx.clone(),
        },
    );

    let runtime = Arc::new(DaemonRuntime {
        status: Arc::clone(&status),
        logger: Arc::clone(&logger),
        flow_table: Arc::new(FlowTable::default()),
        policy: PolicySet::default(),
        rotation: Arc::clone(&rotation),
        circuits: Arc::clone(&circuits),
        shutdown: Arc::new(AtomicBool::new(false)),
        admin_secret: load_admin_secret(settings.admin_secret_env.as_deref()),
        trusted_server_public_key: settings.trusted_server_public_key,
        started_at: Instant::now(),
        connect_latency_ms: connect_started.elapsed().as_millis() as u64,
        packets_tx: AtomicU64::new(0),
        packets_rx: AtomicU64::new(0),
        request_count: AtomicU64::new(0),
        error_count: AtomicU64::new(0),
    });

    spawn_inbound_loop(
        circuits.read()[&initial_id].clone(),
        initial_stop_rx,
        Arc::clone(&tun),
        Arc::clone(&logger),
    );

    let (packet_tx, mut packet_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let reader_shutdown = Arc::clone(&runtime.shutdown);
    let tun_reader = Arc::clone(&tun);
    let reader_handle = thread::spawn(move || {
        // PART 7: Pre-allocated buffer — reused across reads to avoid allocation churn
        let mut buf = vec![0u8; 65535];
        while !reader_shutdown.load(Ordering::Relaxed) {
            // PART 7: Batch read — try to read up to 32 packets per iteration
            // to amortize lock acquisition and channel overhead
            let mut batch_count = 0;
            let max_batch = 32;

            while batch_count < max_batch {
                let result = tun_reader.lock().read_packet(&mut buf);
                match result {
                    Ok(size) => {
                        if packet_tx.send(buf[..size].to_vec()).is_err() {
                            return;
                        }
                        batch_count += 1;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        // No more packets — sleep if batch was empty, otherwise yield
                        if batch_count == 0 {
                            thread::sleep(Duration::from_millis(10));
                        }
                        break;
                    }
                    Err(err) => {
                        error!("tun read failed: {err}");
                        return;
                    }
                }
            }
        }
        info!("tun reader thread exiting");
    });

    let sender_runtime = Arc::clone(&runtime);
    let sender_handle = tokio::spawn(async move {
        while let Some(packet) = packet_rx.recv().await {
            if let Err(err) = handle_outbound_packet(&sender_runtime, &packet).await {
                warn!("outbound packet handling failed: {err}");
            }
        }
    });

    let rotation_runtime = Arc::clone(&runtime);
    let rotation_bind = settings.bind.clone();
    let rotation_hops = settings.hops;
    let rotation_handle = tokio::spawn(async move {
        loop {
            if rotation_runtime.shutdown.load(Ordering::Relaxed) || cleanup::should_shutdown() {
                break;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
            if let Err(err) = maybe_rotate(
                &rotation_runtime,
                &rotation_bind,
                server,
                rotation_hops,
                Arc::clone(&tun),
            )
            .await
            {
                warn!("rotation error: {err}");
            }
        }
    });

    let (ipc_tx, mut ipc_rx) = mpsc::channel::<(IpcRequest, oneshot::Sender<IpcResponse>)>(16);
    let ipc_addr = settings.ipc_addr.clone();
    let ipc_handle = tokio::spawn(async move {
        if let Err(err) = vpn_ipc::serve(&ipc_addr, ipc_tx).await {
            error!("ipc server terminated: {err}");
        }
    });

    // ──────────────────────────────────────────────────────────────
    // Main IPC loop with shutdown awareness
    // ──────────────────────────────────────────────────────────────
    loop {
        // Check for signal-triggered shutdown
        if cleanup::should_shutdown() {
            info!("shutdown signal received, initiating cleanup");
            runtime.shutdown.store(true, Ordering::Relaxed);

            // PART 3: Transition to Disconnecting
            state_machine
                .try_transition(TransitionEvent::DisconnectRequested)
                .ok();

            // Stop circuits
            let _ = initial_stop_tx.send(true);

            // Perform platform cleanup
            cleanup::perform_cleanup(&cleanup_state);

            // PART 3: Transition to Disconnected
            state_machine
                .try_transition(TransitionEvent::DisconnectComplete)
                .ok();
            break;
        }

        tokio::select! {
            maybe_req = ipc_rx.recv() => {
                match maybe_req {
                    Some((req, resp_tx)) => {
                        let resp = handle_ipc_request(&runtime, &settings, &tun_name, req).await;
                        runtime.request_count.fetch_add(1, Ordering::Relaxed);
                        let _ = resp_tx.send(resp);

                        if runtime.shutdown.load(Ordering::Relaxed) {
                            // PART 3: Disconnect was initiated via IPC
                            state_machine.try_transition(TransitionEvent::DisconnectRequested).ok();
                            state_machine.try_transition(TransitionEvent::DisconnectComplete).ok();
                            break;
                        }
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Periodic check for signal-triggered shutdown
            }
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Graceful shutdown: wait for tasks with timeout
    // ──────────────────────────────────────────────────────────────
    info!("waiting for background tasks to terminate");
    let shutdown_timeout = Duration::from_secs(5);

    // Signal all circuits to stop
    for (_, handle) in circuits.read().iter() {
        let _ = handle.stop_tx.send(true);
    }

    // Wait for rotation task
    let _ = tokio::time::timeout(shutdown_timeout, async {
        let _ = rotation_handle.await;
    })
    .await;

    // Wait for sender task
    let _ = tokio::time::timeout(shutdown_timeout, async {
        sender_handle.abort();
    })
    .await;

    // Wait for IPC server
    ipc_handle.abort();

    // Wait for TUN reader thread (synchronous)
    // The thread checks reader_shutdown which is the same AtomicBool as runtime.shutdown
    let _ = tokio::task::spawn_blocking(move || {
        let _ = reader_handle.join();
    })
    .await;

    // Final cleanup if not already done, then run registered cleanup resources.
    if !cleanup::SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
        cleanup::perform_cleanup(&cleanup_state);
    }
    let cleanup_errors = cleanup_mgr.cleanup_all();
    if !cleanup_errors.is_empty() {
        warn!(
            "daemon: cleanup manager reported {} errors during shutdown",
            cleanup_errors.len()
        );
    }

    logger
        .log(
            "daemon",
            "stopped",
            json!({
                "uptime_secs": runtime.started_at.elapsed().as_secs(),
            }),
        )
        .await?;

    Ok(())
}

/// Handle a single IPC request, separated from the main loop for clarity.
async fn handle_ipc_request(
    runtime: &Arc<DaemonRuntime>,
    settings: &crate::control_plane::ResolvedRunSettings,
    tun_name: &str,
    req: IpcRequest,
) -> IpcResponse {
    match req {
        IpcRequest::Status => IpcResponse::Status {
            status: runtime.status.read().clone(),
        },
        IpcRequest::Metrics => IpcResponse::Metrics {
            metrics: vpn_ipc::DaemonMetrics {
                mode: "live".to_string(),
                uptime_secs: runtime.started_at.elapsed().as_secs(),
                last_connect_latency_ms: Some(runtime.connect_latency_ms),
                packets_tx: runtime.packets_tx.load(Ordering::Relaxed),
                packets_rx: runtime.packets_rx.load(Ordering::Relaxed),
                request_count: runtime.request_count.load(Ordering::Relaxed),
                error_count: runtime.error_count.load(Ordering::Relaxed),
                error_rate: 0.0,
                connect_count: 1,
                disconnect_count: if runtime.shutdown.load(Ordering::Relaxed) {
                    1
                } else {
                    0
                },
                last_transition_at: runtime.status.read().last_transition_at.clone(),
            },
        },
        IpcRequest::Connect => IpcResponse::Ok {
            message: "daemon is already connected".to_string(),
        },
        IpcRequest::Disconnect { admin_secret } => {
            if !authorize_disconnect(runtime.admin_secret.as_deref(), admin_secret.as_deref()) {
                runtime.error_count.fetch_add(1, Ordering::Relaxed);
                runtime.status.write().last_error = Some("admin authorization failed".to_string());
                IpcResponse::Error {
                    message: "admin authorization failed".to_string(),
                }
            } else {
                runtime.shutdown.store(true, Ordering::Relaxed);
                if let Err(err) = teardown_platform(tun_name, settings.kill_switch) {
                    warn!("platform teardown failed: {err}");
                    runtime.error_count.fetch_add(1, Ordering::Relaxed);
                }
                {
                    let mut status = runtime.status.write();
                    status.connected = false;
                    status.last_transition_at = Some(unix_millis_string());
                }
                IpcResponse::Ok {
                    message: "disconnect initiated".to_string(),
                }
            }
        }
    }
}

pub async fn run_echo_server(bind: &str) -> Result<()> {
    crate::server::run_vpn_server(None, Some(bind)).await
}

async fn handle_outbound_packet(runtime: &DaemonRuntime, packet: &[u8]) -> Result<()> {
    let action = runtime.policy.classify(packet, None);
    match action {
        RuleAction::Drop => {
            return Ok(());
        }
        RuleAction::Bypass => {
            // Split-tunnel bypass: packet is not encrypted or sent through the tunnel.
            // The packet was already intercepted from the TUN by the OS. On Linux,
            // configure policy routing (ip rule) to route matching source IPs directly
            // through the physical interface. On Windows, use WFP per-app rules.
            // For v0.3.0, we drop the packet at the tunnel level and rely on
            // OS-level split tunneling configuration to prevent these packets from
            // reaching the TUN in the first place.
            runtime.packets_tx.fetch_add(1, Ordering::Relaxed);
            runtime
                .logger
                .log_debug(
                    "routing",
                    "bypass_drop",
                    json!({ "bytes": packet.len(), "action": "drop_at_tunnel" }),
                )
                .await?;
            return Ok(());
        }
        RuleAction::Tunnel => {}
    }

    let active_id = runtime
        .rotation
        .lock()
        .active_id()
        .ok_or_else(|| anyhow!("no active circuit"))?;

    let circuit_id = if let Some(flow) = FlowKey::from_packet(packet) {
        runtime
            .flow_table
            .assign_or_get(flow, active_id, packet.len())
    } else {
        active_id
    };

    let handle = runtime
        .circuits
        .read()
        .get(&circuit_id)
        .cloned()
        .ok_or_else(|| anyhow!("circuit {circuit_id} not found"))?;

    let sealed = handle.circuit.crypto.seal(
        1,
        handle.circuit.descriptor.epoch,
        handle.circuit.descriptor.path_id,
        packet,
    )?;
    let frame = WireFrame::Data(DataFrame::from_sealed(
        handle.circuit.descriptor.session_id,
        handle.circuit.descriptor.epoch,
        handle.circuit.descriptor.path_id,
        1,
        sealed,
    ));
    handle.circuit.transport.send_frame(&frame).await?;
    runtime.packets_tx.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

async fn maybe_rotate(
    runtime: &Arc<DaemonRuntime>,
    bind: &str,
    server: SocketAddr,
    hops: usize,
    tun: Arc<Mutex<Box<dyn TunDevice>>>,
) -> Result<()> {
    if !runtime.rotation.lock().is_due() {
        return Ok(());
    }

    runtime.rotation.lock().begin_prepare();
    update_status(runtime, RotationState::Prepare);
    runtime
        .logger
        .log(
            "rotation",
            "prepare",
            json!({ "server": server.to_string() }),
        )
        .await?;

    let next_epoch = runtime
        .rotation
        .lock()
        .active()
        .map(|c| c.epoch + 1)
        .unwrap_or(1);

    let circuit = match establish_circuit(
        bind,
        server,
        hops,
        next_epoch,
        runtime.trusted_server_public_key,
    )
    .await
    {
        Ok(circuit) => circuit,
        Err(err) => {
            runtime.rotation.lock().abort();
            update_status(runtime, RotationState::Stable);
            let _ = runtime
                .logger
                .log_error(
                    "rotation",
                    "circuit_build_failed",
                    json!({ "error": err.to_string(), "server": server.to_string() }),
                )
                .await;
            return Err(err);
        }
    };
    let new_id = circuit.descriptor.id;
    let (stop_tx, stop_rx) = watch::channel(false);
    runtime.circuits.write().insert(
        new_id,
        CircuitHandle {
            circuit: Arc::new(circuit),
            stop_tx,
        },
    );

    let next_descriptor = runtime
        .circuits
        .read()
        .get(&new_id)
        .map(|handle| handle.circuit.descriptor.clone())
        .ok_or_else(|| anyhow!("new circuit disappeared before migration"))?;
    runtime.rotation.lock().begin_migrate(next_descriptor);
    update_status(runtime, RotationState::Migrate);

    if let Some(draining) = runtime.rotation.lock().draining().cloned() {
        runtime.flow_table.mark_circuit_draining(draining.id);
    }

    spawn_inbound_loop(
        runtime.circuits.read()[&new_id].clone(),
        stop_rx,
        tun,
        Arc::clone(&runtime.logger),
    );

    runtime.rotation.lock().begin_verify();
    update_status(runtime, RotationState::Verify);
    runtime
        .logger
        .log(
            "rotation",
            "verify",
            json!({ "circuit": new_id.to_string() }),
        )
        .await?;

    runtime.rotation.lock().complete();
    update_status(runtime, RotationState::Stable);

    if let Some(draining) = runtime.rotation.lock().draining().cloned() {
        let old_id = draining.id;
        let grace = runtime.rotation.lock().grace();
        let circuits = Arc::clone(&runtime.circuits);
        let flow_table = Arc::clone(&runtime.flow_table);
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            if let Some(handle) = circuits.write().remove(&old_id) {
                let _ = handle.stop_tx.send(true);
            }
            flow_table.reap_circuit(old_id);
        });
    }

    {
        let active = runtime.rotation.lock().active().cloned();
        let mut status = runtime.status.write();
        status.session_id = active.as_ref().map(|c| c.session_id);
        status.active_circuit = active.as_ref().map(|c| c.id.to_string());
    }

    Ok(())
}

fn spawn_inbound_loop(
    handle: CircuitHandle,
    mut stop_rx: watch::Receiver<bool>,
    tun: Arc<Mutex<Box<dyn TunDevice>>>,
    logger: Arc<EventLogger>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    break;
                }
                received = handle.circuit.transport.recv_frame() => {
                    match received {
                        Ok((WireFrame::Data(frame), _)) if frame.session_id == handle.circuit.descriptor.session_id => {
                            match handle.circuit.crypto.open(
                                frame.packet_type,
                                frame.epoch,
                                frame.path_id,
                                frame.counter,
                                frame.plaintext_len,
                                &frame.payload,
                            ) {
                                Ok(plaintext) => {
                                    if let Err(err) = tun.lock().write_packet(&plaintext) {
                                        warn!("tun write failed: {err}");
                                    }
                                }
                                Err(err) => {
                                    let _ = logger.log("transport", "decrypt_failed", json!({ "error": err.to_string() })).await;
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(err) => {
                            let _ = logger.log("transport", "recv_failed", json!({ "error": err.to_string() })).await;
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    });
}

async fn establish_circuit(
    bind_addr: &str,
    server: SocketAddr,
    hops: usize,
    epoch: u32,
    trusted_server_public_key: Option<[u8; 32]>,
) -> Result<ClientCircuit> {
    let transport = UdpTransport::connect(bind_addr, server).await?;
    let eph = EphemeralKeyPair::generate();
    let client_nonce = random_nonce();
    let init = vpn_crypto::HandshakeInit {
        client_public: eph.public_bytes(),
        client_nonce,
    };
    transport
        .send_frame(&WireFrame::HandshakeInit(init))
        .await?;

    let response = match transport.recv_frame().await? {
        (WireFrame::HandshakeResponse(response), _) => response,
        _ => return Err(anyhow!("unexpected server response during handshake")),
    };

    if let Some(expected_public_key) = trusted_server_public_key {
        if response.server_static_public != expected_public_key {
            return Err(anyhow!(
                "server static public key does not match the configured trust anchor"
            ));
        }

        verify_server_static_proof(
            &eph,
            response.server_public,
            response.server_static_public,
            response.session_id,
            client_nonce,
            response.server_nonce,
            response.server_static_proof,
        )?;
    }

    let shared = eph.shared_secret(response.server_public);
    let keys = derive_session_keys(shared, client_nonce, response.server_nonce, Role::Initiator)?;
    let crypto = Arc::new(SessionCrypto::new(keys));
    let confirm = build_confirm(
        crypto.confirm_key(),
        b"client-confirm",
        response.session_id,
        client_nonce,
        response.server_nonce,
    )?;
    transport
        .send_frame(&WireFrame::HandshakeConfirm(confirm.clone()))
        .await?;

    let ack = match transport.recv_frame().await? {
        (WireFrame::HandshakeAck(ack), _) => ack,
        _ => return Err(anyhow!("unexpected server ack during handshake")),
    };
    verify_confirm(
        crypto.confirm_key(),
        b"server-confirm",
        &ack,
        client_nonce,
        response.server_nonce,
    )?;

    Ok(ClientCircuit {
        descriptor: CircuitDescriptor::new(response.session_id, server, hops, epoch),
        crypto,
        transport,
    })
}

fn update_status(runtime: &DaemonRuntime, state: RotationState) {
    let mut status = runtime.status.write();
    status.rotation_state = Some(format!("{state:?}"));
    status.last_transition_at = Some(unix_millis_string());
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
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn load_admin_secret(env_name: Option<&str>) -> Option<String> {
    env_name.and_then(|name| std::env::var(name).ok())
}

fn unix_millis_string() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string()
}

#[cfg(target_os = "linux")]
fn create_platform_tun(config: &TunConfig, server: SocketAddr) -> Result<Box<dyn TunDevice>> {
    use vpn_platform_linux as platform;
    let route = platform::discover_default_route()?;
    let tun = platform::create_tun(config)?;
    let actual_name = tun.name().to_string();
    let actual_config = TunConfig {
        name: actual_name.clone(),
        address_cidr: config.address_cidr.clone(),
        mtu: config.mtu,
    };
    platform::configure_interface(&actual_config)?;
    platform::route_server_via_physical(server.ip(), &route)?;
    Ok(Box::new(tun))
}

#[cfg(windows)]
fn create_platform_tun(config: &TunConfig, server: SocketAddr) -> Result<Box<dyn TunDevice>> {
    use vpn_platform_windows as platform;
    let tun = platform::create_tun(config, None)?;
    platform::route_server_via_physical(server.ip())?;
    Ok(Box::new(tun))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn create_platform_tun(_: &TunConfig, _: SocketAddr) -> Result<Box<dyn TunDevice>> {
    Err(anyhow!(
        "this daemon skeleton currently supports Linux and Windows client operation"
    ))
}

#[cfg(target_os = "linux")]
fn activate_platform_tun(tun_name: &str, server: SocketAddr, kill_switch: bool) -> Result<()> {
    use vpn_platform_linux as platform;
    if kill_switch {
        platform::enable_kill_switch(&platform::KillSwitchConfig {
            tun_name: tun_name.to_string(),
            server_ip: server.ip(),
            server_port: server.port(),
            protocol: "udp".to_string(),
        })?;
    }

    if let Err(err) = platform::route_default_via_tun(tun_name) {
        if kill_switch {
            let _ = platform::disable_kill_switch();
        }
        return Err(err);
    }

    Ok(())
}

#[cfg(windows)]
fn activate_platform_tun(tun_name: &str, server: SocketAddr, kill_switch: bool) -> Result<()> {
    use vpn_platform_windows as platform;
    if kill_switch {
        platform::enable_kill_switch(&platform::KillSwitchConfig {
            tun_alias: tun_name.to_string(),
            server_ip: server.ip(),
            server_port: server.port(),
            protocol: "UDP".to_string(),
        })?;
    }

    if let Err(err) = platform::route_default_via_tun(tun_name) {
        if kill_switch {
            let _ = platform::disable_kill_switch();
        }
        return Err(err);
    }

    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
fn activate_platform_tun(_: &str, _: SocketAddr, _: bool) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn teardown_platform(tun_name: &str, kill_switch: bool) -> Result<()> {
    info!("linux: tearing down platform for '{}'", tun_name);

    // Remove default route via TUN first (must be accessible while cleaning)
    let _ = std::process::Command::new("ip")
        .args(["route", "del", "default"])
        .status();

    // Remove kill switch (nftables table)
    if kill_switch {
        if let Err(e) = vpn_platform_linux::disable_kill_switch() {
            warn!("linux: kill switch disable failed: {e}");
        }
    }

    // Bring TUN interface down and remove it
    let _ = std::process::Command::new("ip")
        .args(["link", "set", tun_name, "down"])
        .status();
    let _ = std::process::Command::new("ip")
        .args(["link", "del", tun_name])
        .status();

    Ok(())
}

#[cfg(windows)]
fn teardown_platform(tun_name: &str, kill_switch: bool) -> Result<()> {
    if kill_switch {
        vpn_platform_windows::full_teardown(tun_name)?;
        let issues = vpn_platform_windows::verify_teardown_clean(tun_name);
        if !issues.is_empty() {
            warn!("teardown verification found issues: {:?}", issues);
        }
    } else {
        vpn_platform_windows::cleanup_routes(tun_name)?;
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
fn teardown_platform(_: &str, _: bool) -> Result<()> {
    Ok(())
}

fn validate_ipc_addr(addr: &str) -> Result<()> {
    if std::env::var("AEGIS_ALLOW_NON_LOOPBACK_IPC")
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

// ──────────────────────────────────────────────────────────────
// PART 3: Runtime mode-aware platform functions
// ──────────────────────────────────────────────────────────────

/// Dummy TUN device for Limited/Safe mode. Reads/writes are no-ops.
/// The daemon runs in IPC-only mode without actual tunnel functionality.
struct DummyTun {
    name: String,
    mtu: u32,
}

impl DummyTun {
    fn new(config: &TunConfig) -> Self {
        Self {
            name: format!("{}-dummy", config.name),
            mtu: config.mtu,
        }
    }
}

impl TunDevice for DummyTun {
    fn name(&self) -> &str {
        &self.name
    }
    fn mtu(&self) -> u32 {
        self.mtu
    }
    fn read_packet(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "dummy tun: no packets",
        ))
    }
    fn write_packet(&mut self, _packet: &[u8]) -> std::io::Result<()> {
        // Silently drop — no tunnel in limited/safe mode
        Ok(())
    }
}

/// Mode-aware TUN creation. In Limited/Safe mode, returns a DummyTun.
fn create_platform_tun_mode(
    config: &TunConfig,
    server: SocketAddr,
    mode: &RuntimeMode,
) -> Result<Box<dyn TunDevice>> {
    if mode.is_limited() {
        info!("daemon: limited mode — creating dummy TUN device");
        return Ok(Box::new(DummyTun::new(config)));
    }

    if mode.is_safe() {
        info!("daemon: safe mode — creating dummy TUN device (simulation)");
        return Ok(Box::new(DummyTun::new(config)));
    }

    // Full mode — use real platform TUN
    create_platform_tun(config, server)
}

/// Mode-aware TUN activation. In Limited/Safe mode, this is a no-op.
fn activate_platform_tun_mode(
    tun_name: &str,
    server: SocketAddr,
    kill_switch: bool,
    mode: &RuntimeMode,
) -> Result<()> {
    if mode.is_limited() {
        info!("daemon: limited mode — skipping kill switch and routing activation");
        return Ok(());
    }

    if mode.is_safe() {
        info!("daemon: safe mode — simulating TUN activation");
        return Ok(());
    }

    // Full mode — use real platform activation
    activate_platform_tun(tun_name, server, kill_switch)
}
