use crate::control_plane::load_server_control_plane;
use anyhow::{anyhow, Result};
use ipnet::Ipv4Net;
use parking_lot::{Mutex, RwLock};
use rand::random;
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tracing::{info, warn};
use vpn_crypto::{
    build_confirm, build_server_static_proof, derive_session_keys, random_nonce, verify_confirm,
    EphemeralKeyPair, HandshakeResponse, Role, SessionCrypto, SessionKeys,
};
use vpn_logger::{EventLogger, LoggerConfig};
use vpn_routing::FlowKey;
use vpn_transport::{DataFrame, UdpTransport, WireFrame};
use vpn_tun::TunDevice;

/// Per-client IP address pool. Allocates unique addresses from a CIDR range.
/// Prevents duplicate IP assignments across concurrent clients.
struct IpPool {
    network: Ipv4Net,
    allocated: HashSet<IpAddr>,
}

impl IpPool {
    fn new(cidr: &str) -> Result<Self> {
        let network: Ipv4Net = cidr
            .parse()
            .map_err(|e| anyhow!("invalid client pool CIDR: {e}"))?;
        Ok(Self {
            network,
            allocated: HashSet::new(),
        })
    }

    /// Allocate the next available IP from the pool.
    /// Skips .0 (network), .1 (typically the server), and already-allocated IPs.
    fn allocate(&mut self) -> Result<IpAddr> {
        let base = u32::from(self.network.network());
        let prefix_len = self.network.prefix_len();

        // Number of usable host addresses
        let total_hosts = (1u32 << (32 - prefix_len)).saturating_sub(2);
        if self.allocated.len() as u32 >= total_hosts {
            return Err(anyhow!(
                "IP pool exhausted: {} addresses allocated",
                self.allocated.len()
            ));
        }

        // Start from .2 (skip network .0 and server .1)
        for offset in 2..(total_hosts + 2) {
            let addr = IpAddr::V4(Ipv4Addr::from(base + offset));
            if !self.allocated.contains(&addr) {
                self.allocated.insert(addr);
                info!(
                    "ip pool: allocated {addr} ({} in use)",
                    self.allocated.len()
                );
                return Ok(addr);
            }
        }

        Err(anyhow!("IP pool exhausted: no available addresses"))
    }

    fn release(&mut self, addr: IpAddr) {
        if self.allocated.remove(&addr) {
            info!(
                "ip pool: released {addr} ({} remaining)",
                self.allocated.len()
            );
        }
    }
}

#[derive(Clone)]
struct PendingServerSession {
    keys: SessionKeys,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    peer: SocketAddr,
    created_at: Instant,
}

#[derive(Clone)]
struct EstablishedServerSession {
    session_id: u64,
    peer: SocketAddr,
    crypto: Arc<SessionCrypto>,
    client_ip: Option<IpAddr>,
    last_seen: Instant,
    epoch: u32,
    path_id: u32,
}

#[derive(Clone)]
enum SessionState {
    Pending(PendingServerSession),
    Established(EstablishedServerSession),
}

#[cfg(target_os = "linux")]
pub async fn run_vpn_server(
    config_path: Option<&PathBuf>,
    bind_override: Option<&str>,
) -> Result<()> {
    let (config, identity) = load_server_control_plane(config_path)?;
    let server_static_private = identity.private_key_bytes()?;
    let server_static_public = identity.public_key_bytes()?;
    let bind = bind_override
        .unwrap_or(&config.server.listen_address)
        .to_string();

    // Register signal handlers for graceful shutdown
    crate::cleanup::register_signal_handlers().await?;

    let logger = Arc::new(
        EventLogger::new(LoggerConfig {
            service_name: "vpn-server".to_string(),
            json_log_path: config.logging.json_log_path.clone().map(PathBuf::from),
            mysql_url: config
                .logging
                .mysql_url
                .as_ref()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            chain_key: random::<[u8; 32]>(),
        })
        .await?,
    );

    logger
        .log(
            "server",
            "starting",
            json!({
                "bind": bind.clone(),
                "fingerprint": identity.fingerprint.clone(),
                "nat_mode": config.server.nat_mode.clone(),
                "egress_interface": config.server.egress_interface.clone(),
            }),
        )
        .await?;

    let tun = vpn_platform_linux::server_nat::setup_server_network(
        &vpn_platform_linux::server_nat::ServerNatConfig {
            tun_name: config.server.tun_name.clone(),
            tun_cidr: config.server.tun_cidr.clone(),
            client_pool_cidr: config.server.client_pool_cidr.clone(),
            egress_interface: config.server.egress_interface.clone(),
            nat_mode: config.server.nat_mode.clone(),
        },
    )?;
    let tun = Arc::new(Mutex::new(tun));
    let transport = UdpTransport::bind(&bind).await?;
    let sessions = Arc::new(RwLock::new(HashMap::<u64, SessionState>::new()));
    let routes = Arc::new(RwLock::new(HashMap::<IpAddr, Vec<u64>>::new()));
    let ip_pool = Arc::new(Mutex::new(IpPool::new(&config.server.client_pool_cidr)?));
    let session_timeout = Duration::from_secs(config.server.session_timeout_secs);

    let (tun_packets_tx, mut tun_packets_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let tun_reader = Arc::clone(&tun);
    thread::spawn(move || {
        let mut buf = vec![0u8; 65535];
        loop {
            match tun_reader.lock().read_packet(&mut buf) {
                Ok(size) => {
                    if tun_packets_tx.send(buf[..size].to_vec()).is_err() {
                        break;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let routes_for_tun = Arc::clone(&routes);
    let sessions_for_tun = Arc::clone(&sessions);
    let transport_for_tun = transport.clone();
    tokio::spawn(async move {
        while let Some(packet) = tun_packets_rx.recv().await {
            let Some(flow) = FlowKey::from_packet(&packet) else {
                continue;
            };

            let session_id = routes_for_tun
                .read()
                .get(&flow.dst_ip)
                .and_then(|list| list.first().copied());

            let Some(session_id) = session_id else {
                continue;
            };

            let session = sessions_for_tun.read().get(&session_id).cloned();
            let Some(SessionState::Established(session)) = session else {
                continue;
            };

            if let Ok(sealed) = session
                .crypto
                .seal(1, session.epoch, session.path_id, &packet)
            {
                let data_frame = WireFrame::Data(DataFrame::from_sealed(
                    session.session_id,
                    session.epoch,
                    session.path_id,
                    1,
                    sealed,
                ));
                let _ = transport_for_tun
                    .send_frame_to(&data_frame, session.peer)
                    .await;
            }
        }
    });

    let sessions_cleanup = Arc::clone(&sessions);
    let routes_cleanup = Arc::clone(&routes);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let expired_ids: Vec<u64> = sessions_cleanup
                .read()
                .iter()
                .filter_map(|(id, state)| match state {
                    SessionState::Pending(pending)
                        if pending.created_at.elapsed() > session_timeout =>
                    {
                        Some(*id)
                    }
                    SessionState::Established(established)
                        if established.last_seen.elapsed() > session_timeout =>
                    {
                        Some(*id)
                    }
                    _ => None,
                })
                .collect();

            if expired_ids.is_empty() {
                continue;
            }

            let mut sessions_guard = sessions_cleanup.write();
            let mut routes_guard = routes_cleanup.write();
            for id in expired_ids {
                if let Some(SessionState::Established(established)) = sessions_guard.remove(&id) {
                    if let Some(ip) = established.client_ip {
                        if let Some(route_list) = routes_guard.get_mut(&ip) {
                            route_list.retain(|candidate| *candidate != id);
                            if route_list.is_empty() {
                                routes_guard.remove(&ip);
                            }
                        }
                    }
                } else {
                    let _ = sessions_guard.remove(&id);
                }
            }
        }
    });

    info!("vpn server listening on {bind}");

    loop {
        // Check for shutdown signal
        if crate::cleanup::should_shutdown() {
            info!("vpn server: shutdown signal received, cleaning up");

            // Clean up NAT
            let _ = vpn_platform_linux::server_nat::disable_nat(
                &vpn_platform_linux::server_nat::ServerNatConfig {
                    tun_name: config.server.tun_name.clone(),
                    tun_cidr: config.server.tun_cidr.clone(),
                    client_pool_cidr: config.server.client_pool_cidr.clone(),
                    egress_interface: config.server.egress_interface.clone(),
                    nat_mode: config.server.nat_mode.clone(),
                },
            );

            // Disable kill switch
            let _ = vpn_platform_linux::disable_kill_switch();

            // Remove TUN
            let _ = std::process::Command::new("ip")
                .args(["link", "set", &config.server.tun_name, "down"])
                .status();
            let _ = std::process::Command::new("ip")
                .args(["link", "del", &config.server.tun_name])
                .status();

            info!("vpn server: shutdown complete");
            return Ok(());
        }

        let recv_result =
            tokio::time::timeout(Duration::from_millis(500), transport.recv_frame()).await;

        let (frame, peer) = match recv_result {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return Err(e.into()),
            Err(_timeout) => continue, // Check shutdown and loop
        };
        match frame {
            WireFrame::HandshakeInit(init) => {
                let eph = EphemeralKeyPair::generate();
                let server_nonce = random_nonce();
                let shared = eph.shared_secret(init.client_public);
                let keys =
                    derive_session_keys(shared, init.client_nonce, server_nonce, Role::Responder)?;
                let session_id = random::<u64>();
                let server_public = eph.public_bytes();
                let server_static_proof = build_server_static_proof(
                    server_static_private,
                    init.client_public,
                    server_public,
                    server_static_public,
                    session_id,
                    init.client_nonce,
                    server_nonce,
                )?;
                sessions.write().insert(
                    session_id,
                    SessionState::Pending(PendingServerSession {
                        keys,
                        client_nonce: init.client_nonce,
                        server_nonce,
                        peer,
                        created_at: Instant::now(),
                    }),
                );

                let response = HandshakeResponse {
                    server_public,
                    server_static_public,
                    server_static_proof,
                    server_nonce,
                    session_id,
                };
                transport
                    .send_frame_to(&WireFrame::HandshakeResponse(response), peer)
                    .await?;
                logger
                    .log(
                        "connection",
                        "handshake_init",
                        json!({ "peer": peer.to_string(), "session_id": session_id }),
                    )
                    .await?;
            }
            WireFrame::HandshakeConfirm(confirm) => {
                let pending = sessions.read().get(&confirm.session_id).cloned();
                let Some(SessionState::Pending(pending)) = pending else {
                    continue;
                };
                if pending.peer != peer {
                    continue;
                }

                let crypto = Arc::new(SessionCrypto::new(pending.keys.clone()));
                verify_confirm(
                    crypto.confirm_key(),
                    b"client-confirm",
                    &confirm,
                    pending.client_nonce,
                    pending.server_nonce,
                )?;

                let ack = build_confirm(
                    crypto.confirm_key(),
                    b"server-confirm",
                    confirm.session_id,
                    pending.client_nonce,
                    pending.server_nonce,
                )?;

                // Allocate a unique client IP from the pool
                let allocated_ip = match ip_pool.lock().allocate() {
                    Ok(ip) => ip,
                    Err(e) => {
                        warn!(
                            "ip pool allocation failed for session {}: {e}",
                            confirm.session_id
                        );
                        continue;
                    }
                };

                // Register the allocated IP in the route table immediately
                routes
                    .write()
                    .entry(allocated_ip)
                    .or_default()
                    .push(confirm.session_id);

                sessions.write().insert(
                    confirm.session_id,
                    SessionState::Established(EstablishedServerSession {
                        session_id: confirm.session_id,
                        peer: pending.peer,
                        crypto,
                        client_ip: Some(allocated_ip),
                        last_seen: Instant::now(),
                        epoch: 1,
                        path_id: 1,
                    }),
                );
                transport
                    .send_frame_to(&WireFrame::HandshakeAck(ack), pending.peer)
                    .await?;
                logger
                    .log(
                        "connection",
                        "established",
                        json!({
                            "peer": pending.peer.to_string(),
                            "session_id": confirm.session_id,
                            "allocated_ip": allocated_ip.to_string()
                        }),
                    )
                    .await?;
            }
            WireFrame::Data(frame) => {
                let state = sessions.read().get(&frame.session_id).cloned();
                let Some(SessionState::Established(established)) = state else {
                    continue;
                };
                if established.peer != peer {
                    continue;
                }

                let plaintext = established.crypto.open(
                    frame.packet_type,
                    frame.epoch,
                    frame.path_id,
                    frame.counter,
                    frame.plaintext_len,
                    &frame.payload,
                )?;

                if let Some(flow) = FlowKey::from_packet(&plaintext) {
                    let src_ip = flow.src_ip;
                    {
                        let mut sessions_guard = sessions.write();
                        if let Some(SessionState::Established(session)) =
                            sessions_guard.get_mut(&frame.session_id)
                        {
                            session.client_ip = Some(src_ip);
                            session.last_seen = Instant::now();
                        }
                    }
                    touch_route(&routes, src_ip, frame.session_id);
                }

                tun.lock().write_packet(&plaintext)?;
            }
            WireFrame::Keepalive { session_id } => {
                let mut sessions_guard = sessions.write();
                if let Some(SessionState::Established(session)) =
                    sessions_guard.get_mut(&session_id)
                {
                    if session.peer != peer {
                        continue;
                    }
                    session.last_seen = Instant::now();
                }
            }
            WireFrame::HandshakeResponse(_) | WireFrame::HandshakeAck(_) => {}
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn run_vpn_server(_: Option<&PathBuf>, _: Option<&str>) -> Result<()> {
    Err(anyhow!(
        "the routed VPN server implementation currently targets Linux"
    ))
}

fn touch_route(routes: &Arc<RwLock<HashMap<IpAddr, Vec<u64>>>>, ip: IpAddr, session_id: u64) {
    let mut guard = routes.write();
    let entry = guard.entry(ip).or_default();
    entry.retain(|candidate| *candidate != session_id);
    entry.insert(0, session_id);
}
