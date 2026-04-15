use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug};

use super::{HaConfig, HaState, StateSnapshot};

pub struct InterProcess通信 {
    config: HaConfig,
    bind_addr: String,
    peers: Arc<RwLock<HashMap<String, mpsc::Sender<IpcMessage>>>>,
    event_tx: mpsc::Sender<IpcMessage>,
    running: Arc<RwLock<bool>>,
}

impl InterProcess通信 {
    pub fn new(bind_addr: String, event_tx: mpsc::Sender<IpcMessage>) -> Self {
        Self {
            config: HaConfig::default(),
            bind_addr,
            peers: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            running: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn start(&mut self, mut rx: mpsc::Receiver<IpcMessage>) {
        *self.running.write() = true;
        info!("ipc: starting IPC server on {}", self.bind_addr);

        let listener = match TcpListener::bind(&self.bind_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("ipc: failed to bind to {}: {}", self.bind_addr, e);
                return;
            }
        };

        info!("ipc: listening on {}", self.bind_addr);

        loop {
            if !*self.running.read() {
                break;
            }

            tokio::select! {
                Some(msg) = rx.recv() => {
                    self.handle_outgoing_message(msg).await;
                }
                result = listener.accept() => {
                    match result {
                        Ok((stream, addr)) => {
                            let peers = Arc::clone(&self.peers);
                            tokio::spawn(async move {
                                Self::handle_connection(stream, addr, peers).await;
                            });
                        }
                        Err(e) => {
                            error!("ipc: accept error: {}", e);
                        }
                    }
                }
            }
        }

        info!("ipc: IPC server stopped");
    }

    pub fn stop(&mut self) {
        *self.running.write() = false;
    }

    async fn handle_outgoing_message(&self, msg: IpcMessage) {
        match &msg.target {
            Some(target) => {
                if let Some(peer) = self.peers.read().get(target) {
                    if let Err(e) = peer.send(msg).await {
                        warn!("ipc: failed to send to {}: {}", target, e);
                    }
                } else {
                    debug!("ipc: unknown target: {}", target);
                }
            }
            None => {
                for (peer_id, sender) in self.peers.read().iter() {
                    if let Err(e) = sender.send(msg.clone()).await {
                        warn!("ipc: broadcast failed to {}: {}", peer_id, e);
                    }
                }
            }
        }
    }

    async fn handle_connection(stream: TcpStream, addr: std::net::SocketAddr, peers: Arc<RwLock<HashMap<String, mpsc::Sender<IpcMessage>>>>) {
        let (mut reader, mut writer) = stream.split();
        let mut buffer = vec![0u8; 8192];

        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    match serde_json::from_slice::<IpcMessage>(&buffer[..n]) {
                        Ok(msg) => {
                            debug!("ipc: received message from {}", addr);
                            
                            if let Some(peer_id) = &msg.source {
                                let (tx, mut rx) = mpsc::channel(32);
                                peers.write().insert(peer_id.clone(), tx);
                                
                                tokio::spawn(async move {
                                    while let Some(forward_msg) = rx.recv().await {
                                        let data = match serde_json::to_vec(&forward_msg) {
                                            Ok(d) => d,
                                            Err(_) => continue,
                                        };
                                        if let Err(e) = writer.write_all(&data).await {
                                            error!("ipc: write error: {}", e);
                                            break;
                                        }
                                    }
                                });
                            }
                        }
                        Err(e) => {
                            debug!("ipc: parse error from {}: {}", addr, e);
                        }
                    }
                }
                Err(e) => {
                    error!("ipc: read error from {}: {}", addr, e);
                    break;
                }
            }
        }

        info!("ipc: connection closed: {}", addr);
    }

    pub async fn broadcast_state(&self, state: &StateSnapshot) {
        let msg = IpcMessage {
            msg_type: IpcMessageType::StateSync,
            source: Some(self.config.node_id.clone()),
            target: None,
            payload: serde_json::to_vec(state).ok(),
        };

        self.handle_outgoing_message(msg).await;
    }

    pub async fn send_state(&self, target: &str, state: &StateSnapshot) {
        let msg = IpcMessage {
            msg_type: IpcMessageType::StateSync,
            source: Some(self.config.node_id.clone()),
            target: Some(target.to_string()),
            payload: serde_json::to_vec(state).ok(),
        };

        self.handle_outgoing_message(msg).await;
    }

    pub fn get_connected_peers(&self) -> Vec<String> {
        self.peers.read().keys().cloned().collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcMessage {
    pub msg_type: IpcMessageType,
    pub source: Option<String>,
    pub target: Option<String>,
    pub payload: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcMessageType {
    StateSync,
    HealthCheck,
    FailoverRequest,
    FailoverAck,
    StateTransfer,
    VoteRequest,
    VoteResponse,
    Heartbeat,
}

pub async fn handle_ipc_message(msg: IpcMessage) -> Option<IpcMessage> {
    match msg.msg_type {
        IpcMessageType::StateSync => {
            if let Some(payload) = msg.payload {
                if let Ok(state) = serde_json::from_slice::<StateSnapshot>(&payload) {
                    super::state::import_state_snapshot(state);
                }
            }
            None
        }
        IpcMessageType::HealthCheck => {
            Some(IpcMessage {
                msg_type: IpcMessageType::HealthCheck,
                source: Some("local".to_string()),
                target: msg.source.clone(),
                payload: Some(b"ok".to_vec()),
            })
        }
        IpcMessageType::VoteRequest => None,
        IpcMessageType::Heartbeat => None,
        _ => None,
    }
}