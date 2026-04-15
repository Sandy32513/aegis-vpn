use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{info, warn, error};

pub mod election;
pub mod ipc;
pub mod state;

pub use election::{LeaderElection, ElectionEvent};
pub use ipc::{InterProcess通信, IpcMessage, IpcResponse};
pub use state::{HaState, ConnectionState, StateSnapshot};

const HA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaConfig {
    pub enabled: bool,
    pub node_id: String,
    pub cluster_id: String,
    pub bind_addr: String,
    pub peers: Vec<String>,
    pub election_timeout_ms: u64,
    pub heartbeat_interval_ms: u64,
    pub failover_timeout_ms: u64,
    pub max_retry: u32,
}

impl Default for HaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: uuid::Uuid::new_v4().to_string(),
            cluster_id: "aegis-default".to_string(),
            bind_addr: "127.0.0.1:9999".to_string(),
            peers: vec![],
            election_timeout_ms: 5000,
            heartbeat_interval_ms: 1000,
            failover_timeout_ms: 10000,
            max_retry: 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    Follower,
    Candidate,
    Leader,
}

impl std::fmt::Display for NodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeRole::Follower => write!(f, "Follower"),
            NodeRole::Candidate => write!(f, "Candidate"),
            NodeRole::Leader => write!(f, "Leader"),
        }
    }
}

pub struct HighAvailabilityManager {
    config: HaConfig,
    role: Arc<RwLock<NodeRole>>,
    state: Arc<RwLock<HaState>>,
    election: Option<LeaderElection>,
    ipc: Option<InterProcess通信>,
    event_tx: mpsc::Sender<HaEvent>,
}

#[derive(Debug, Clone)]
pub enum HaEvent {
    RoleChanged { old_role: NodeRole, new_role: NodeRole },
    PeerJoined { peer_id: String },
    PeerLeft { peer_id: String },
    FailoverInitiated { from_node: String, reason: String },
    FailoverComplete { new_leader: String, duration_ms: u64 },
    StateSyncComplete { entries: u64 },
    HealthCheckFailed { peer_id: String },
}

impl HighAvailabilityManager {
    pub fn new(config: HaConfig, event_tx: mpsc::Sender<HaEvent>) -> Self {
        Self {
            config: config.clone(),
            role: Arc::new(RwLock::new(NodeRole::Follower)),
            state: Arc::new(RwLock::new(HaState::default())),
            election: None,
            ipc: None,
            event_tx,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    pub fn role(&self) -> NodeRole {
        *self.role.read()
    }

    pub fn is_leader(&self) -> bool {
        *self.role.read() == NodeRole::Leader
    }

    pub async fn start(&mut self) -> Result<(), String> {
        if !self.config.enabled {
            info!("ha: HA disabled, skipping initialization");
            return Ok(());
        }

        info!(
            "ha: starting HA manager (node={}, cluster={})",
            self.config.node_id, self.config.cluster_id
        );

        let (election_tx, election_rx) = mpsc::channel(32);
        self.election = Some(LeaderElection::new(
            self.config.clone(),
            election_tx,
        ));

        let (ipc_tx, ipc_rx) = mpsc::channel(64);
        self.ipc = Some(InterProcess通信::new(
            self.config.bind_addr.clone(),
            ipc_tx,
        ));

        if let Some(ref mut election) = self.election {
            election.start(election_rx).await;
        }

        if let Some(ref mut ipc) = self.ipc {
            ipc.start(ipc_rx).await;
        }

        info!("ha: HA manager started");
        Ok(())
    }

    pub async fn stop(&mut self) {
        info!("ha: stopping HA manager");

        if let Some(mut election) = self.election.take() {
            election.stop().await;
        }

        if let Some(mut ipc) = self.ipc.take() {
            ipc.stop().await;
        }

        *self.role.write() = NodeRole::Follower;
        info!("ha: HA manager stopped");
    }

    pub fn update_state(&self, snapshot: StateSnapshot) {
        let mut state = self.state.write();
        state.update_from(snapshot);
        info!("ha: state updated");
    }

    pub fn get_state(&self) -> HaState {
        self.state.read().clone()
    }

    pub async fn request_failover(&self, reason: &str) -> Result<(), String> {
        if !self.is_leader() {
            return Err("not the leader".to_string());
        }

        info!("ha: initiating failover: {}", reason);
        
        self.event_tx.send(HaEvent::FailoverInitiated {
            from_node: self.config.node_id.clone(),
            reason: reason.to_string(),
        }).await.ok();

        Ok(())
    }

    pub fn get_health_status(&self) -> HaHealthStatus {
        HaHealthStatus {
            enabled: self.config.enabled,
            role: self.role(),
            node_id: self.config.node_id.clone(),
            cluster_id: self.config.cluster_id.clone(),
            state: self.get_state(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HaHealthStatus {
    pub enabled: bool,
    pub role: NodeRole,
    pub node_id: String,
    pub cluster_id: String,
    pub state: HaState,
}

pub mod metrics {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    pub static HA_ELECTIONS_WON: AtomicU64 = AtomicU64::new(0);
    pub static HA_ELECTIONS_LOST: AtomicU64 = AtomicU64::new(0);
    pub static HA_FAILOVERS_COMPLETED: AtomicU64 = AtomicU64::new(0);
    pub static HA_PEERS_ACTIVE: AtomicUsize = AtomicUsize::new(0);
    pub static HA_LAST_FAILOVER_MS: AtomicU64 = AtomicU64::new(0);
    pub static HA_STATE_SYNC_COUNT: AtomicU64 = AtomicU64::new(0);

    pub fn inc_election_won() {
        HA_ELECTIONS_WON.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_election_lost() {
        HA_ELECTIONS_LOST.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_failover() {
        HA_FAILOVERS_COMPLETED.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_active_peers(count: usize) {
        HA_PEERS_ACTIVE.store(count, Ordering::Relaxed);
    }

    pub fn record_failover_time(ms: u64) {
        HA_LAST_FAILOVER_MS.store(ms, Ordering::Relaxed);
    }

    pub fn inc_state_sync() {
        HA_STATE_SYNC_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ha_config_default() {
        let config = HaConfig::default();
        assert!(!config.enabled);
        assert!(!config.node_id.is_empty());
    }

    #[test]
    fn test_node_role_display() {
        assert_eq!(NodeRole::Leader.to_string(), "Leader");
        assert_eq!(NodeRole::Follower.to_string(), "Follower");
        assert_eq!(NodeRole::Candidate.to_string(), "Candidate");
    }
}