use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use super::metrics;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HaState {
    pub connected: bool,
    pub server: Option<String>,
    pub mode: Option<String>,
    pub rotation_state: Option<String>,
    pub uptime_secs: u64,
    pub packets_tx: u64,
    pub packets_rx: u64,
    pub errors: u64,
    pub last_error: Option<String>,
    pub activeCircuits: u32,
    pub routes_installed: u32,
    pub wfp_filters_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionState {
    pub circuit_id: String,
    pub server_endpoint: String,
    pub established_at: u64,
    pub last_activity: u64,
    pub packets_tx: u64,
    pub packets_rx: u64,
    pub crypto_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    pub timestamp: u64,
    pub node_id: String,
    pub term: u64,
    pub state: HaState,
    pub connections: Vec<ConnectionState>,
    pub routes: Vec<RouteState>,
    pub wfp_filters: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteState {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub metric: u32,
}

impl HaState {
    pub fn update_from(&mut self, snapshot: StateSnapshot) {
        self.connected = snapshot.state.connected;
        self.server = snapshot.state.server.clone();
        self.mode = snapshot.state.mode.clone();
        self.rotation_state = snapshot.state.rotation_state.clone();
        self.uptime_secs = snapshot.state.uptime_secs;
        self.packets_tx = snapshot.state.packets_tx;
        self.packets_rx = snapshot.state.packets_rx;
        self.errors = snapshot.state.errors;
        self.last_error = snapshot.state.last_error.clone();
        self.activeCircuits = snapshot.state.activeCircuits;
        self.routes_installed = snapshot.routes.len() as u32;
        self.wfp_filters_active = !snapshot.wfp_filters.is_empty();

        metrics::inc_state_sync();
    }
}

impl StateSnapshot {
    pub fn new(node_id: String, term: u64) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            node_id,
            term,
            state: HaState::default(),
            connections: vec![],
            routes: vec![],
            wfp_filters: vec![],
        }
    }

    pub fn from_daemon_status(status: &super::super::vpn_ipc::DaemonStatus) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            node_id: "local".to_string(),
            term: 0,
            state: HaState {
                connected: status.connected,
                server: status.server.clone(),
                mode: status.mode.clone(),
                rotation_state: status.rotation_state.clone(),
                uptime_secs: status.uptime_secs,
                packets_tx: status.packets_tx,
                packets_rx: status.packets_rx,
                errors: status.error_count,
                last_error: status.last_error.clone(),
                activeCircuits: status.active_circuits.unwrap_or(0),
                routes_installed: 0,
                wfp_filters_active: false,
            },
            connections: vec![],
            routes: vec![],
            wfp_filters: vec![],
        }
    }

    pub fn merge(&mut self, other: &StateSnapshot) {
        if other.timestamp > self.timestamp {
            self.state = other.state.clone();
            self.connections = other.connections.clone();
            self.routes = other.routes.clone();
            self.wfp_filters = other.wfp_filters.clone();
        }
    }
}

static STATE_STORE: std::sync::OnceLock<Arc<RwLock<HashMap<String, StateSnapshot>>>> = std::sync::OnceLock::new();

fn get_state_store() -> Arc<RwLock<HashMap<String, StateSnapshot>>> {
    STATE_STORE.get_or_init(|| Arc::new(RwLock::new(HashMap::new()))).clone()
}

pub fn store_state(node_id: &str, snapshot: StateSnapshot) {
    let store = get_state_store();
    store.write().insert(node_id.to_string(), snapshot);
}

pub fn get_state(node_id: &str) -> Option<StateSnapshot> {
    let store = get_state_store();
    store.read().get(node_id).cloned()
}

pub fn get_all_states() -> Vec<StateSnapshot> {
    let store = get_state_store();
    store.read().values().cloned().collect()
}

pub fn import_state_snapshot(snapshot: StateSnapshot) {
    info!("ha: importing state snapshot from node {}", snapshot.node_id);
    store_state(&snapshot.node_id, snapshot);
}

pub fn clear_states() {
    let store = get_state_store();
    store.write().clear();
}

pub fn get_cluster_state() -> Option<StateSnapshot> {
    let states = get_all_states();
    
    if states.is_empty() {
        return None;
    }

    let mut merged = states.first()?.clone();
    
    for state in states.iter().skip(1) {
        merged.merge(state);
    }
    
    Some(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_snapshot_new() {
        let snapshot = StateSnapshot::new("node1".to_string(), 1);
        assert_eq!(snapshot.node_id, "node1");
        assert_eq!(snapshot.term, 1);
        assert!(!snapshot.connections.is_empty());
    }

    #[test]
    fn test_state_merge() {
        let mut a = StateSnapshot::new("node1".to_string(), 1);
        a.state.connected = true;
        
        let mut b = StateSnapshot::new("node2".to_string(), 2);
        b.state.connected = false;
        b.state.packets_tx = 100;
        
        a.merge(&b);
        
        assert!(!a.state.connected);
        assert_eq!(a.state.packets_tx, 100);
    }

    #[test]
    fn test_store_and_retrieve() {
        let snapshot = StateSnapshot::new("node1".to_string(), 1);
        store_state("node1", snapshot.clone());
        
        let retrieved = get_state("node1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().node_id, "node1");
    }
}