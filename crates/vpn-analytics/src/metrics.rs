use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionMetrics {
    pub session_id: String,
    pub server: String,
    pub connected_at: i64,
    pub duration_secs: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub latency_ms: Option<u64>,
    pub handshake_duration_ms: Option<u64>,
    pub reconnection_count: u32,
    pub status: ConnectionStatus,
    pub last_error: Option<String>,
}

impl Default for ConnectionMetrics {
    fn default() -> Self {
        Self {
            session_id: Uuid::new_v4().to_string(),
            server: String::new(),
            connected_at: 0,
            duration_secs: 0,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            latency_ms: None,
            handshake_duration_ms: None,
            reconnection_count: 0,
            status: ConnectionStatus::Disconnected,
            last_error: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Handshake,
    Connected,
    Reconnecting,
    Disconnecting,
    Error,
}

impl std::fmt::Display for ConnectionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionStatus::Disconnected => write!(f, "disconnected"),
            ConnectionStatus::Connecting => write!(f, "connecting"),
            ConnectionStatus::Handshake => write!(f, "handshake"),
            ConnectionStatus::Connected => write!(f, "connected"),
            ConnectionStatus::Reconnecting => write!(f, "reconnecting"),
            ConnectionStatus::Disconnecting => write!(f, "disconnecting"),
            ConnectionStatus::Error => write!(f, "error"),
        }
    }
}

pub struct MetricsRecorder {
    current: Arc<RwLock<ConnectionMetrics>>,
    history: Arc<RwLock<Vec<ConnectionMetrics>>>,
    server_stats: Arc<RwLock<HashMap<String, ServerStats>>>,
    max_history: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServerStats {
    pub server: String,
    pub total_connections: u64,
    pub successful_connections: u64,
    pub failed_connections: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub avg_latency_ms: f64,
    pub avg_handshake_ms: f64,
    pub total_duration_secs: u64,
}

impl MetricsRecorder {
    pub fn new(max_history: usize) -> Self {
        Self {
            current: Arc::new(RwLock::new(ConnectionMetrics::default())),
            history: Arc::new(RwLock::new(Vec::with_capacity(max_history))),
            server_stats: Arc::new(RwLock::new(HashMap::new())),
            max_history,
        }
    }

    pub fn current(&self) -> ConnectionMetrics {
        self.current.read().clone()
    }

    pub fn history(&self) -> Vec<ConnectionMetrics> {
        self.history.read().clone()
    }

    pub fn server_stats(&self) -> Vec<ServerStats> {
        self.server_stats.read().values().cloned().collect()
    }

    pub fn connect_start(&self, server: &str) {
        let mut current = self.current.write();
        current.session_id = Uuid::new_v4().to_string();
        current.server = server.to_string();
        current.connected_at = unix_millis();
        current.status = ConnectionStatus::Connecting;
        current.bytes_sent = 0;
        current.bytes_received = 0;
        current.packets_sent = 0;
        current.packets_received = 0;
        current.reconnection_count = 0;
        current.last_error = None;
    }

    pub fn handshake_complete(&self, latency_ms: u64, handshake_ms: u64) {
        let mut current = self.current.write();
        current.status = ConnectionStatus::Connected;
        current.latency_ms = Some(latency_ms);
        current.handshake_duration_ms = Some(handshake_ms);
    }

    pub fn connected(&self, session_id: &str) {
        let mut current = self.current.write();
        current.session_id = session_id.to_string();
        current.status = ConnectionStatus::Connected;
        current.connected_at = unix_millis();
    }

    pub fn disconnect(&self) {
        let mut current = self.current.write();
        if current.status == ConnectionStatus::Connected {
            current.duration_secs = ((unix_millis() - current.connected_at) / 1000) as u64;
            current.status = ConnectionStatus::Disconnected;

            let finished = current.clone();
            drop(current);

            self.history.write().push(finished);
            self.prune_history();
        }
    }

    pub fn reconnecting(&self) {
        let mut current = self.current.write();
        current.status = ConnectionStatus::Reconnecting;
        current.reconnection_count += 1;
    }

    pub fn reconnect_complete(&self) {
        let mut current = self.current.write();
        current.status = ConnectionStatus::Connected;
    }

    pub fn error(&self, err: &str) {
        let mut current = self.current.write();
        current.status = ConnectionStatus::Error;
        current.last_error = Some(err.to_string());
    }

    pub fn add_bytes_sent(&self, bytes: u64) {
        self.current.write().bytes_sent += bytes;
    }

    pub fn add_bytes_received(&self, bytes: u64) {
        self.current.write().bytes_received += bytes;
    }

    pub fn increment_packets_sent(&self) {
        self.current.write().packets_sent += 1;
    }

    pub fn increment_packets_received(&self) {
        self.current.write().packets_received += 1;
    }

    pub fn update_latency(&self, latency_ms: u64) {
        self.current.write().latency_ms = Some(latency_ms);
    }

    pub fn record_server_stats(&self) {
        let current = self.current.read();
        if current.server.is_empty() {
            return;
        }

        let mut stats = self.server_stats.write();
        let server = current.server.clone();
        let entry = stats.entry(server.clone()).or_insert_with(|| ServerStats {
            server,
            ..Default::default()
        });

        entry.total_connections += 1;
        if current.status == ConnectionStatus::Connected {
            entry.successful_connections += 1;
        } else if current.status == ConnectionStatus::Error {
            entry.failed_connections += 1;
        }
        entry.total_bytes_sent += current.bytes_sent;
        entry.total_bytes_received += current.bytes_received;
        entry.total_duration_secs += current.duration_secs;

        if let Some(latency) = current.latency_ms {
            entry.avg_latency_ms =
                ((entry.avg_latency_ms * (entry.total_connections - 1) as f64) + latency as f64)
                    / entry.total_connections as f64;
        }
        if let Some(handshake) = current.handshake_duration_ms {
            entry.avg_handshake_ms =
                ((entry.avg_handshake_ms * (entry.total_connections - 1) as f64) + handshake as f64)
                    / entry.total_connections as f64;
        }
    }

    fn prune_history(&self) {
        let mut history = self.history.write();
        while history.len() > self.max_history {
            history.remove(0);
        }
    }

    pub fn summary(&self) -> MetricsSummary {
        let current = self.current.read();
        let history = self.history.read();
        let server_stats = self.server_stats.read();

        let mut total_bytes_sent: u64 = 0;
        let mut total_bytes_received: u64 = 0;
        let mut total_duration: u64 = 0;
        let mut total_connections: u64 = 0;
        let mut successful: u64 = 0;

        for session in history.iter() {
            total_bytes_sent += session.bytes_sent;
            total_bytes_received += session.bytes_received;
            total_duration += session.duration_secs;
            total_connections += 1;
            if session.status == ConnectionStatus::Connected {
                successful += 1;
            }
        }

        MetricsSummary {
            active_session: current.clone(),
            total_sessions: total_connections,
            successful_sessions: successful,
            total_bytes_sent,
            total_bytes_received,
            total_duration_secs: total_duration,
            success_rate: if total_connections > 0 {
                (successful as f64 / total_connections as f64) * 100.0
            } else {
                0.0
            },
            server_count: server_stats.len() as u64,
        }
    }
}

impl Default for MetricsRecorder {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricsSummary {
    pub active_session: ConnectionMetrics,
    pub total_sessions: u64,
    pub successful_sessions: u64,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_duration_secs: u64,
    pub success_rate: f64,
    pub server_count: u64,
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}