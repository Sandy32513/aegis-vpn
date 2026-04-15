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
    bandwidth: Arc<BandwidthRecorder>,
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
            bandwidth: Arc::new(BandwidthRecorder::default()),
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

    pub fn bandwidth(&self) -> Arc<BandwidthRecorder> {
        self.bandwidth.clone()
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
        self.bandwidth.start_session(session_id);
    }

    pub fn disconnect(&self) {
        let mut current = self.current.write();
        if current.status == ConnectionStatus::Connected {
            current.duration_secs = ((unix_millis() - current.connected_at) / 1000) as u64;
            current.status = ConnectionStatus::Disconnected;

            self.bandwidth.end_session();

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
        let mut current = self.current.write();
        current.bytes_sent += bytes;
        self.bandwidth.record_sample(current.bytes_sent, current.bytes_received);
    }

    pub fn add_bytes_received(&self, bytes: u64) {
        let mut current = self.current.write();
        current.bytes_received += bytes;
        self.bandwidth.record_sample(current.bytes_sent, current.bytes_received);
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

use std::time::Instant;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BandwidthMetrics {
    pub session_id: String,
    pub samples: Vec<BandwidthSample>,
    pub upload_speed_bps: u64,
    pub download_speed_bps: u64,
    pub peak_upload_bps: u64,
    pub peak_download_bps: u64,
    pub avg_upload_bps: u64,
    pub avg_download_bps: u64,
    pub total_transfer_mb: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BandwidthSample {
    pub timestamp_ms: i64,
    pub bytes_sent_delta: u64,
    pub bytes_received_delta: u64,
    pub duration_ms: u64,
}

impl Default for BandwidthMetrics {
    fn default() -> Self {
        Self {
            session_id: String::new(),
            samples: Vec::with_capacity(3600),
            upload_speed_bps: 0,
            download_speed_bps: 0,
            peak_upload_bps: 0,
            peak_download_bps: 0,
            avg_upload_bps: 0,
            avg_download_bps: 0,
            total_transfer_mb: 0.0,
        }
    }
}

pub struct BandwidthRecorder {
    current: Arc<RwLock<BandwidthMetrics>>,
    last_sample: Arc<RwLock<(Instant, u64, u64)>>,
    sample_interval_secs: u64,
}

impl BandwidthRecorder {
    pub fn new(sample_interval_secs: u64) -> Self {
        Self {
            current: Arc::new(RwLock::new(BandwidthMetrics::default())),
            last_sample: Arc::new(RwLock::new((
                Instant::now(),
                0u64,
                0u64,
            ))),
            sample_interval_secs,
        }
    }

    pub fn current(&self) -> BandwidthMetrics {
        self.current.read().clone()
    }

    pub fn start_session(&self, session_id: &str) {
        let mut current = self.current.write();
        current.session_id = session_id.to_string();
        current.samples.clear();
        current.upload_speed_bps = 0;
        current.download_speed_bps = 0;
        current.peak_upload_bps = 0;
        current.peak_download_bps = 0;
        current.avg_upload_bps = 0;
        current.avg_download_bps = 0;
        current.total_transfer_mb = 0.0;

        *self.last_sample.write() = (Instant::now(), 0u64, 0u64);
    }

    pub fn record_sample(&self, total_bytes_sent: u64, total_bytes_received: u64) {
        let now = Instant::now();
        let (last_time, last_sent, last_received) = *self.last_sample.read();

        let elapsed = now.duration_since(last_time).as_millis() as u64;
        if elapsed < self.sample_interval_secs * 1000 {
            return;
        }

        let bytes_sent_delta = total_bytes_sent.saturating_sub(last_sent);
        let bytes_received_delta = total_bytes_received.saturating_sub(last_received);

        let send_bps = if elapsed > 0 {
            (bytes_sent_delta as u128 * 8000 / elapsed as u128) as u64
        } else {
            0
        };
        let recv_bps = if elapsed > 0 {
            (bytes_received_delta as u128 * 8000 / elapsed as u128) as u64
        } else {
            0
        };

        let mut current = self.current.write();
        let timestamp_ms = unix_millis();

        current.samples.push(BandwidthSample {
            timestamp_ms,
            bytes_sent_delta,
            bytes_received_delta,
            duration_ms: elapsed,
        });

        current.upload_speed_bps = send_bps;
        current.download_speed_bps = recv_bps;

        if send_bps > current.peak_upload_bps {
            current.peak_upload_bps = send_bps;
        }
        if recv_bps > current.peak_download_bps {
            current.peak_download_bps = recv_bps;
        }

        let total_sent: u64 = current.samples.iter().map(|s| s.bytes_sent_delta).sum();
        let total_recv: u64 = current.samples.iter().map(|s| s.bytes_received_delta).sum();
        let total_time_ms: u64 = current.samples.iter().map(|s| s.duration_ms).sum();

        if total_time_ms > 0 {
            current.avg_upload_bps = (total_sent as u128 * 8000 / total_time_ms as u128) as u64;
            current.avg_download_bps = (total_recv as u128 * 8000 / total_time_ms as u128) as u64;
        }

        current.total_transfer_mb = (total_sent + total_recv) as f64 / (1024.0 * 1024.0);

        *self.last_sample.write() = (now, total_bytes_sent, total_bytes_received);
    }

    pub fn end_session(&self) {
        self.current.write().samples.clear();
    }
}

impl Default for BandwidthRecorder {
    fn default() -> Self {
        Self::new(5)
    }
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}