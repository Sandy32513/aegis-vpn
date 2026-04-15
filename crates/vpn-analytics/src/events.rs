use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionEvent {
    pub id: String,
    pub event_type: EventType,
    pub session_id: String,
    pub server: Option<String>,
    pub timestamp: i64,
    pub duration_ms: Option<u64>,
    pub metadata: serde_json::Value,
}

impl ConnectionEvent {
    pub fn new(event_type: EventType, session_id: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            event_type,
            session_id: session_id.to_string(),
            server: None,
            timestamp: unix_millis(),
            duration_ms: None,
            metadata: serde_json::json!({}),
        }
    }

    pub fn with_server(mut self, server: &str) -> Self {
        self.server = Some(server.to_string());
        self
    }

    pub fn with_duration(mut self, duration_ms: u64) -> Self {
        self.duration_ms = Some(duration_ms);
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum EventType {
    ConnectStarted,
    HandshakeStarted,
    HandshakeComplete,
    Connected,
    Disconnected,
    Reconnecting,
    ReconnectComplete,
    Error,
    RotationStarted,
    RotationComplete,
    PacketSent,
    PacketReceived,
    LatencyMeasured,
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::ConnectStarted => write!(f, "connect_started"),
            EventType::HandshakeStarted => write!(f, "handshake_started"),
            EventType::HandshakeComplete => write!(f, "handshake_complete"),
            EventType::Connected => write!(f, "connected"),
            EventType::Disconnected => write!(f, "disconnected"),
            EventType::Reconnecting => write!(f, "reconnecting"),
            EventType::ReconnectComplete => write!(f, "reconnect_complete"),
            EventType::Error => write!(f, "error"),
            EventType::RotationStarted => write!(f, "rotation_started"),
            EventType::RotationComplete => write!(f, "rotation_complete"),
            EventType::PacketSent => write!(f, "packet_sent"),
            EventType::PacketReceived => write!(f, "packet_received"),
            EventType::LatencyMeasured => write!(f, "latency_measured"),
        }
    }
}

pub struct EventRecorder {
    events: Arc<RwLock<VecDeque<ConnectionEvent>>>,
    max_events: usize,
}

impl EventRecorder {
    pub fn new(max_events: usize) -> Self {
        Self {
            events: Arc::new(RwLock::new(VecDeque::with_capacity(max_events))),
            max_events,
        }
    }

    pub fn record(&self, event: ConnectionEvent) {
        let mut events = self.events.write();
        if events.len() >= self.max_events {
            events.pop_front();
        }
        events.push_back(event);
    }

    pub fn events(&self) -> Vec<ConnectionEvent> {
        self.events.read().iter().cloned().collect()
    }

    pub fn recent(&self, count: usize) -> Vec<ConnectionEvent> {
        let events = self.events.read();
        events.iter().rev().take(count).cloned().collect()
    }

    pub fn clear(&self) {
        self.events.write().clear();
    }

    pub fn filter_by_type(&self, event_type: &EventType) -> Vec<ConnectionEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| &e.event_type == event_type)
            .cloned()
            .collect()
    }

    pub fn filter_by_session(&self, session_id: &str) -> Vec<ConnectionEvent> {
        self.events
            .read()
            .iter()
            .filter(|e| e.session_id == session_id)
            .cloned()
            .collect()
    }
}

impl Default for EventRecorder {
    fn default() -> Self {
        Self::new(5000)
    }
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}