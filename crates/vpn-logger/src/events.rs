use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::EventLogger;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionEvent<'a> {
    pub event: &'a str,
    pub session_id: Option<u64>,
    pub peer: Option<&'a str>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotationEvent<'a> {
    pub event: &'a str,
    pub old_circuit: Option<&'a str>,
    pub new_circuit: Option<&'a str>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorEvent<'a> {
    pub component: &'a str,
    pub error: &'a str,
}

impl EventLogger {
    pub async fn log_connection_event(&self, event: ConnectionEvent<'_>) -> anyhow::Result<()> {
        self.log(
            "connection",
            event.event,
            json!({
                "session_id": event.session_id,
                "peer": event.peer,
            }),
        )
        .await
    }

    pub async fn log_rotation_event(&self, event: RotationEvent<'_>) -> anyhow::Result<()> {
        self.log(
            "rotation",
            event.event,
            json!({
                "old_circuit": event.old_circuit,
                "new_circuit": event.new_circuit,
            }),
        )
        .await
    }

    pub async fn log_error_event(&self, event: ErrorEvent<'_>) -> anyhow::Result<()> {
        self.log(
            "error",
            event.component,
            json!({
                "error": event.error,
            }),
        )
        .await
    }
}
