pub mod events;

use anyhow::Result;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use std::{path::PathBuf, sync::Arc};
use tokio::{
    fs::{File, OpenOptions},
    io::AsyncWriteExt,
    sync::Mutex,
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LoggerConfig {
    pub service_name: String,
    pub json_log_path: Option<PathBuf>,
    pub mysql_url: Option<String>,
    pub chain_key: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogRecord {
    pub service: String,
    pub category: String,
    pub event: String,
    pub fields: Value,
    pub prev_hmac: Option<String>,
    pub row_hmac: String,
    pub timestamp: String,
    pub level: String,
}

#[derive(Clone)]
pub struct EventLogger {
    service_name: String,
    file: Option<Arc<Mutex<File>>>,
    prev_hmac: Arc<Mutex<Option<[u8; 32]>>>,
    chain_key: [u8; 32],
    #[cfg(feature = "mysql")]
    mysql: Option<sqlx::MySqlPool>,
}

pub fn init_tracing() {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("info")
        .json()
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

impl EventLogger {
    pub async fn new(config: LoggerConfig) -> Result<Self> {
        let file = if let Some(path) = config.json_log_path {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;
            Some(Arc::new(Mutex::new(file)))
        } else {
            None
        };

        #[cfg(feature = "mysql")]
        let mysql = if let Some(url) = config.mysql_url {
            Some(sqlx::MySqlPool::connect(&url).await?)
        } else {
            None
        };

        #[cfg(not(feature = "mysql"))]
        let _ = config.mysql_url;

        Ok(Self {
            service_name: config.service_name,
            file,
            prev_hmac: Arc::new(Mutex::new(None)),
            chain_key: config.chain_key,
            #[cfg(feature = "mysql")]
            mysql,
        })
    }

    pub async fn log(&self, category: &str, event: &str, fields: Value) -> Result<()> {
        self.log_with_level(LogLevel::Info, category, event, fields)
            .await
    }

    pub async fn log_with_level(
        &self,
        level: LogLevel,
        category: &str,
        event: &str,
        fields: Value,
    ) -> Result<()> {
        let mut prev_guard = self.prev_hmac.lock().await;
        let prev_hex = prev_guard.as_ref().map(hex::encode);
        let timestamp = chrono_timestamp();

        let canonical = json!({
            "service": self.service_name,
            "category": category,
            "event": event,
            "fields": fields,
            "prev_hmac": prev_hex,
            "timestamp": &timestamp,
            "level": level.to_string(),
        });
        let canonical_bytes = serde_json::to_vec(&canonical)?;
        let row_hmac = compute_hmac(&self.chain_key, prev_guard.as_ref(), &canonical_bytes)?;
        *prev_guard = Some(row_hmac);

        let record = LogRecord {
            service: self.service_name.clone(),
            category: category.to_string(),
            event: event.to_string(),
            fields,
            prev_hmac: prev_hex,
            row_hmac: hex::encode(row_hmac),
            timestamp,
            level: level.to_string(),
        };

        let line = serde_json::to_string(&record)?;
        tracing::info!(target: "vpn", "{}", line);

        if let Some(file) = &self.file {
            let mut guard = file.lock().await;
            guard.write_all(line.as_bytes()).await?;
            guard.write_all(b"\n").await?;
            guard.flush().await?;
        }

        #[cfg(feature = "mysql")]
        if let Some(pool) = &self.mysql {
            sqlx::query(
                "INSERT INTO event_log (service_name, category, event_name, level, ts_unix_ms, fields_json, prev_hmac, row_hmac) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&record.service)
            .bind(&record.category)
            .bind(event)
            .bind(&record.level)
            .bind(&record.timestamp)
            .bind(record.fields.to_string())
            .bind(record.prev_hmac.clone())
            .bind(record.row_hmac.clone())
            .execute(pool)
            .await?;
        }

        Ok(())
    }

    pub async fn log_warn(&self, category: &str, event: &str, fields: Value) -> Result<()> {
        self.log_with_level(LogLevel::Warn, category, event, fields)
            .await
    }

    pub async fn log_error(&self, category: &str, event: &str, fields: Value) -> Result<()> {
        self.log_with_level(LogLevel::Error, category, event, fields)
            .await
    }

    pub async fn log_debug(&self, category: &str, event: &str, fields: Value) -> Result<()> {
        self.log_with_level(LogLevel::Debug, category, event, fields)
            .await
    }
}

fn compute_hmac(key: &[u8; 32], prev: Option<&[u8; 32]>, data: &[u8]) -> Result<[u8; 32]> {
    let mut mac = HmacSha256::new_from_slice(key)?;
    if let Some(prev) = prev {
        mac.update(prev);
    }
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn logger_creates_parent_directories() {
        let root = std::env::temp_dir().join(format!("aegis-vpn-test-{}", std::process::id()));
        let path = root.join("nested").join("events.jsonl");
        let logger = EventLogger::new(LoggerConfig {
            service_name: "test".to_string(),
            json_log_path: Some(path.clone()),
            mysql_url: None,
            chain_key: [7u8; 32],
        })
        .await
        .expect("create logger");

        logger
            .log("test", "created", json!({"ok": true}))
            .await
            .expect("write log");

        assert!(path.exists());
        let _ = tokio::fs::remove_dir_all(root).await;
    }
}

fn chrono_timestamp() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    now.as_millis().to_string()
}
