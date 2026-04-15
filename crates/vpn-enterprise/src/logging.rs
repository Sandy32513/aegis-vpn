use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub struct CentralizedLogger {
    config: Arc<RwLock<LoggingConfig>>,
    syslog_socket: Arc<RwLock<Option<std::net::UdpSocket>>>,
    buffer: Arc<RwLock<Vec<u8>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub format: LogFormat,
    pub syslog: Option<SyslogConfig>,
    pub splunk: Option<SplunkConfig>,
    pub cef: Option<CefConfig>,
    pub retention_days: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LogFormat {
    Json,
    Syslog,
    Cef,
    Plain,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyslogConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub facility: String,
    pub app_name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SplunkConfig {
    pub enabled: bool,
    pub hec_url: String,
    pub hec_token: String,
    pub index: String,
    pub source: String,
    pub sourcetype: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CefConfig {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub device_vendor: String,
    pub device_product: String,
    pub device_version: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Json,
            syslog: None,
            splunk: None,
            cef: None,
            retention_days: 90,
        }
    }
}

impl CentralizedLogger {
    pub fn new(config: LoggingConfig) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let syslog_socket = if let Some(ref syslog) = config.syslog {
            if syslog.enabled {
                let addr: SocketAddr = format!("{}:{}", syslog.host, syslog.port).parse()?;
                let socket = std::net::Udp::bind("0.0.0.0:0")?;
                socket.connect(addr)?;
                Some(socket)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            syslog_socket: Arc::new(RwLock::new(syslog_socket)),
            buffer: Arc::new(RwLock::new(Vec::with_capacity(4096))),
        })
    }

    pub fn log(&self, event: &LogEvent) -> std::result::Result<(), String> {
        let config = self.config.read().clone();

        match config.format {
            LogFormat::Json => self.log_json(event)?,
            LogFormat::Syslog => self.log_syslog(event)?,
            LogFormat::Cef => self.log_cef(event)?,
            LogFormat::Plain => self.log_plain(event)?,
        }

        if let Some(ref splunk) = config.splunk {
            if splunk.enabled {
                self.send_to_splunk(event, splunk)?;
            }
        }

        if let Some(ref cef) = config.cef {
            if cef.enabled {
                self.send_to_cef(event, cef)?;
            }
        }

        Ok(())
    }

    fn log_json(&self, event: &LogEvent) -> std::result::Result<(), String> {
        let json = serde_json::to_string(event).map_err(|e| e.to_string())?;
        tracing::debug!("{}", json);
        Ok(())
    }

    fn log_syslog(&self, event: &LogEvent) -> std::result::Result<(), String> {
        let config = self.config.read();
        let syslog = config.syslog.as_ref().ok_or("Syslog not configured")?;

        let facility_code = syslog_facility_code(&syslog.facility);
        let severity = syslog_severity(&event.level);
        let priority = (facility_code * 8) + severity;

        let timestamp = chrono::Utc::now().format("%b %d %H:%M:%S");
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let message = format!(
            "<{}>{} {} {}: {}",
            priority,
            timestamp,
            hostname,
            syslog.app_name,
            event.message
        );

        let socket = self.syslog_socket.read();
        if let Some(ref sock) = *socket {
            sock.send(message.as_bytes()).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    fn log_cef(&self, event: &LogEvent) -> std::result::Result<(), String> {
        let config = self.config.read();
        let cef = config.cef.as_ref().ok_or("CEF not configured")?;

        let timestamp = chrono::Utc::now().to_rfc3339();
        let cef_version = "0";
        let device_vendor = &cef.device_vendor;
        let device_product = &cef.device_product;
        let device_version = &cef.device_version;
        let signature = format!("{}:{}", event.event_type, event.event_id);
        let severity = cef_severity(&event.level);

        let cef_line = format!(
            "CEF:{}|{}|{}|{}|{}|{}|{}",
            cef_version, device_vendor, device_product, device_version, signature, event.message, severity
        );

        let message = format!("CEF:{} {}", cef_version, event.message);

        let socket = self.syslog_socket.read();
        if let Some(ref sock) = *sock {
            sock.send(message.as_bytes()).map_err(|e| e.to_string())?;
        }

        let _ = timestamp;
        Ok(())
    }

    fn log_plain(&self, event: &LogEvent) -> std::result::Result<(), String> {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let line = format!(
            "[{}] {}: {} - {}",
            timestamp, event.level, event.event_type, event.message
        );
        tracing::debug!("{}", line);
        Ok(())
    }

    fn send_to_splunk(&self, event: &LogEvent, config: &SplunkConfig) -> std::result::Result<(), String> {
        let client = reqwest::blocking::Client::new();

        let payload = serde_json::json!({
            "time": chrono::Utc::now().timestamp(),
            "host": hostname::get().map(|h| h.to_string_lossy().to_string()).unwrap_or_default(),
            "source": config.source,
            "sourcetype": config.sourcetype,
            "index": config.index,
            "event": event,
        });

        client
            .post(&config.hec_url)
            .header("Authorization", format!("Splunk {}", config.hec_token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    fn send_to_cef(&self, event: &LogEvent, config: &CefConfig) -> std::result::Result<(), String> {
        let severity = cef_severity(&event.level);
        let message = format!(
            "CEF:0|{}|{}|{}|{}|{}|{}",
            config.device_vendor,
            config.device_product,
            config.device_version,
            event.event_type,
            event.message,
            severity
        );

        let socket = self.syslog_socket.read();
        if let Some(ref sock) = *socket {
            sock.send(message.as_bytes()).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    pub fn configure(&self, config: LoggingConfig) -> std::result::Result<(), Box<dyn std::error::Error>> {
        *self.config.write() = config;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogEvent {
    pub timestamp: i64,
    pub level: String,
    pub event_type: String,
    pub event_id: String,
    pub message: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub tenant_id: Option<String>,
    pub source_ip: Option<String>,
    pub metadata: serde_json::Value,
}

impl LogEvent {
    pub fn new(level: &str, event_type: &str, message: &str) -> Self {
        Self {
            timestamp: unix_millis(),
            level: level.to_string(),
            event_type: event_type.to_string(),
            event_id: uuid::Uuid::new_v4().to_string(),
            message: message.to_string(),
            user_id: None,
            session_id: None,
            tenant_id: None,
            source_ip: None,
            metadata: serde_json::json!({}),
        }
    }

    pub fn with_user(mut self, user_id: &str) -> Self {
        self.user_id = Some(user_id.to_string());
        self
    }

    pub fn with_session(mut self, session_id: &str) -> Self {
        self.session_id = Some(session_id.to_string());
        self
    }

    pub fn with_tenant(mut self, tenant_id: &str) -> Self {
        self.tenant_id = Some(tenant_id.to_string());
        self
    }

    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = metadata;
        self
    }
}

fn syslog_facility_code(facility: &str) -> u8 {
    match facility.to_lowercase().as_str() {
        "auth" => 4,
        "authpriv" => 10,
        "cron" => 9,
        "daemon" => 3,
        "ftp" => 11,
        "kern" => 0,
        "lpr" => 6,
        "mail" => 2,
        "news" => 7,
        "syslog" => 12,
        "user" => 1,
        "uucp" => 8,
        _ => 1,
    }
}

fn syslog_severity(level: &str) -> u8 {
    match level.to_lowercase().as_str() {
        "emergency" => 0,
        "alert" => 1,
        "critical" => 2,
        "error" => 3,
        "warning" => 4,
        "notice" => 5,
        "info" => 6,
        "debug" => 7,
        _ => 6,
    }
}

fn cef_severity(level: &str) -> u8 {
    match level.to_lowercase().as_str() {
        "emergency" | "critical" => 10,
        "error" => 8,
        "warning" => 6,
        "notice" | "info" => 4,
        "debug" => 1,
        _ => 4,
    }
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

mod chrono {
    pub struct Utc;
    impl Utc {
        pub fn now() -> Self {
            Utc
        }
        pub fn to_rfc3339(&self) -> String {
            "2024-01-01T00:00:00Z".to_string()
        }
    }
    pub struct Signed {
        pub timestamp: i64,
    }
    impl Signed {
        pub fn format(&self, fmt: &str) -> String {
            "2024-01-01T00:00:00Z".to_string()
        }
    }
}

mod hostname {
    pub fn get() -> std::result::Result<std::ffi::OsString, std::io::Error> {
        Ok(std::ffi::OsString::from("aegis-vpn"))
    }
}