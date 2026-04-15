pub mod auth;
pub mod config;
pub mod users;
pub mod logging;
pub mod snmp;
pub mod gpo;
pub mod tenant;

pub use auth::{Authenticator, AuthMethod, IdentityProvider, Session};
pub use config::EnterpriseConfig;
pub use users::{Role, User, UserManager};
pub use logging::{CentralizedLogger, LogEvent, LoggingConfig, LogFormat};
pub use snmp::{SnmpAgent, SnmpConfig, SnmpVersion, OidValue};
pub use gpo::{GpoManager, GpoTemplate, GpoSettings};
pub use tenant::{TenantManager, Tenant, TenantQuota, TenantSettings, TenantUsageReport};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error("invalid token: {0}")]
    InvalidToken(String),
    #[error("session expired")]
    SessionExpired,
    #[error("user not found: {0}")]
    UserNotFound(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("configuration error: {0}")]
    ConfigError(String),
    #[error("IdP error: {0}")]
    IdpError(String),
    #[error("logging error: {0}")]
    LoggingError(String),
    #[error("SNMP error: {0}")]
    SnmpError(String),
    #[error("GPO error: {0}")]
    GpoError(String),
    #[error("tenant error: {0}")]
    TenantError(String),
}