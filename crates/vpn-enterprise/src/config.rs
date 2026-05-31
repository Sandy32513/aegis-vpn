use crate::auth::IdentityProvider;
use crate::users::Role;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnterpriseConfig {
    pub enabled: bool,
    pub auth: AuthConfig,
    pub rbac: RbacConfig,
    pub logging: LoggingConfig,
    pub tenants: Option<TenantsConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthConfig {
    pub method: String,
    pub idp: Option<IdpConfig>,
    pub session_timeout_secs: u64,
    pub require_mfa: bool,
    pub allow_password_auth: bool,
    pub password_policy: PasswordPolicy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdpConfig {
    pub idp_type: String,
    pub config: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub expiry_days: u32,
    pub history_count: u32,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: false,
            expiry_days: 90,
            history_count: 5,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RbacConfig {
    pub default_role: String,
    pub enforce_rbac: bool,
    pub role_mappings: HashMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantsConfig {
    pub enabled: bool,
    pub isolation_mode: String,
    pub per_tenant_logging: bool,
    pub quota_enforcement: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub format: String,
    pub syslog_enabled: bool,
    pub syslog_host: Option<String>,
    pub syslog_port: Option<u16>,
    pub splunk_enabled: bool,
    pub splunk_hec_url: Option<String>,
    pub splunk_hec_token: Option<String>,
    pub cef_enabled: bool,
    pub retention_days: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            format: "json".to_string(),
            syslog_enabled: false,
            syslog_host: None,
            syslog_port: None,
            splunk_enabled: false,
            splunk_hec_url: None,
            splunk_hec_token: None,
            cef_enabled: false,
            retention_days: 90,
        }
    }
}

impl Default for EnterpriseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auth: AuthConfig {
                method: "none".to_string(),
                idp: None,
                session_timeout_secs: 3600,
                require_mfa: false,
                allow_password_auth: true,
                password_policy: PasswordPolicy::default(),
            },
            rbac: RbacConfig {
                default_role: "user".to_string(),
                enforce_rbac: false,
                role_mappings: HashMap::new(),
            },
            logging: LoggingConfig::default(),
            tenants: None,
        }
    }
}

impl EnterpriseConfig {
    pub fn load(path: &Path) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let text = std::fs::read_to_string(path)?;
        let config: EnterpriseConfig = toml::from_str(&text)?;
        Ok(config)
    }

    pub fn load_default() -> std::result::Result<Self, Box<dyn std::error::Error>> {
        let path = Path::new("config/enterprise.toml");
        if path.exists() {
            Self::load(path)
        } else {
            Ok(Self::default())
        }
    }

    pub fn validate(&self) -> std::result::Result<(), Box<dyn std::error::Error>> {
        if self.enabled {
            if self.auth.method != "none" && self.auth.idp.is_none() {
                return Err("method set but no IdP configured".into());
            }
        }

        if self.auth.password_policy.min_length < 4 {
            return Err("password policy min_length must be at least 4".into());
        }

        if self.logging.retention_days < 1 {
            return Err("logging retention_days must be at least 1".into());
        }

        Ok(())
    }

    pub fn to_identity_provider(&self) -> Option<IdentityProvider> {
        if !self.enabled {
            return None;
        }

        match self.auth.method.as_str() {
            "saml" => {
                if let Some(idp_config) = &self.auth.idp {
                    if let Ok(config) = serde_json::from_value::<crate::auth::SamlIdpConfig>(idp_config.config.clone()) {
                        return Some(IdentityProvider::SAML(config));
                    }
                }
                None
            }
            "oidc" => {
                if let Some(idp_config) = &self.auth.idp {
                    if let Ok(config) = serde_json::from_value::<crate::auth::OidcIdpConfig>(idp_config.config.clone()) {
                        return Some(IdentityProvider::OIDC(config));
                    }
                }
                None
            }
            "ldap" => {
                if let Some(idp_config) = &self.auth.idp {
                    if let Ok(config) = serde_json::from_value::<crate::auth::LdapIdpConfig>(idp_config.config.clone()) {
                        return Some(IdentityProvider::LDAP(config));
                    }
                }
                None
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub domain: Option<String>,
    pub enabled: bool,
    pub connection_limit: Option<u32>,
    pub bandwidth_limit_mbps: Option<u32>,
    pub created_at: i64,
}

impl Tenant {
    pub fn new(name: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            domain: None,
            enabled: true,
            connection_limit: None,
            bandwidth_limit_mbps: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantQuota {
    pub tenant_id: String,
    pub active_connections: u32,
    pub max_connections: Option<u32>,
    pub bandwidth_used_mb: u64,
    pub bandwidth_limit_mb: Option<u64>,
    pub last_reset: i64,
}

impl TenantQuota {
    pub fn can_connect(&self) -> bool {
        if let Some(max) = self.max_connections {
            self.active_connections < max
        } else {
            true
        }
    }

    pub fn has_bandwidth(&self, needed_mb: u64) -> bool {
        if let Some(limit) = self.bandwidth_limit_mb {
            (self.bandwidth_used_mb + needed_mb) <= limit
        } else {
            true
        }
    }
}