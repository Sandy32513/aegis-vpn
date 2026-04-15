use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

pub struct TenantManager {
    tenants: Arc<RwLock<HashMap<String, Tenant>>>,
    quotas: Arc<RwLock<HashMap<String, TenantQuota>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub name: String,
    pub domain: Option<String>,
    pub enabled: bool,
    pub created_at: i64,
    pub settings: TenantSettings,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantSettings {
    pub max_connections: Option<u32>,
    pub max_bandwidth_mbps: Option<u32>,
    pub max_sessions_per_user: Option<u32>,
    pub allowed_server_regions: Option<Vec<String>>,
    pub vpn_pool_cidr: Option<String>,
    pub custom_dns: Option<Vec<String>>,
    pub enforce_mfa: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantQuota {
    pub tenant_id: String,
    pub active_connections: u32,
    pub bandwidth_in_mb: u64,
    pub bandwidth_out_mb: u64,
    pub last_reset: i64,
}

impl Tenant {
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            domain: None,
            enabled: true,
            created_at: unix_millis(),
            settings: TenantSettings::default(),
        }
    }

    pub fn can_connect(&self, quota: &TenantQuota) -> bool {
        if !self.enabled {
            return false;
        }

        if let Some(max) = self.settings.max_connections {
            if quota.active_connections >= max {
                return false;
            }
        }

        true
    }

    pub fn has_bandwidth(&self, quota: &TenantQuota, needed_mbps: u32) -> bool {
        if let Some(max) = self.settings.max_bandwidth_mbps {
            if (quota.bandwidth_in_mb as u32) >= max || (quota.bandwidth_out_mb as u32) >= max {
                return false;
            }
        }

        true
    }
}

impl Default for TenantSettings {
    fn default() -> Self {
        Self {
            max_connections: Some(100),
            max_bandwidth_mbps: Some(1000),
            max_sessions_per_user: Some(5),
            allowed_server_regions: None,
            vpn_pool_cidr: None,
            custom_dns: None,
            enforce_mfa: false,
        }
    }
}

impl TenantManager {
    pub fn new() -> Self {
        Self {
            tenants: Arc::new(RwLock::new(HashMap::new())),
            quotas: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn create_tenant(&self, name: String) -> Tenant {
        let tenant = Tenant::new(name);
        let quota = TenantQuota {
            tenant_id: tenant.id.clone(),
            active_connections: 0,
            bandwidth_in_mb: 0,
            bandwidth_out_mb: 0,
            last_reset: unix_millis(),
        };

        self.tenants.write().insert(tenant.id.clone(), tenant.clone());
        self.quotas.write().insert(tenant.id.clone(), quota);

        tenant
    }

    pub fn get_tenant(&self, tenant_id: &str) -> Option<Tenant> {
        self.tenants.read().get(tenant_id).cloned()
    }

    pub fn get_tenant_by_domain(&self, domain: &str) -> Option<Tenant> {
        self.tenants
            .read()
            .values()
            .find(|t| t.domain.as_deref() == Some(domain))
            .cloned()
    }

    pub fn update_tenant(&self, tenant_id: &str, settings: TenantSettings) -> std::result::Result<Tenant, String> {
        let mut tenants = self.tenants.write();
        let tenant = tenants.get_mut(tenant_id).ok_or("Tenant not found")?;
        tenant.settings = settings;
        Ok(tenant.clone())
    }

    pub fn delete_tenant(&self, tenant_id: &str) -> bool {
        self.tenants.write().remove(tenant_id).is_some() && self.quotas.write().remove(tenant_id).is_some()
    }

    pub fn list_tenants(&self) -> Vec<Tenant> {
        self.tenants.read().values().cloned().collect()
    }

    pub fn record_connection(&self, tenant_id: &str) -> std::result::Result<(), String> {
        let mut quotas = self.quotas.write();
        let quota = quotas.get_mut(tenant_id).ok_or("Tenant not found")?;
        quota.active_connections += 1;
        Ok(())
    }

    pub fn close_connection(&self, tenant_id: &str) -> std::result::Result<(), String> {
        let mut quotas = self.quotas.write();
        let quota = quotas.get_mut(tenant_id).ok_or("Tenant not found")?;
        quota.active_connections = quota.active_connections.saturating_sub(1);
        Ok(())
    }

    pub fn update_bandwidth(&self, tenant_id: &str, bytes_in: u64, bytes_out: u64) -> std::result::Result<(), String> {
        let mut quotas = self.quotas.write();
        let quota = quotas.get_mut(tenant_id).ok_or("Tenant not found")?;
        quota.bandwidth_in_mb += bytes_in / (1024 * 1024);
        quota.bandwidth_out_mb += bytes_out / (1024 * 1024);
        Ok(())
    }

    pub fn get_quota(&self, tenant_id: &str) -> Option<TenantQuota> {
        self.quotas.read().get(tenant_id).cloned()
    }

    pub fn reset_quota(&self, tenant_id: &str) -> std::result::Result<(), String> {
        let mut quotas = self.quotas.write();
        let quota = quotas.get_mut(tenant_id).ok_or("Tenant not found")?;
        quota.active_connections = 0;
        quota.bandwidth_in_mb = 0;
        quota.bandwidth_out_mb = 0;
        quota.last_reset = unix_millis();
        Ok(())
    }

    pub fn get_usage_report(&self, tenant_id: &str) -> Option<TenantUsageReport> {
        let tenant = self.tenants.read().get(tenant_id)?;
        let quota = self.quotas.read().get(tenant_id)?;

        Some(TenantUsageReport {
            tenant: tenant.clone(),
            quota: quota.clone(),
            connection_usage: quota.active_connections as f64
                / tenant.settings.max_connections.unwrap_or(100) as f64
                * 100.0,
            bandwidth_usage: ((quota.bandwidth_in_mb + quota.bandwidth_out_mb) as f64
                / tenant.settings.max_bandwidth_mbps.unwrap_or(1000) as f64
                * 100.0),
        })
    }
}

impl Default for TenantManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantUsageReport {
    pub tenant: Tenant,
    pub quota: TenantQuota,
    pub connection_usage: f64,
    pub bandwidth_usage: f64,
}

fn unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}