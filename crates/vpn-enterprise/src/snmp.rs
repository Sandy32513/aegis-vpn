use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

pub struct SnmpAgent {
    config: Arc<RwLock<SnmpConfig>>,
    caches: Arc<RwLock<HashMap<String, OidValue>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnmpConfig {
    pub enabled: bool,
    pub version: SnmpVersion,
    pub bind_addr: String,
    pub port: u16,
    pub community: String,
    pub v3_config: Option<V3Config>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SnmpVersion {
    V2c,
    V3,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct V3Config {
    pub user: String,
    pub auth_protocol: String,
    pub auth_key: String,
    pub priv_protocol: String,
    pub priv_key: String,
}

#[derive(Clone, Debug)]
pub enum OidValue {
    Integer(i32),
    Counter(u32),
    Counter64(u64),
    Gauge(u32),
    OctetString(Vec<u8>),
    Timeticks(u32),
    IpAddress([u8; 4]),
}

pub const OID_SYSTEM_DESCRIPTION: &str = "1.3.6.1.2.1.1.1.0";
pub const OID_SYSTEM_UPTIME: &str = "1.3.6.1.2.1.1.3.0";
pub const OID_SYSTEM_CONTACT: &str = "1.3.6.1.2.1.1.4.0";
pub const OID_SYSTEM_NAME: &str = "1.3.6.1.2.1.1.5.0";
pub const OID_SYSTEM_LOCATION: &str = "1.3.6.1.2.1.1.6.0";

pub const OID_IF_NUMBER: &str = "1.3.6.1.2.2.1.0";
pub const OID_IF_DESCR: &str = "1.3.6.1.2.2.1.2.1";
pub const OID_IF_TYPE: &str = "1.3.6.1.2.2.1.3.1";
pub const OID_IF_MTU: &str = "1.3.6.1.2.2.1.4.1";
pub const OID_IF_SPEED: &str = "1.3.6.1.2.2.1.5.1";
pub const OID_IF_PHYS_ADDRESS: &str = "1.3.6.1.2.2.1.6.1";
pub const OID_IF_ADMIN_STATUS: &str = "1.3.6.1.2.2.1.7.1";
pub const OID_IF_OPER_STATUS: &str = "1.3.6.1.2.2.1.8.1";
pub const OID_IF_IN_OCTETS: &str = "1.3.6.1.2.2.1.10.1";
pub const OID_IF_OUT_OCTETS: &str = "1.3.6.1.2.2.1.16.1";

pub const OID_VPN_CONNECTIONS: &str = "1.3.6.1.4.1.9999.1.1.0";
pub const OID_VPN_BYTES_IN: &str = "1.3.6.1.4.1.9999.1.2.0";
pub const OID_VPN_BYTES_OUT: &str = "1.3.6.1.4.1.9999.1.3.0";
pub const OID_VPN_STATUS: &str = "1.3.6.1.4.1.9999.1.4.0";

impl SnmpAgent {
    pub fn new(config: SnmpConfig) -> Self {
        let agent = Self {
            config: Arc::new(RwLock::new(config)),
            caches: Arc::new(RwLock::new(HashMap::new())),
        };
        agent.init_mibs();
        agent
    }

    fn init_mibs(&self) {
        let mut cache = self.caches.write();
        
        cache.insert(OID_SYSTEM_DESCRIPTION.to_string(), OidValue::OctetString(b"Aegis VPN".to_vec()));
        cache.insert(OID_SYSTEM_NAME.to_string(), OidValue::OctetString(b"Aegis VPN".to_vec()));
        cache.insert(OID_SYSTEM_CONTACT.to_string(), OidValue::OctetString(b"admin@aegis.local".to_vec()));
        cache.insert(OID_SYSTEM_LOCATION.to_string(), OidValue::OctetString(b"Local".to_vec()));
        
        cache.insert(OID_IF_NUMBER.to_string(), OidValue::Integer(1));
        cache.insert(OID_IF_DESCR.to_string(), OidValue::OctetString(b"TUN".to_vec()));
        cache.insert(OID_IF_TYPE.to_string(), OidValue::Integer(1));
        cache.insert(OID_IF_MTU.to_string(), OidValue::Integer(1400));
        cache.insert(OID_IF_SPEED.to_string(), OidValue::Gauge(100000));
        cache.insert(OID_IF_ADMIN_STATUS.to_string(), OidValue::Integer(1));
        cache.insert(OID_IF_OPER_STATUS.to_string(), OidValue::Integer(1));
        
        cache.insert(OID_VPN_CONNECTIONS.to_string(), OidValue::Gauge(0));
        cache.insert(OID_VPN_BYTES_IN.to_string(), OidValue::Counter64(0));
        cache.insert(OID_VPN_BYTES_OUT.to_string(), OidValue::Counter64(0));
        cache.insert(OID_VPN_STATUS.to_string(), OidValue::Integer(1));
    }

    pub fn update_connections(&self, count: u32) {
        self.caches.write().insert(OID_VPN_CONNECTIONS.to_string(), OidValue::Gauge(count));
    }

    pub fn update_bytes(&self, bytes_in: u64, bytes_out: u64) {
        self.caches.write().insert(OID_VPN_BYTES_IN.to_string(), OidValue::Counter64(bytes_in));
        self.caches.write().insert(OID_VPN_BYTES_OUT.to_string(), OidValue::Counter64(bytes_out));
    }

    pub fn update_status(&self, status: i32) {
        self.caches.write().insert(OID_VPN_STATUS.to_string(), OidValue::Integer(status));
    }

    pub fn update_interface_stats(&self, in_octets: u64, out_octets: u64) {
        self.caches.write().insert(OID_IF_IN_OCTETS.to_string(), OidValue::Counter64(in_octets));
        self.caches.write().insert(OID_IF_OUT_OCTETS.to_string(), OidValue::Counter64(out_octets));
    }

    pub fn get(&self, oid: &str) -> Option<OidValue> {
        self.caches.read().get(oid).cloned()
    }

    pub fn walk(&self, prefix: &str) -> HashMap<String, OidValue> {
        let cache = self.caches.read();
        cache
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn get_next(&self, oid: &str) -> Option<(String, OidValue)> {
        let cache = self.caches.read();
        let mut oids: Vec<_> = cache.keys().collect();
        oids.sort();
        
        for (k, v) in cache.iter() {
            if k > oid {
                return Some((k.clone(), v.clone()));
            }
        }
        None
    }
}

impl Default for SnmpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            version: SnmpVersion::V2c,
            bind_addr: "0.0.0.0".to_string(),
            port: 161,
            community: "public".to_string(),
            v3_config: None,
        }
    }
}