use anyhow::{anyhow, Context, Result};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub client: ClientConfig,
    pub server: ServerConfig,
    pub control_plane: ControlPlaneConfig,
    pub dns: DnsConfig,
    pub logging: LoggingConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_endpoint: String,
    pub trusted_server_public_key: Option<String>,
    pub bind_address: String,
    pub tun_name: String,
    pub tun_cidr: String,
    pub mtu: u32,
    pub rotation_interval_secs: u64,
    pub kill_switch: bool,
    pub config_identity_dir: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_address: String,
    pub transport_port: u16,
    pub tun_name: String,
    pub tun_cidr: String,
    pub client_pool_cidr: String,
    pub egress_interface: String,
    pub nat_mode: String,
    pub session_timeout_secs: u64,
    pub config_identity_dir: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlPlaneConfig {
    pub node_id: String,
    pub bootstrap_token_env: Option<String>,
    pub allow_persist_identity: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsConfig {
    pub servers: Vec<String>,
    pub search_domains: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub json_log_path: Option<String>,
    pub mysql_url: Option<String>,
    pub level: String,
}

#[derive(Clone, Copy, Debug)]
pub enum IdentityRole {
    Client,
    Server,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key_hex: String,
    pub private_key_hex: String,
    pub fingerprint: String,
}

impl KeyPair {
    pub fn public_key_bytes(&self) -> Result<[u8; 32]> {
        decode_32("public key", &self.public_key_hex)
    }

    pub fn private_key_bytes(&self) -> Result<[u8; 32]> {
        decode_32("private key", &self.private_key_hex)
    }
}

pub fn decode_public_key_hex(value: &str) -> Result<[u8; 32]> {
    decode_32("public key", value)
}

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<Config> {
    let text = fs::read_to_string(path.as_ref())
        .with_context(|| format!("failed to read config file {}", path.as_ref().display()))?;
    let config: Config = toml::from_str(&text)
        .with_context(|| format!("failed to parse config file {}", path.as_ref().display()))?;
    validate_config(&config)?;
    Ok(config)
}

pub fn load_default_config() -> Result<Config> {
    let primary = PathBuf::from("config/control-plane.toml");
    if primary.exists() {
        return load_config(primary);
    }

    let example = PathBuf::from("config/control-plane.example.toml");
    load_config(example)
}

pub fn get_identity(config: &Config, role: IdentityRole) -> Result<KeyPair> {
    let identity_dir = match role {
        IdentityRole::Client => &config.client.config_identity_dir,
        IdentityRole::Server => &config.server.config_identity_dir,
    };

    let role_name = match role {
        IdentityRole::Client => "client",
        IdentityRole::Server => "server",
    };

    let dir = PathBuf::from(identity_dir);
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create identity directory {}", dir.display()))?;
    let identity_path = dir.join(format!("{role_name}.identity.toml"));

    if identity_path.exists() {
        let text = fs::read_to_string(&identity_path)
            .with_context(|| format!("failed to read identity file {}", identity_path.display()))?;
        let pair: KeyPair = toml::from_str(&text).with_context(|| {
            format!("failed to parse identity file {}", identity_path.display())
        })?;
        validate_identity(&pair)?;
        return Ok(pair);
    }

    let pair = generate_identity_pair();

    if !config.control_plane.allow_persist_identity {
        return Ok(pair);
    }

    if let Some(env_name) = &config.control_plane.bootstrap_token_env {
        let _ = std::env::var(env_name).with_context(|| {
            format!(
                "bootstrap token env var {env_name} is required for first-run identity generation"
            )
        })?;
    }

    let encoded = toml::to_string_pretty(&pair)?;
    write_secure_file(&identity_path, encoded.as_bytes())?;
    Ok(pair)
}

fn validate_config(config: &Config) -> Result<()> {
    if config.client.server_endpoint.is_empty() {
        return Err(anyhow!("client.server_endpoint must not be empty"));
    }
    if config.client.rotation_interval_secs == 0 {
        return Err(anyhow!("client.rotation_interval_secs must be > 0"));
    }
    if config.server.transport_port == 0 {
        return Err(anyhow!("server.transport_port must be > 0"));
    }
    if config.server.session_timeout_secs == 0 {
        return Err(anyhow!("server.session_timeout_secs must be > 0"));
    }
    if config.dns.servers.is_empty() {
        return Err(anyhow!("dns.servers must contain at least one resolver"));
    }
    if !matches!(config.server.nat_mode.as_str(), "iptables" | "nftables") {
        return Err(anyhow!(
            "server.nat_mode must be either 'iptables' or 'nftables'"
        ));
    }
    Ok(())
}

fn validate_identity(identity: &KeyPair) -> Result<()> {
    let _ = identity.public_key_bytes()?;
    let _ = identity.private_key_bytes()?;
    Ok(())
}

fn generate_identity_pair() -> KeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let private_bytes = secret.to_bytes();
    let public_bytes = public.to_bytes();
    let fingerprint = hex::encode(Sha256::digest(public_bytes));

    KeyPair {
        public_key_hex: hex::encode(public_bytes),
        private_key_hex: hex::encode(private_bytes),
        fingerprint,
    }
}

fn write_secure_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {} for writing", path.display()))?;
    file.write_all(bytes)?;
    file.flush()?;
    Ok(())
}

fn decode_32(label: &str, value: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(value)?;
    if raw.len() != 32 {
        return Err(anyhow!("{label} must be 32 bytes"));
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_like_config_parses() {
        let config = r#"
[client]
server_endpoint = "127.0.0.1:7000"
trusted_server_public_key = ""
bind_address = "0.0.0.0:0"
tun_name = "aegis0"
tun_cidr = "10.20.0.2/24"
mtu = 1400
rotation_interval_secs = 300
kill_switch = true
config_identity_dir = "state/client"

[server]
listen_address = "0.0.0.0:7000"
transport_port = 7000
tun_name = "aegis-srv0"
tun_cidr = "10.20.0.1/24"
client_pool_cidr = "10.20.0.0/24"
egress_interface = "eth0"
nat_mode = "iptables"
session_timeout_secs = 300
config_identity_dir = "state/server"

[control_plane]
node_id = "edge-01"
bootstrap_token_env = "AEGIS_BOOTSTRAP_TOKEN"
allow_persist_identity = true

[dns]
servers = ["1.1.1.1"]
search_domains = []

[logging]
json_log_path = "logs/aegis.jsonl"
mysql_url = ""
level = "info"
"#;

        let parsed: Config = toml::from_str(config).expect("parse config");
        validate_config(&parsed).expect("validate config");
    }
}
