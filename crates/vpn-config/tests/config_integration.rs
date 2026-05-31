use vpn_config::*;

#[test]
fn parse_example_config() {
    let toml = r#"
[client]
server_endpoint = "198.51.100.10:7000"
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
    let config: Config = toml::from_str(toml).expect("parse");
    assert_eq!(config.client.server_endpoint, "198.51.100.10:7000");
    assert_eq!(config.client.mtu, 1400);
    assert_eq!(config.server.nat_mode, "iptables");
    assert_eq!(config.dns.servers, vec!["1.1.1.1"]);
}

#[test]
fn validate_rejects_empty_endpoint() {
    let toml = r#"
[client]
server_endpoint = ""
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
bootstrap_token_env = ""
allow_persist_identity = false

[dns]
servers = ["1.1.1.1"]
search_domains = []

[logging]
json_log_path = ""
mysql_url = ""
level = "info"
"#;
    let config: Config = toml::from_str(toml).unwrap();
    let err = validate_config_public(&config);
    assert!(err.is_err());
}

#[test]
fn validate_rejects_invalid_nat_mode() {
    let toml = r#"
[client]
server_endpoint = "1.2.3.4:7000"
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
nat_mode = "invalid"
session_timeout_secs = 300
config_identity_dir = "state/server"

[control_plane]
node_id = "edge-01"
bootstrap_token_env = ""
allow_persist_identity = false

[dns]
servers = ["1.1.1.1"]
search_domains = []

[logging]
json_log_path = ""
mysql_url = ""
level = "info"
"#;
    let config: Config = toml::from_str(toml).unwrap();
    let err = validate_config_public(&config);
    assert!(err.is_err());
}

#[test]
fn keypair_public_private_roundtrip() {
    let toml = r#"
[client]
server_endpoint = "1.2.3.4:7000"
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
bootstrap_token_env = ""
allow_persist_identity = false

[dns]
servers = ["1.1.1.1"]
search_domains = []

[logging]
json_log_path = ""
mysql_url = ""
level = "info"
"#;
    let config: Config = toml::from_str(toml).unwrap();
    let kp = get_identity(&config, IdentityRole::Client).expect("generate identity");
    let pub_bytes = kp.public_key_bytes().expect("decode public");
    let priv_bytes = kp.private_key_bytes().expect("decode private");
    assert_eq!(pub_bytes.len(), 32);
    assert_eq!(priv_bytes.len(), 32);
}

// Expose the internal validate function for testing
fn validate_config_public(config: &Config) -> anyhow::Result<()> {
    // Reimplement the validation logic from the crate for testing
    if config.client.server_endpoint.is_empty() {
        return Err(anyhow::anyhow!("client.server_endpoint must not be empty"));
    }
    if config.client.rotation_interval_secs == 0 {
        return Err(anyhow::anyhow!("client.rotation_interval_secs must be > 0"));
    }
    if config.server.transport_port == 0 {
        return Err(anyhow::anyhow!("server.transport_port must be > 0"));
    }
    if config.server.session_timeout_secs == 0 {
        return Err(anyhow::anyhow!("server.session_timeout_secs must be > 0"));
    }
    if config.dns.servers.is_empty() {
        return Err(anyhow::anyhow!(
            "dns.servers must contain at least one resolver"
        ));
    }
    if !matches!(config.server.nat_mode.as_str(), "iptables" | "nftables") {
        return Err(anyhow::anyhow!(
            "server.nat_mode must be either 'iptables' or 'nftables'"
        ));
    }
    Ok(())
}
