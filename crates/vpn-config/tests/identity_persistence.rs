use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use vpn_config::{
    get_identity, ClientConfig, Config, ControlPlaneConfig, DnsConfig, IdentityRole, LoggingConfig,
    ServerConfig,
};

fn temp_identity_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "aegis-vpn-config-test-{}-{nanos}",
        std::process::id()
    ))
}

#[test]
fn get_identity_persists_and_reloads_same_keypair() {
    let identity_root = temp_identity_dir();
    let config = Config {
        client: ClientConfig {
            server_endpoint: "127.0.0.1:7000".to_string(),
            trusted_server_public_key: None,
            bind_address: "0.0.0.0:0".to_string(),
            tun_name: "aegis0".to_string(),
            tun_cidr: "10.20.0.2/24".to_string(),
            mtu: 1400,
            rotation_interval_secs: 300,
            kill_switch: true,
            config_identity_dir: identity_root.to_string_lossy().to_string(),
        },
        server: ServerConfig {
            listen_address: "0.0.0.0:7000".to_string(),
            transport_port: 7000,
            tun_name: "aegis-srv0".to_string(),
            tun_cidr: "10.20.0.1/24".to_string(),
            client_pool_cidr: "10.20.0.0/24".to_string(),
            egress_interface: "eth0".to_string(),
            nat_mode: "iptables".to_string(),
            session_timeout_secs: 300,
            config_identity_dir: identity_root.to_string_lossy().to_string(),
        },
        control_plane: ControlPlaneConfig {
            node_id: "edge-01".to_string(),
            bootstrap_token_env: None,
            allow_persist_identity: true,
        },
        dns: DnsConfig {
            servers: vec!["1.1.1.1".to_string()],
            search_domains: Vec::new(),
        },
        logging: LoggingConfig {
            json_log_path: None,
            mysql_url: None,
            level: "info".to_string(),
        },
    };

    let first =
        get_identity(&config, IdentityRole::Client).expect("create initial client identity");
    let second = get_identity(&config, IdentityRole::Client).expect("reload client identity");

    assert_eq!(first.public_key_hex, second.public_key_hex);
    assert_eq!(first.private_key_hex, second.private_key_hex);
    assert_eq!(first.fingerprint, second.fingerprint);

    let _ = fs::remove_dir_all(identity_root);
}
