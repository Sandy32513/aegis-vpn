use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use vpn_daemon::{config::RunConfig, control_plane::resolve_run_settings};

fn temp_config_path() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "aegis-vpn-daemon-test-{}-{nanos}.toml",
        std::process::id()
    ))
}

fn temp_state_dir(suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "aegis-vpn-daemon-state-{suffix}-{}-{nanos}",
        std::process::id()
    ))
}

#[test]
fn resolve_run_settings_uses_config_without_cli_server_override() {
    let path = temp_config_path();
    let client_state_dir = temp_state_dir("client");
    let server_state_dir = temp_state_dir("server");
    let client_state = client_state_dir.to_string_lossy().replace('\\', "\\\\");
    let server_state = server_state_dir.to_string_lossy().replace('\\', "\\\\");

    let config = format!(
        r#"
[client]
server_endpoint = "127.0.0.1:7000"
trusted_server_public_key = "1111111111111111111111111111111111111111111111111111111111111111"
bind_address = "0.0.0.0:0"
tun_name = "aegis0"
tun_cidr = "10.20.0.2/24"
mtu = 1400
rotation_interval_secs = 300
kill_switch = true
config_identity_dir = "{client_state}"

[server]
listen_address = "0.0.0.0:7000"
transport_port = 7000
tun_name = "aegis-srv0"
tun_cidr = "10.20.0.1/24"
client_pool_cidr = "10.20.0.0/24"
egress_interface = "eth0"
nat_mode = "iptables"
session_timeout_secs = 300
config_identity_dir = "{server_state}"

[control_plane]
node_id = "edge-01"
allow_persist_identity = true

[dns]
servers = ["1.1.1.1"]
search_domains = []

[logging]
json_log_path = "logs/test.jsonl"
mysql_url = ""
level = "info"
"#
    );
    fs::write(&path, config).expect("write config");

    let settings = resolve_run_settings(&RunConfig {
        config_path: Some(path.clone()),
        server: String::new(),
        bind: "0.0.0.0:0".to_string(),
        tun_name: "ignored".to_string(),
        tun_addr: "10.99.0.2/24".to_string(),
        mtu: 1300,
        ipc_addr: "127.0.0.1:7788".to_string(),
        log_file: None,
        kill_switch: false,
        hops: 3,
        admin_secret_env: Some("AEGIS_ADMIN_SECRET".to_string()),
        safe_mode: false,
    })
    .expect("resolve config-backed settings");

    assert_eq!(settings.server, "127.0.0.1:7000");
    assert!(settings.trusted_server_public_key.is_some());
    assert_eq!(settings.rotation_interval_secs, 300);
    assert_eq!(
        settings
            .log_file
            .as_ref()
            .map(|p| p.to_string_lossy().to_string()),
        Some("logs/test.jsonl".to_string())
    );

    let _ = fs::remove_file(path);
    let _ = fs::remove_dir_all(client_state_dir);
    let _ = fs::remove_dir_all(server_state_dir);
}
