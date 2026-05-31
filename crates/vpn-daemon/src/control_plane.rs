use crate::config::RunConfig;
use anyhow::{anyhow, Result};
use std::path::PathBuf;
use vpn_config::{
    decode_public_key_hex, get_identity, load_config, load_default_config, Config, IdentityRole,
    KeyPair,
};

#[derive(Clone, Debug)]
pub struct ResolvedRunSettings {
    pub server: String,
    pub trusted_server_public_key: Option<[u8; 32]>,
    pub bind: String,
    pub tun_name: String,
    pub tun_addr: String,
    pub mtu: u32,
    pub ipc_addr: String,
    pub log_file: Option<PathBuf>,
    pub mysql_url: Option<String>,
    pub kill_switch: bool,
    pub hops: usize,
    pub rotation_interval_secs: u64,
    pub admin_secret_env: Option<String>,
    pub identity: Option<KeyPair>,
    pub safe_mode: bool,
}

pub fn resolve_run_settings(run: &RunConfig) -> Result<ResolvedRunSettings> {
    if let Some(path) = &run.config_path {
        let config = load_config(path)?;
        let identity = Some(get_identity(&config, IdentityRole::Client)?);
        return from_config(run, &config, identity);
    }

    if let Ok(config) = load_default_config() {
        let identity = Some(get_identity(&config, IdentityRole::Client)?);
        return from_config(run, &config, identity);
    }

    if run.server.trim().is_empty() {
        return Err(anyhow!(
            "no control-plane config was found and --server was not provided"
        ));
    }

    Ok(ResolvedRunSettings {
        server: run.server.clone(),
        trusted_server_public_key: None,
        bind: run.bind.clone(),
        tun_name: run.tun_name.clone(),
        tun_addr: run.tun_addr.clone(),
        mtu: run.mtu,
        ipc_addr: run.ipc_addr.clone(),
        log_file: run.log_file.clone(),
        mysql_url: None,
        kill_switch: run.kill_switch,
        hops: run.hops,
        rotation_interval_secs: 300,
        admin_secret_env: run.admin_secret_env.clone(),
        identity: None,
        safe_mode: run.safe_mode,
    })
}

pub fn load_server_control_plane(path: Option<&PathBuf>) -> Result<(Config, KeyPair)> {
    let config = if let Some(path) = path {
        load_config(path)?
    } else {
        load_default_config()?
    };
    let identity = get_identity(&config, IdentityRole::Server)?;
    Ok((config, identity))
}

fn from_config(
    run: &RunConfig,
    config: &Config,
    identity: Option<KeyPair>,
) -> Result<ResolvedRunSettings> {
    let trusted_server_public_key = config
        .client
        .trusted_server_public_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(decode_public_key_hex)
        .transpose()?;

    Ok(ResolvedRunSettings {
        server: config.client.server_endpoint.clone(),
        trusted_server_public_key,
        bind: config.client.bind_address.clone(),
        tun_name: config.client.tun_name.clone(),
        tun_addr: config.client.tun_cidr.clone(),
        mtu: config.client.mtu,
        ipc_addr: run.ipc_addr.clone(),
        log_file: config
            .logging
            .json_log_path
            .as_ref()
            .map(PathBuf::from)
            .or_else(|| run.log_file.clone()),
        mysql_url: config
            .logging
            .mysql_url
            .as_ref()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        kill_switch: config.client.kill_switch,
        hops: run.hops,
        rotation_interval_secs: config.client.rotation_interval_secs,
        admin_secret_env: run.admin_secret_env.clone(),
        identity,
        safe_mode: run.safe_mode,
    })
}
