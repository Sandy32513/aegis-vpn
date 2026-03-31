#[cfg(target_os = "linux")]
use anyhow::{anyhow, Result};
#[cfg(target_os = "linux")]
use std::{process::Command, str::FromStr};
#[cfg(target_os = "linux")]
use vpn_tun::{TunConfig, TunDevice};

#[cfg(target_os = "linux")]
#[derive(Clone, Debug)]
pub struct ServerNatConfig {
    pub tun_name: String,
    pub tun_cidr: String,
    pub client_pool_cidr: String,
    pub egress_interface: String,
    pub nat_mode: String,
}

#[cfg(target_os = "linux")]
pub fn setup_server_network(config: &ServerNatConfig) -> Result<Box<dyn TunDevice>> {
    validate_client_pool(&config.client_pool_cidr)?;
    let tun_config = TunConfig {
        name: config.tun_name.clone(),
        address_cidr: config.tun_cidr.clone(),
        mtu: 1400,
    };

    let tun = crate::create_tun(&tun_config)?;
    let actual_name = tun.name().to_string();
    let actual_config = TunConfig {
        name: actual_name.clone(),
        address_cidr: config.tun_cidr.clone(),
        mtu: tun.mtu(),
    };

    crate::configure_interface(&actual_config)?;
    enable_ip_forwarding()?;
    let actual_nat_config = ServerNatConfig {
        tun_name: actual_name,
        tun_cidr: config.tun_cidr.clone(),
        client_pool_cidr: config.client_pool_cidr.clone(),
        egress_interface: config.egress_interface.clone(),
        nat_mode: config.nat_mode.clone(),
    };
    enable_nat(&actual_nat_config)?;
    Ok(Box::new(tun))
}

#[cfg(target_os = "linux")]
pub fn enable_ip_forwarding() -> Result<()> {
    run("sysctl", &["-w", "net.ipv4.ip_forward=1"])
}

#[cfg(target_os = "linux")]
pub fn enable_nat(config: &ServerNatConfig) -> Result<()> {
    let _ = disable_nat(config);
    match config.nat_mode.as_str() {
        "iptables" => {
            run(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-A",
                    "POSTROUTING",
                    "-s",
                    &config.client_pool_cidr,
                    "-o",
                    &config.egress_interface,
                    "-j",
                    "MASQUERADE",
                ],
            )?;
            run(
                "iptables",
                &[
                    "-A",
                    "FORWARD",
                    "-i",
                    &config.tun_name,
                    "-o",
                    &config.egress_interface,
                    "-j",
                    "ACCEPT",
                ],
            )?;
            run(
                "iptables",
                &[
                    "-A",
                    "FORWARD",
                    "-i",
                    &config.egress_interface,
                    "-o",
                    &config.tun_name,
                    "-m",
                    "state",
                    "--state",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ],
            )?;
        }
        "nftables" => {
            let _ = disable_nat(config);
            run("nft", &["add", "table", "inet", "aegis_vpn_srv"])?;
            run(
                "nft",
                &[
                    "add",
                    "chain",
                    "inet",
                    "aegis_vpn_srv",
                    "forward",
                    "{",
                    "type",
                    "filter",
                    "hook",
                    "forward",
                    "priority",
                    "0",
                    ";",
                    "policy",
                    "drop",
                    ";",
                    "}",
                ],
            )?;
            run("nft", &["add", "table", "ip", "aegis_vpn_srv_ip"])?;
            run(
                "nft",
                &[
                    "add",
                    "chain",
                    "ip",
                    "aegis_vpn_srv_ip",
                    "postrouting",
                    "{",
                    "type",
                    "nat",
                    "hook",
                    "postrouting",
                    "priority",
                    "100",
                    ";",
                    "}",
                ],
            )?;
            run(
                "nft",
                &[
                    "add",
                    "rule",
                    "inet",
                    "aegis_vpn_srv",
                    "forward",
                    "iifname",
                    &config.tun_name,
                    "oifname",
                    &config.egress_interface,
                    "accept",
                ],
            )?;
            run(
                "nft",
                &[
                    "add",
                    "rule",
                    "inet",
                    "aegis_vpn_srv",
                    "forward",
                    "iifname",
                    &config.egress_interface,
                    "oifname",
                    &config.tun_name,
                    "ct",
                    "state",
                    "established,related",
                    "accept",
                ],
            )?;
            run(
                "nft",
                &[
                    "add",
                    "rule",
                    "ip",
                    "aegis_vpn_srv_ip",
                    "postrouting",
                    "ip",
                    "saddr",
                    &config.client_pool_cidr,
                    "oifname",
                    &config.egress_interface,
                    "masquerade",
                ],
            )?;
        }
        other => return Err(anyhow!("unsupported NAT mode {other}")),
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn disable_nat(config: &ServerNatConfig) -> Result<()> {
    match config.nat_mode.as_str() {
        "iptables" => {
            let _ = run(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-D",
                    "POSTROUTING",
                    "-s",
                    &config.client_pool_cidr,
                    "-o",
                    &config.egress_interface,
                    "-j",
                    "MASQUERADE",
                ],
            );
            let _ = run(
                "iptables",
                &[
                    "-D",
                    "FORWARD",
                    "-i",
                    &config.tun_name,
                    "-o",
                    &config.egress_interface,
                    "-j",
                    "ACCEPT",
                ],
            );
            let _ = run(
                "iptables",
                &[
                    "-D",
                    "FORWARD",
                    "-i",
                    &config.egress_interface,
                    "-o",
                    &config.tun_name,
                    "-m",
                    "state",
                    "--state",
                    "RELATED,ESTABLISHED",
                    "-j",
                    "ACCEPT",
                ],
            );
        }
        "nftables" => {
            let _ = run("nft", &["delete", "table", "inet", "aegis_vpn_srv"]);
            let _ = run("nft", &["delete", "table", "ip", "aegis_vpn_srv_ip"]);
        }
        _ => {}
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn validate_client_pool(cidr: &str) -> Result<()> {
    let _ = ipnet::Ipv4Net::from_str(cidr)
        .map_err(|e| anyhow!("invalid client pool CIDR {cidr}: {e}"))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn run(program: &str, args: &[&str]) -> Result<()> {
    let status = Command::new(program).args(args).status()?;
    if !status.success() {
        return Err(anyhow!("{program} {:?} failed with status {status}", args));
    }
    Ok(())
}
