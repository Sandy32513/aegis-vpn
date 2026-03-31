#[cfg(target_os = "linux")]
mod imp {
    use anyhow::{anyhow, Result};
    use libc::{c_char, c_short, c_ulong, IFNAMSIZ};
    use std::{
        fs::OpenOptions,
        io::{Read, Write},
        net::IpAddr,
        os::fd::AsRawFd,
        process::Command,
    };
    use tracing::warn;
    use vpn_tun::{TunConfig, TunDevice};

    const TUNSETIFF: c_ulong = 0x400454ca;
    const IFF_TUN: c_short = 0x0001;
    const IFF_NO_PI: c_short = 0x1000;

    #[repr(C)]
    struct IfReq {
        ifr_name: [c_char; IFNAMSIZ],
        ifr_flags: c_short,
        ifr_pad: [u8; 24],
    }

    pub struct LinuxTun {
        file: std::fs::File,
        name: String,
        mtu: u32,
    }

    #[derive(Clone, Debug)]
    pub struct DefaultRoute {
        pub gateway: String,
        pub interface: String,
    }

    #[derive(Clone, Debug)]
    pub struct KillSwitchConfig {
        pub tun_name: String,
        pub server_ip: IpAddr,
        pub server_port: u16,
        pub protocol: String,
    }

    impl TunDevice for LinuxTun {
        fn name(&self) -> &str {
            &self.name
        }

        fn mtu(&self) -> u32 {
            self.mtu
        }

        fn read_packet(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.file.read(buf)
        }

        fn write_packet(&mut self, packet: &[u8]) -> std::io::Result<()> {
            self.file.write_all(packet)
        }
    }

    pub fn create_tun(config: &TunConfig) -> Result<LinuxTun> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        let mut ifreq = IfReq {
            ifr_name: [0; IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            ifr_pad: [0; 24],
        };

        for (idx, byte) in config.name.as_bytes().iter().take(IFNAMSIZ - 1).enumerate() {
            ifreq.ifr_name[idx] = *byte as c_char;
        }

        let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &ifreq) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let set_rc =
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if set_rc < 0 {
            return Err(std::io::Error::last_os_error().into());
        }

        let actual_name = decode_ifname(&ifreq.ifr_name);
        Ok(LinuxTun {
            file,
            name: actual_name,
            mtu: config.mtu,
        })
    }

    pub fn configure_interface(config: &TunConfig) -> Result<()> {
        run(
            "ip",
            &[
                "link",
                "set",
                "dev",
                &config.name,
                "mtu",
                &config.mtu.to_string(),
            ],
        )?;
        run(
            "ip",
            &["addr", "replace", &config.address_cidr, "dev", &config.name],
        )?;
        run("ip", &["link", "set", "dev", &config.name, "up"])?;
        Ok(())
    }

    pub fn discover_default_route() -> Result<DefaultRoute> {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()?;

        if !output.status.success() {
            return Err(anyhow!("failed to query default route"));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let tokens: Vec<&str> = stdout.split_whitespace().collect();
        let gateway = tokens
            .windows(2)
            .find(|pair| pair[0] == "via")
            .map(|pair| pair[1].to_string())
            .ok_or_else(|| anyhow!("could not determine default gateway"))?;
        let interface = tokens
            .windows(2)
            .find(|pair| pair[0] == "dev")
            .map(|pair| pair[1].to_string())
            .ok_or_else(|| anyhow!("could not determine default interface"))?;

        Ok(DefaultRoute { gateway, interface })
    }

    pub fn route_server_via_physical(server_ip: IpAddr, route: &DefaultRoute) -> Result<()> {
        let prefix = match server_ip {
            IpAddr::V4(addr) => format!("{addr}/32"),
            IpAddr::V6(addr) => format!("{addr}/128"),
        };

        run(
            "ip",
            &[
                "route",
                "replace",
                &prefix,
                "via",
                &route.gateway,
                "dev",
                &route.interface,
            ],
        )
    }

    pub fn route_default_via_tun(tun_name: &str) -> Result<()> {
        run("ip", &["route", "replace", "default", "dev", tun_name])
    }

    pub fn enable_kill_switch(config: &KillSwitchConfig) -> Result<()> {
        let _ = disable_kill_switch();
        run("nft", &["add", "table", "inet", "aegis_vpn"])?;
        run(
            "nft",
            &[
                "add",
                "chain",
                "inet",
                "aegis_vpn",
                "output",
                "{",
                "type",
                "filter",
                "hook",
                "output",
                "priority",
                "0",
                ";",
                "policy",
                "drop",
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
                "aegis_vpn",
                "output",
                "oifname",
                "lo",
                "accept",
            ],
        )?;
        run(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                "aegis_vpn",
                "output",
                "oifname",
                &config.tun_name,
                "accept",
            ],
        )?;
        run(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                "aegis_vpn",
                "output",
                "ip",
                "daddr",
                &config.server_ip.to_string(),
                &config.protocol,
                "dport",
                &config.server_port.to_string(),
                "accept",
            ],
        )?;
        run(
            "nft",
            &[
                "add",
                "rule",
                "inet",
                "aegis_vpn",
                "output",
                "ct",
                "state",
                "established,related",
                "accept",
            ],
        )?;
        Ok(())
    }

    pub fn disable_kill_switch() -> Result<()> {
        let status = Command::new("nft")
            .args(["delete", "table", "inet", "aegis_vpn"])
            .status()?;
        if !status.success() {
            warn!("linux kill switch table was not present");
        }
        Ok(())
    }

    fn decode_ifname(raw: &[c_char; IFNAMSIZ]) -> String {
        let bytes: Vec<u8> = raw
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8)
            .collect();
        String::from_utf8_lossy(&bytes).to_string()
    }

    fn run(program: &str, args: &[&str]) -> Result<()> {
        let status = Command::new(program).args(args).status()?;
        if !status.success() {
            return Err(anyhow!("{program} {:?} failed with status {status}", args));
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use anyhow::{anyhow, Result};
    use std::net::IpAddr;
    use vpn_tun::TunConfig;

    #[derive(Clone, Debug)]
    pub struct DefaultRoute {
        pub gateway: String,
        pub interface: String,
    }

    #[derive(Clone, Debug)]
    pub struct KillSwitchConfig {
        pub tun_name: String,
        pub server_ip: IpAddr,
        pub server_port: u16,
        pub protocol: String,
    }

    pub fn create_tun(_: &TunConfig) -> Result<()> {
        Err(anyhow!("linux platform support is only available on Linux"))
    }

    pub fn configure_interface(_: &TunConfig) -> Result<()> {
        Err(anyhow!("linux platform support is only available on Linux"))
    }

    pub fn discover_default_route() -> Result<DefaultRoute> {
        Err(anyhow!("linux platform support is only available on Linux"))
    }

    pub fn route_server_via_physical(_: IpAddr, _: &DefaultRoute) -> Result<()> {
        Err(anyhow!("linux platform support is only available on Linux"))
    }

    pub fn route_default_via_tun(_: &str) -> Result<()> {
        Err(anyhow!("linux platform support is only available on Linux"))
    }

    pub fn enable_kill_switch(_: &KillSwitchConfig) -> Result<()> {
        Err(anyhow!("linux platform support is only available on Linux"))
    }

    pub fn disable_kill_switch() -> Result<()> {
        Err(anyhow!("linux platform support is only available on Linux"))
    }
}

#[cfg(target_os = "linux")]
pub mod server_nat;

pub use imp::*;
