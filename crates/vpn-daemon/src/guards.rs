// ═══════════════════════════════════════════════════════════════
// PART 2: RAII Resource Guards
// ═══════════════════════════════════════════════════════════════
//
// Every resource has a dedicated guard struct implementing Drop.
// Drop is guaranteed to run on scope exit, task cancellation, or panic.
// Guards are designed to be idempotent — dropping twice is safe.

use tracing::{info, trace, warn};

// ──────────────────────────────────────────────────────────────
// Route Guard (Linux)
// ──────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub struct LinuxRouteGuard {
    prefix: String,
    via: Option<String>,
    dev: Option<String>,
    alive: bool,
}

#[cfg(target_os = "linux")]
impl LinuxRouteGuard {
    /// Track a route that was added via `ip route replace ...`.
    pub fn new(prefix: &str, via: Option<&str>, dev: Option<&str>) -> Self {
        Self {
            prefix: prefix.to_string(),
            via: via.map(|s| s.to_string()),
            dev: dev.map(|s| s.to_string()),
            alive: true,
        }
    }

    /// Explicitly remove the route (called before Drop for ordered teardown).
    pub fn remove(&mut self) {
        if !self.alive {
            return;
        }
        self.alive = false;

        let mut cmd = std::process::Command::new("ip");
        cmd.args(["route", "del", &self.prefix]);
        if let Some(ref via) = self.via {
            cmd.args(["via", via]);
        }
        if let Some(ref dev) = self.dev {
            cmd.args(["dev", dev]);
        }

        match cmd.status() {
            Ok(s) if s.success() => info!("route guard: removed {}", self.prefix),
            Ok(_) => warn!("route guard: remove failed for {}", self.prefix),
            Err(e) => warn!("route guard: remove error for {}: {e}", self.prefix),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxRouteGuard {
    fn drop(&mut self) {
        self.remove();
    }
}

// ──────────────────────────────────────────────────────────────
// nftables Table Guard (Linux)
// ──────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub struct NftablesTableGuard {
    family: String,
    name: String,
    alive: bool,
}

#[cfg(target_os = "linux")]
impl NftablesTableGuard {
    pub fn new(family: &str, name: &str) -> Self {
        Self {
            family: family.to_string(),
            name: name.to_string(),
            alive: true,
        }
    }

    pub fn remove(&mut self) {
        if !self.alive {
            return;
        }
        self.alive = false;

        let status = std::process::Command::new("nft")
            .args(["delete", "table", &self.family, &self.name])
            .status();
        match status {
            Ok(s) if s.success() => info!("nft guard: removed table {}/{}", self.family, self.name),
            Ok(_) => warn!("nft guard: remove failed for {}/{}", self.family, self.name),
            Err(e) => warn!(
                "nft guard: remove error for {}/{}: {e}",
                self.family, self.name
            ),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for NftablesTableGuard {
    fn drop(&mut self) {
        self.remove();
    }
}

// ──────────────────────────────────────────────────────────────
// TUN Device Guard (Linux)
// ──────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub struct TunDeviceGuard {
    name: String,
    alive: bool,
}

#[cfg(target_os = "linux")]
impl TunDeviceGuard {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            alive: true,
        }
    }

    pub fn remove(&mut self) {
        if !self.alive {
            return;
        }
        self.alive = false;

        // Bring interface down, then delete
        let _ = std::process::Command::new("ip")
            .args(["link", "set", &self.name, "down"])
            .status();
        let status = std::process::Command::new("ip")
            .args(["link", "del", &self.name])
            .status();
        match status {
            Ok(s) if s.success() => info!("tun guard: removed interface '{}'", self.name),
            Ok(_) => warn!("tun guard: remove failed for '{}'", self.name),
            Err(e) => warn!("tun guard: remove error for '{}': {e}", self.name),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for TunDeviceGuard {
    fn drop(&mut self) {
        self.remove();
    }
}

// ──────────────────────────────────────────────────────────────
// WFP Filter Guard (Windows) — delegates to existing cleanup
// ──────────────────────────────────────────────────────────────

#[cfg(windows)]
pub struct WfpCleanupGuard {
    tun_name: String,
    kill_switch: bool,
    alive: bool,
}

#[cfg(windows)]
impl WfpCleanupGuard {
    pub fn new(tun_name: &str, kill_switch: bool) -> Self {
        Self {
            tun_name: tun_name.to_string(),
            kill_switch,
            alive: true,
        }
    }

    pub fn cleanup(&mut self) {
        if !self.alive {
            return;
        }
        self.alive = false;

        if self.kill_switch {
            if let Err(e) = vpn_platform_windows::full_teardown(&self.tun_name) {
                warn!("wfp guard: teardown warning: {e}");
            } else {
                info!("wfp guard: full teardown complete for '{}'", self.tun_name);
            }
        } else {
            if let Err(e) = vpn_platform_windows::cleanup_routes(&self.tun_name) {
                warn!("wfp guard: route cleanup warning: {e}");
            }
        }
    }
}

#[cfg(windows)]
impl Drop for WfpCleanupGuard {
    fn drop(&mut self) {
        self.cleanup();
    }
}

// ──────────────────────────────────────────────────────────────
// Generic Platform Cleanup Guard (cross-platform wrapper)
// ──────────────────────────────────────────────────────────────

/// Composite guard that cleans up all platform-specific resources.
/// Creates the appropriate platform guards at construction time.
pub struct PlatformCleanupGuard {
    #[cfg(target_os = "linux")]
    kill_switch_table: Option<NftablesTableGuard>,
    #[cfg(target_os = "linux")]
    default_route: Option<LinuxRouteGuard>,
    #[cfg(target_os = "linux")]
    server_route: Option<LinuxRouteGuard>,
    #[cfg(target_os = "linux")]
    tun_device: Option<TunDeviceGuard>,

    #[cfg(windows)]
    wfp_guard: Option<WfpCleanupGuard>,

    tun_name: String,
}

impl PlatformCleanupGuard {
    /// Create a new guard. Call this AFTER resources are created.
    #[cfg(target_os = "linux")]
    pub fn new(tun_name: &str, server_ip: std::net::IpAddr, _kill_switch: bool) -> Self {
        Self {
            kill_switch_table: Some(NftablesTableGuard::new("inet", "aegis_vpn")),
            default_route: Some(LinuxRouteGuard::new("default", None, Some(tun_name))),
            server_route: Some(LinuxRouteGuard::new(&format!("{server_ip}/32"), None, None)),
            tun_device: Some(TunDeviceGuard::new(tun_name)),
            tun_name: tun_name.to_string(),
        }
    }

    #[cfg(windows)]
    pub fn new(tun_name: &str, _server_ip: std::net::IpAddr, kill_switch: bool) -> Self {
        Self {
            wfp_guard: Some(WfpCleanupGuard::new(tun_name, kill_switch)),
            tun_name: tun_name.to_string(),
        }
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    pub fn new(tun_name: &str, _server_ip: std::net::IpAddr, _kill_switch: bool) -> Self {
        Self {
            tun_name: tun_name.to_string(),
        }
    }

    /// Explicitly clean up all resources in reverse order.
    /// Called before Drop for ordered teardown.
    pub fn cleanup_all(&mut self) {
        info!(
            "platform guard: cleaning up all resources for '{}'",
            self.tun_name
        );

        #[cfg(target_os = "linux")]
        {
            // Reverse order: routes first, then nft, then TUN
            if let Some(ref mut g) = self.default_route {
                g.remove();
            }
            if let Some(ref mut g) = self.server_route {
                g.remove();
            }
            if let Some(ref mut g) = self.kill_switch_table {
                g.remove();
            }
            if let Some(ref mut g) = self.tun_device {
                g.remove();
            }
        }

        #[cfg(windows)]
        {
            if let Some(ref mut g) = self.wfp_guard {
                g.cleanup();
            }
        }
    }
}

impl Drop for PlatformCleanupGuard {
    fn drop(&mut self) {
        self.cleanup_all();
    }
}

// ──────────────────────────────────────────────────────────────
// Key Material Guard (cross-platform)
// ──────────────────────────────────────────────────────────────

/// Zeroizes sensitive key material on drop.
pub struct KeyMaterialGuard<T: Zeroize> {
    material: Option<T>,
}

pub trait Zeroize {
    fn zeroize(&mut self);
}

impl Zeroize for [u8; 32] {
    fn zeroize(&mut self) {
        for byte in self.iter_mut() {
            *byte = 0;
        }
    }
}

impl<T: Zeroize> KeyMaterialGuard<T> {
    pub fn new(material: T) -> Self {
        Self {
            material: Some(material),
        }
    }

    pub fn get(&self) -> Option<&T> {
        self.material.as_ref()
    }
}

impl<T: Zeroize> Drop for KeyMaterialGuard<T> {
    fn drop(&mut self) {
        if let Some(ref mut m) = self.material {
            m.zeroize();
            trace!("key guard: material zeroized");
        }
    }
}
