// ═══════════════════════════════════════════════════════════════
// PART 6: Unified Cleanup Manager with Cleanable trait
// ═══════════════════════════════════════════════════════════════

use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{error, info, trace, warn};

/// All managed resources must implement Cleanable.
/// Resources are cleaned up in the order they were registered,
/// but cleanup does NOT depend on order — each resource handles its own state.
pub trait Cleanable: Send + Sync {
    fn name(&self) -> &str;
    fn cleanup(&self) -> Result<(), String>;
}

/// Manages a collection of resources that need cleanup.
/// Cleanup runs exactly once via AtomicBool guard.
/// Safe under partial initialization, crashes, and repeated calls.
pub struct CleanupManager {
    resources: Vec<Box<dyn Cleanable>>,
    cleaned: AtomicBool,
}

impl CleanupManager {
    pub fn new() -> Self {
        Self {
            resources: Vec::new(),
            cleaned: AtomicBool::new(false),
        }
    }

    /// Register a resource for cleanup.
    pub fn register(&mut self, resource: Box<dyn Cleanable>) {
        trace!("cleanup_manager: registered '{}'", resource.name());
        self.resources.push(resource);
    }

    /// Run cleanup on all registered resources exactly once.
    /// Returns a summary of errors (empty = success).
    pub fn cleanup_all(&self) -> Vec<String> {
        // CAS: only the first caller enters the body
        if self
            .cleaned
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            trace!("cleanup_manager: already cleaned (idempotent skip)");
            return Vec::new();
        }

        info!(
            "cleanup_manager: cleaning up {} resources",
            self.resources.len()
        );

        let mut errors = Vec::new();

        for resource in &self.resources {
            trace!("cleanup_manager: cleaning '{}'", resource.name());
            match resource.cleanup() {
                Ok(()) => {
                    info!(
                        "cleanup_manager: '{}' cleaned successfully",
                        resource.name()
                    );
                }
                Err(e) => {
                    warn!(
                        "cleanup_manager: '{}' cleanup failed: {}",
                        resource.name(),
                        e
                    );
                    errors.push(format!("{}: {}", resource.name(), e));
                }
            }
        }

        if errors.is_empty() {
            info!("cleanup_manager: all resources cleaned successfully");
        } else {
            error!(
                "cleanup_manager: completed with {}/{} errors",
                errors.len(),
                self.resources.len()
            );
        }

        errors
    }

    /// Check if cleanup has already been performed.
    pub fn is_cleaned(&self) -> bool {
        self.cleaned.load(Ordering::SeqCst)
    }

    /// Number of registered resources.
    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }
}

impl Default for CleanupManager {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────
// Built-in Cleanable implementations
// ──────────────────────────────────────────────────────────────

/// Cleanup a WFP kill switch.
pub struct WfpCleanup {
    label: String,
}

impl WfpCleanup {
    pub fn new() -> Self {
        Self {
            label: "wfp-kill-switch".to_string(),
        }
    }
}

impl Cleanable for WfpCleanup {
    fn name(&self) -> &str {
        &self.label
    }

    fn cleanup(&self) -> Result<(), String> {
        #[cfg(windows)]
        {
            match vpn_platform_windows::disable_kill_switch() {
                Ok(()) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
    }
}

/// Cleanup a TUN adapter by name.
pub struct TunCleanup {
    label: String,
    tun_name: String,
}

impl TunCleanup {
    pub fn new(tun_name: &str) -> Self {
        Self {
            label: format!("tun-{}", tun_name),
            tun_name: tun_name.to_string(),
        }
    }
}

impl Cleanable for TunCleanup {
    fn name(&self) -> &str {
        &self.label
    }

    fn cleanup(&self) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("ip")
                .args(["link", "set", &self.tun_name, "down"])
                .status();
            match std::process::Command::new("ip")
                .args(["link", "del", &self.tun_name])
                .status()
            {
                Ok(s) if s.success() => Ok(()),
                Ok(_) => Err(format!("failed to delete TUN '{}'", self.tun_name)),
                Err(e) => Err(format!("ip link del error: {e}")),
            }
        }
        #[cfg(windows)]
        {
            // Wintun adapter is cleaned by Drop — just log
            trace!(
                "tun_cleanup: Wintun adapter '{}' will be cleaned by RAII Drop",
                self.tun_name
            );
            Ok(())
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            Ok(())
        }
    }
}

/// Cleanup network routes.
pub struct RouteCleanup {
    label: String,
    tun_name: String,
}

impl RouteCleanup {
    pub fn new(tun_name: &str) -> Self {
        Self {
            label: format!("routes-{}", tun_name),
            tun_name: tun_name.to_string(),
        }
    }
}

impl Cleanable for RouteCleanup {
    fn name(&self) -> &str {
        &self.label
    }

    fn cleanup(&self) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let _ = std::process::Command::new("ip")
                .args(["route", "del", "default"])
                .status();
            Ok(())
        }
        #[cfg(windows)]
        {
            match vpn_platform_windows::cleanup_routes(&self.tun_name) {
                Ok(()) => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            Ok(())
        }
    }
}
