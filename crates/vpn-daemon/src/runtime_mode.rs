// ═══════════════════════════════════════════════════════════════
// PART 3: Global Runtime Mode
// ═══════════════════════════════════════════════════════════════

use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    /// Full functionality: admin privileges available, all drivers present.
    /// WFP kill switch, Wintun adapter, full routing.
    Full,
    /// Limited mode: no admin privileges.
    /// UI and logs work, no WFP/Wintun, no TUN adapter creation.
    /// Existing tunnel can be used if pre-created.
    Limited,
    /// Safe mode: explicit --safe-mode flag. No OS-level interaction.
    /// All operations are simulated. For debugging/testing.
    Safe,
}

impl std::fmt::Display for RuntimeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeMode::Full => write!(f, "full"),
            RuntimeMode::Limited => write!(f, "limited"),
            RuntimeMode::Safe => write!(f, "safe"),
        }
    }
}

impl RuntimeMode {
    /// Detect the appropriate runtime mode based on environment.
    /// Takes into account: admin privileges, explicit --safe-mode flag, driver presence.
    pub fn detect(safe_mode: bool) -> Self {
        if safe_mode {
            info!("runtime_mode: safe mode requested via --safe-mode flag");
            return RuntimeMode::Safe;
        }

        #[cfg(windows)]
        {
            let is_admin = vpn_platform_windows::admin::is_admin();
            info!("runtime_mode: privilege check — is_admin={}", is_admin);

            if !is_admin {
                warn!(
                    "runtime_mode: non-admin detected — entering LIMITED mode. \
                     WFP kill switch and Wintun adapter creation are disabled. \
                     UI, logs, and IPC will function normally. \
                     Run as Administrator for full VPN functionality."
                );
                return RuntimeMode::Limited;
            }

            info!("runtime_mode: admin privileges confirmed — entering FULL mode");
            RuntimeMode::Full
        }

        #[cfg(not(windows))]
        {
            info!("runtime_mode: assuming FULL mode on non-Windows platform");
            RuntimeMode::Full
        }
    }

    pub fn is_full(&self) -> bool {
        matches!(self, RuntimeMode::Full)
    }

    pub fn is_limited(&self) -> bool {
        matches!(self, RuntimeMode::Limited)
    }

    pub fn is_safe(&self) -> bool {
        matches!(self, RuntimeMode::Safe)
    }

    /// Can we create a TUN adapter?
    pub fn can_create_tun(&self) -> bool {
        matches!(self, RuntimeMode::Full)
    }

    /// Can we install WFP kill switch filters?
    pub fn can_install_wfp(&self) -> bool {
        matches!(self, RuntimeMode::Full)
    }

    /// Should we simulate all operations?
    pub fn is_simulation(&self) -> bool {
        matches!(self, RuntimeMode::Safe)
    }
}
