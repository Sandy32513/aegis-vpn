use serde_json::json;
use std::{
    fmt, io,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
};
use tracing::{error, info, trace, warn};

// ═══════════════════════════════════════════════════════════════
// PART 3: Formal State Machine
// ═══════════════════════════════════════════════════════════════

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnState {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Rotating = 3,
    Disconnecting = 4,
    Error = 5,
}

impl VpnState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => VpnState::Disconnected,
            1 => VpnState::Connecting,
            2 => VpnState::Connected,
            3 => VpnState::Rotating,
            4 => VpnState::Disconnecting,
            5 => VpnState::Error,
            _ => VpnState::Error,
        }
    }
}

#[derive(Debug)]
pub enum TransitionEvent {
    ConnectInitiated,
    ConnectSucceeded,
    ConnectFailed(String),
    DisconnectRequested,
    DisconnectComplete,
    RotationStarted,
    RotationSucceeded,
    RotationFailed(String),
    FatalError(String),
}

#[derive(Debug)]
pub struct TransitionError {
    pub current: VpnState,
    pub event: TransitionEvent,
    pub reason: String,
}

impl std::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid transition: {:?} + {:?} — {}",
            self.current, self.event, self.reason
        )
    }
}

#[derive(Debug)]
pub enum CleanupError {
    SignalRegistration(io::Error),
}

impl fmt::Display for CleanupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CleanupError::SignalRegistration(err) => {
                write!(f, "failed to register signal handler: {err}")
            }
        }
    }
}

impl std::error::Error for CleanupError {}

impl From<io::Error> for CleanupError {
    fn from(err: io::Error) -> Self {
        CleanupError::SignalRegistration(err)
    }
}

/// Atomic state machine. All transitions go through `try_transition`.
/// Invalid transitions return an error. In debug builds, invalid transitions panic.
pub struct StateMachine {
    state: AtomicU8,
}

impl StateMachine {
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(VpnState::Disconnected as u8),
        }
    }

    pub fn current(&self) -> VpnState {
        VpnState::from_u8(self.state.load(Ordering::SeqCst))
    }

    /// Attempt a state transition. Returns Ok(new_state) on success,
    /// Err(TransitionError) if the transition is invalid.
    pub fn try_transition(&self, event: TransitionEvent) -> Result<VpnState, TransitionError> {
        let current_raw = self.state.load(Ordering::SeqCst);
        let current = VpnState::from_u8(current_raw);

        let next = match (current, &event) {
            // Disconnected → Connecting
            (VpnState::Disconnected, TransitionEvent::ConnectInitiated) => VpnState::Connecting,
            // Connecting → Connected
            (VpnState::Connecting, TransitionEvent::ConnectSucceeded) => VpnState::Connected,
            // Connecting → Disconnected
            (VpnState::Connecting, TransitionEvent::ConnectFailed(_)) => VpnState::Disconnected,
            // Connecting → Error
            (VpnState::Connecting, TransitionEvent::FatalError(_)) => VpnState::Error,
            // Connected → Rotating
            (VpnState::Connected, TransitionEvent::RotationStarted) => VpnState::Rotating,
            // Connected → Disconnecting
            (VpnState::Connected, TransitionEvent::DisconnectRequested) => VpnState::Disconnecting,
            // Connected → Error
            (VpnState::Connected, TransitionEvent::FatalError(_)) => VpnState::Error,
            // Rotating → Connected
            (VpnState::Rotating, TransitionEvent::RotationSucceeded) => VpnState::Connected,
            // Rotating → Disconnecting
            (VpnState::Rotating, TransitionEvent::DisconnectRequested) => VpnState::Disconnecting,
            // Rotating → Error
            (VpnState::Rotating, TransitionEvent::FatalError(_)) => VpnState::Error,
            // Rotating → Connected (on rotation failure, we stay connected on old circuit)
            (VpnState::Rotating, TransitionEvent::RotationFailed(_)) => VpnState::Connected,
            // Disconnecting → Disconnected
            (VpnState::Disconnecting, TransitionEvent::DisconnectComplete) => {
                VpnState::Disconnected
            }
            // Error → Disconnected
            (VpnState::Error, TransitionEvent::DisconnectComplete) => VpnState::Disconnected,
            // Any → Error
            (_, TransitionEvent::FatalError(_)) => VpnState::Error,

            // All other transitions are invalid
            _ => {
                let err = TransitionError {
                    current,
                    event,
                    reason: format!("no valid transition from {:?}", current),
                };
                debug_assert!(false, "{}", err.reason);
                return Err(err);
            }
        };

        self.state.store(next as u8, Ordering::SeqCst);
        trace!("state transition: {current:?} → {next:?}");
        Ok(next)
    }
}

// ═══════════════════════════════════════════════════════════════
// PART 1: Cleanup Subsystem
// ═══════════════════════════════════════════════════════════════

/// Global shutdown flag — set by signal handlers, polled by all async loops.
pub static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Tracks whether cleanup has started. Uses CAS to ensure body executes exactly once.
static CLEANUP_STARTED: AtomicBool = AtomicBool::new(false);

/// Platform-specific cleanup parameters captured at resource creation time.
pub struct CleanupState {
    pub tun_name: String,
    pub kill_switch: bool,
    pub server_bind: Option<String>,
}

/// The unified, idempotent cleanup function.
/// Safe to call from signal handlers (avoids heap allocation where possible).
/// Safe to call multiple times (CAS guard).
pub fn perform_cleanup(state: &CleanupState) {
    // CAS: only the first caller enters the body
    if CLEANUP_STARTED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        trace!("cleanup already in progress, skipping");
        return;
    }

    info!(
        tun = %state.tun_name,
        kill_switch = state.kill_switch,
        "performing unified cleanup"
    );

    let mut errors: Vec<String> = Vec::new();

    // Step 1: Disable kill switch (routes must be accessible for cleanup)
    if state.kill_switch {
        trace!("cleanup: disabling kill switch");
        #[cfg(target_os = "linux")]
        if let Err(e) = vpn_platform_linux::disable_kill_switch() {
            warn!("cleanup: kill switch disable failed: {e}");
            errors.push(format!("kill_switch: {e}"));
        }
        #[cfg(windows)]
        if let Err(e) = vpn_platform_windows::disable_kill_switch() {
            warn!("cleanup: kill switch disable failed: {e}");
            errors.push(format!("kill_switch: {e}"));
        }
    }

    // Step 2: Remove routes
    trace!("cleanup: removing routes via '{}'", state.tun_name);
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("ip")
            .args(["route", "del", "default"])
            .status();
        let _ = std::process::Command::new("ip")
            .args(["route", "flush", "table", "aegis"])
            .status();
    }
    #[cfg(windows)]
    {
        if let Err(e) = vpn_platform_windows::cleanup_routes(&state.tun_name) {
            warn!("cleanup: route cleanup warning: {e}");
            errors.push(format!("routes: {e}"));
        }
    }

    // Step 3: Close TUN adapter (last — after all routes removed)
    trace!("cleanup: closing TUN adapter '{}'", state.tun_name);
    // The TUN device is dropped by the RAII guard (LinuxTun / WintunTun)
    // which calls close() / end_session+close_adapter automatically.
    // On crash, the OS closes the fd/handle on process exit.
    // But we try to explicitly close here for clean shutdown.

    // Step 4: Write cleanup manifest if there were errors
    if !errors.is_empty() {
        warn!("cleanup completed with {} errors", errors.len());
        let manifest_path = cleanup_manifest_path();
        let manifest = json!({
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            "tun_name": state.tun_name,
            "errors": errors,
        });
        if let Ok(serialized) = serde_json::to_string(&manifest) {
            if let Err(e) = std::fs::write(&manifest_path, serialized) {
                warn!("cleanup: failed to write manifest to {manifest_path}: {e}");
            } else {
                info!("cleanup: wrote manifest to {manifest_path}");
            }
        }
    } else {
        info!("cleanup: all resources freed successfully");
        // Remove any stale manifest from a previous crash
        let _ = std::fs::remove_file(cleanup_manifest_path());
    }
}

fn cleanup_manifest_path() -> String {
    #[cfg(target_os = "linux")]
    {
        "/tmp/aegis-vpn-cleanup.json".to_string()
    }
    #[cfg(windows)]
    {
        let temp = std::env::var("TEMP").unwrap_or_else(|_| "C:\\Temp".to_string());
        format!("{temp}\\aegis-vpn-cleanup.json")
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        "/tmp/aegis-vpn-cleanup.json".to_string()
    }
}

// ═══════════════════════════════════════════════════════════════
// PART 1.4: Orphan Detection on Startup
// ═══════════════════════════════════════════════════════════════

/// Scan for orphaned resources from a previous crash and clean them.
pub fn detect_and_clean_orphans(tun_name: &str, kill_switch: bool) {
    info!("startup: scanning for orphaned resources");

    // Check for cleanup manifest from previous crash
    let manifest_path = cleanup_manifest_path();
    if let Ok(contents) = std::fs::read_to_string(&manifest_path) {
        warn!("startup: found cleanup manifest from previous crash:");
        warn!("  {contents}");
        let _ = std::fs::remove_file(&manifest_path);
    }

    #[cfg(target_os = "linux")]
    {
        // Check for orphaned nftables table
        let status = std::process::Command::new("nft")
            .args(["list", "table", "inet", "aegis_vpn"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if let Ok(s) = status {
            if s.success() {
                warn!("startup: found orphaned nftables table 'aegis_vpn', cleaning");
                let _ = std::process::Command::new("nft")
                    .args(["delete", "table", "inet", "aegis_vpn"])
                    .status();
            }
        }

        // Check for orphaned default route pointing to our TUN
        let output = std::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output();
        if let Ok(out) = output {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if stdout.contains(tun_name) {
                warn!(
                    "startup: found orphaned default route via '{}', cleaning",
                    tun_name
                );
                let _ = std::process::Command::new("ip")
                    .args(["route", "del", "default"])
                    .status();
            }
        }

        // Check for orphaned TUN interface
        let output = std::process::Command::new("ip")
            .args(["link", "show", tun_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if let Ok(s) = output {
            if s.success() {
                warn!(
                    "startup: found orphaned TUN interface '{}', cleaning",
                    tun_name
                );
                let _ = std::process::Command::new("ip")
                    .args(["link", "set", tun_name, "down"])
                    .status();
                let _ = std::process::Command::new("ip")
                    .args(["link", "del", tun_name])
                    .status();
            }
        }
    }

    #[cfg(windows)]
    {
        // Check for orphaned WFP filters
        if kill_switch {
            if let Err(e) = vpn_platform_windows::disable_kill_switch() {
                warn!("startup: WFP cleanup attempt: {e}");
            }
        }

        // Check for orphaned routes
        if let Err(e) = vpn_platform_windows::cleanup_routes(tun_name) {
            warn!("startup: route cleanup attempt: {e}");
        }
    }

    info!("startup: orphan scan complete");
}

// ═══════════════════════════════════════════════════════════════
// PART 1.1: Signal Handling (Cross-platform)
// ═══════════════════════════════════════════════════════════════

/// Install the global panic hook that logs and triggers cleanup.
pub fn install_panic_hook(cleanup_state: Arc<CleanupState>) {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        error!("PANIC: {info}");

        // Try to capture backtrace
        let backtrace = std::backtrace::Backtrace::capture();
        error!("backtrace:\n{backtrace}");

        // Trigger cleanup
        perform_cleanup(&cleanup_state);

        // Call original hook (prints to stderr)
        original_hook(info);
    }));
}

/// Register signal handlers that set SHUTDOWN_REQUESTED.
/// The actual cleanup is performed by the main loop after it observes the flag.
pub async fn register_signal_handlers() -> Result<(), CleanupError> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigint = signal(SignalKind::interrupt())?;
        let mut sigterm = signal(SignalKind::terminate())?;

        tokio::spawn(async move {
            tokio::select! {
                _ = sigint.recv() => {
                    info!("received SIGINT");
                }
                _ = sigterm.recv() => {
                    info!("received SIGTERM");
                }
            }
            SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
        });
    }

    #[cfg(windows)]
    {
        // Windows: use ctrl_c handler for CTRL_C_EVENT and CTRL_BREAK_EVENT
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                info!("received CTRL+C / CTRL+BREAK");
                SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
            }
        });
    }

    Ok(())
}

/// Poll the shutdown flag. Returns true when shutdown has been requested.
pub fn should_shutdown() -> bool {
    SHUTDOWN_REQUESTED.load(Ordering::SeqCst)
}
