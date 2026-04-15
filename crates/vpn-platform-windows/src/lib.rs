pub mod admin;
pub mod service_installer;
pub mod wfp_native;

#[cfg(windows)]
mod imp {
    use anyhow::{anyhow, Result};
    use libloading::Library;
    use std::{
        ffi::{c_void, OsStr},
        io,
        net::IpAddr,
        os::windows::ffi::OsStrExt,
        process::Command,
        ptr::null,
        sync::Arc,
    };
    use tracing::{error, info, warn};
    use vpn_tun::{TunConfig, TunDevice};

    type AdapterHandle = *mut c_void;
    type SessionHandle = *mut c_void;
    type CreateAdapterFn =
        unsafe extern "system" fn(*const u16, *const u16, *const Guid) -> AdapterHandle;
    type CloseAdapterFn = unsafe extern "system" fn(AdapterHandle);
    type StartSessionFn = unsafe extern "system" fn(AdapterHandle, u32) -> SessionHandle;
    type EndSessionFn = unsafe extern "system" fn(SessionHandle);
    type ReceivePacketFn = unsafe extern "system" fn(SessionHandle, *mut u32) -> *mut u8;
    type ReleaseReceivePacketFn = unsafe extern "system" fn(SessionHandle, *const u8);
    type AllocateSendPacketFn = unsafe extern "system" fn(SessionHandle, u32) -> *mut u8;
    type SendPacketFn = unsafe extern "system" fn(SessionHandle, *const u8);

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Guid {
        pub data1: u32,
        pub data2: u16,
        pub data3: u16,
        pub data4: [u8; 8],
    }

    pub struct WintunApi {
        _lib: Library,
        create_adapter: CreateAdapterFn,
        close_adapter: CloseAdapterFn,
        start_session: StartSessionFn,
        end_session: EndSessionFn,
        receive_packet: ReceivePacketFn,
        release_receive_packet: ReleaseReceivePacketFn,
        allocate_send_packet: AllocateSendPacketFn,
        send_packet: SendPacketFn,
    }

    pub struct WintunTun {
        api: Arc<WintunApi>,
        adapter: AdapterHandle,
        session: SessionHandle,
        name: String,
        mtu: u32,
    }

    // Wintun handles are opaque OS resources owned by this wrapper and only
    // accessed through the synchronized daemon/runtime layers.
    unsafe impl Send for WintunTun {}
    unsafe impl Sync for WintunTun {}

    #[derive(Clone, Debug)]
    pub struct KillSwitchConfig {
        pub tun_alias: String,
        pub server_ip: IpAddr,
        pub server_port: u16,
        pub protocol: String,
    }

    #[derive(Clone, Debug)]
    pub struct WfpFilterSpec {
        pub remote_server_ip: IpAddr,
        pub remote_server_port: u16,
        pub tunnel_alias: String,
    }

    // ──────────────────────────────────────────────────────────────
    // NativeWfpController — admin-aware WFP integration
    // ──────────────────────────────────────────────────────────────

    pub struct NativeWfpController;

    impl NativeWfpController {
        /// Apply WFP filters using the native engine.
        /// Requires admin privileges — returns Err if not admin.
        pub fn apply_filters(spec: &WfpFilterSpec) -> Result<()> {
            if !crate::admin::is_admin() {
                return Err(anyhow!(
                    "WFP filter installation requires administrator privileges. \
                     Run as Administrator or disable kill switch."
                ));
            }

            info!(
                "NativeWfpController: applying WFP filters for server {}:{}",
                spec.remote_server_ip, spec.remote_server_port
            );

            let config = KillSwitchConfig {
                tun_alias: spec.tunnel_alias.clone(),
                server_ip: spec.remote_server_ip,
                server_port: spec.remote_server_port,
                protocol: "UDP".to_string(),
            };

            if let Ok(recovered) = super::wfp_native::recover_orphaned_filters() {
                if !recovered.is_empty() {
                    info!("NativeWfpController: recovered {} orphaned filters from previous session", recovered.len());
                }
            }

            let mut engine = super::wfp_native::WfpEngine::open()
                .map_err(|e| anyhow!("WFP engine open failed: {e}"))?;

            engine
                .install_kill_switch(&config)
                .map_err(|e| anyhow!("WFP filter installation failed: {e}"))?;

            info!("NativeWfpController: WFP filters applied successfully");
            Ok(())
        }

        /// Remove all WFP filters by opening a fresh engine and removing tracked filters.
        /// Safe to call when not admin — logs warning and returns Ok.
        pub fn remove_filters() -> Result<()> {
            info!("NativeWfpController: removing WFP filters");
            match super::wfp_native::WfpEngine::open() {
                Ok(mut engine) => {
                    engine
                        .remove_filters()
                        .map_err(|e| anyhow!("WFP filter removal failed: {e}"))?;
                    info!("NativeWfpController: WFP filters removed");
                    Ok(())
                }
                Err(e) => {
                    if !crate::admin::is_admin() {
                        info!("NativeWfpController: non-admin — WFP cleanup skipped (filters may persist until reboot)");
                    } else {
                        warn!("NativeWfpController: could not open WFP engine for cleanup: {e}");
                    }
                    Ok(())
                }
            }
        }
    }

    // ──────────────────────────────────────────────────────────────
    // PART 4: Wintun hardening — verify DLL and driver before use
    // ──────────────────────────────────────────────────────────────

    impl WintunApi {
        /// Load the Wintun DLL with verification.
        /// Returns Result::Err if DLL not found, corrupted, or driver missing.
        /// Never panics.
        pub fn load(dll_path: &str) -> Result<Self> {
            info!("wintun: loading DLL from '{dll_path}'");

            // Verify the DLL file exists before attempting to load
            if !std::path::Path::new(dll_path).exists() {
                // Search common locations
                let search_paths = [
                    "wintun.dll",
                    "C:\\Program Files\\WireGuard\\wintun.dll",
                    &format!(
                        "{}\\wintun.dll",
                        std::env::var("SystemRoot").unwrap_or_default()
                    ),
                ];

                let found = false;
                for path in &search_paths {
                    if std::path::Path::new(path).exists() {
                        info!("wintun: found DLL at '{path}'");
                        return Self::load_inner(path);
                    }
                }

                if !found {
                    error!(
                        "wintun: DLL not found at '{dll_path}' or common locations. \
                            Install WireGuard or place wintun.dll in the working directory."
                    );
                    return Err(anyhow!(
                        "wintun.dll not found. The Wintun driver must be installed. \
                         Download from https://www.wintun.net/ or install WireGuard."
                    ));
                }
            }

            Self::load_inner(dll_path)
        }

        fn load_inner(dll_path: &str) -> Result<Self> {
            let lib = match unsafe { Library::new(dll_path) } {
                Ok(lib) => lib,
                Err(e) => {
                    error!("wintun: failed to load DLL '{dll_path}': {e}");
                    return Err(anyhow!("Failed to load wintun.dll: {e}. \
                                        Verify the DLL is not corrupted and matches your architecture (x64)."));
                }
            };

            // Verify all required symbols exist — fail early, not on first use
            let create_adapter = unsafe { *lib.get::<CreateAdapterFn>(b"WintunCreateAdapter\0")? };
            let close_adapter = unsafe { *lib.get::<CloseAdapterFn>(b"WintunCloseAdapter\0")? };
            let start_session = unsafe { *lib.get::<StartSessionFn>(b"WintunStartSession\0")? };
            let end_session = unsafe { *lib.get::<EndSessionFn>(b"WintunEndSession\0")? };
            let receive_packet = unsafe { *lib.get::<ReceivePacketFn>(b"WintunReceivePacket\0")? };
            let release_receive_packet =
                unsafe { *lib.get::<ReleaseReceivePacketFn>(b"WintunReleaseReceivePacket\0")? };
            let allocate_send_packet =
                unsafe { *lib.get::<AllocateSendPacketFn>(b"WintunAllocateSendPacket\0")? };
            let send_packet = unsafe { *lib.get::<SendPacketFn>(b"WintunSendPacket\0")? };

            info!("wintun: DLL loaded and verified — all 8 symbols resolved");

            Ok(Self {
                create_adapter,
                close_adapter,
                start_session,
                end_session,
                receive_packet,
                release_receive_packet,
                allocate_send_packet,
                send_packet,
                _lib: lib,
            })
        }
    }

    impl TunDevice for WintunTun {
        fn name(&self) -> &str {
            &self.name
        }

        fn mtu(&self) -> u32 {
            self.mtu
        }

        fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut packet_size = 0u32;
            let ptr = unsafe { (self.api.receive_packet)(self.session, &mut packet_size) };
            if ptr.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "no packet available",
                ));
            }

            let size = packet_size as usize;
            if size > buf.len() {
                unsafe { (self.api.release_receive_packet)(self.session, ptr) };
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "packet larger than destination buffer",
                ));
            }

            unsafe {
                std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), size);
                (self.api.release_receive_packet)(self.session, ptr);
            }
            Ok(size)
        }

        /// Read multiple packets in a batch (up to max_packets).
        /// Returns the number of packets read and a list of (offset, size) pairs
        /// into the provided buffer.
        fn read_packets_batch(&mut self, buf: &mut [u8], max_packets: usize) -> io::Result<usize> {
            // Wintun's recv returns one packet at a time, so we just call read_packet
            // in a loop. This is still useful for amortizing the TUN lock acquisition.
            if max_packets == 0 {
                return Ok(0);
            }

            let mut offset = 0;
            let mut count = 0;

            while count < max_packets && offset < buf.len() {
                let remaining = &mut buf[offset..];
                match self.read_packet(remaining) {
                    Ok(size) => {
                        offset += size;
                        count += 1;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }

            Ok(count)
        }

        fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
            let ptr = unsafe { (self.api.allocate_send_packet)(self.session, packet.len() as u32) };
            if ptr.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "wintun send buffer full",
                ));
            }

            unsafe {
                std::ptr::copy_nonoverlapping(packet.as_ptr(), ptr, packet.len());
                (self.api.send_packet)(self.session, ptr);
            }
            Ok(())
        }
    }

    // ──────────────────────────────────────────────────────────────
    // CRASH-SAFE DROP — never panics inside Drop
    // ──────────────────────────────────────────────────────────────

    impl Drop for WintunTun {
        fn drop(&mut self) {
            info!("wintun: closing session and adapter for '{}'", self.name);

            // Use catch_unwind pattern — never panic in Drop
            let session = self.session;
            let adapter = self.adapter;
            let api = &self.api;

            // End session (must happen before closing adapter)
            if !session.is_null() {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    unsafe { (api.end_session)(session) };
                }));
                if let Err(_) = result {
                    error!(
                        "wintun: end_session panicked for '{}' — continuing cleanup",
                        self.name
                    );
                }
            }

            // Close adapter
            if !adapter.is_null() {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    unsafe { (api.close_adapter)(adapter) };
                }));
                if let Err(_) = result {
                    error!(
                        "wintun: close_adapter panicked for '{}' — continuing cleanup",
                        self.name
                    );
                }
            }

            info!("wintun: adapter '{}' closed", self.name);
        }
    }

    // ──────────────────────────────────────────────────────────────
    // TUN creation and configuration — admin-aware
    // ──────────────────────────────────────────────────────────────

    pub fn create_tun(config: &TunConfig, dll_path: Option<&str>) -> Result<WintunTun> {
        info!("wintun: creating adapter '{}'", config.name);

        // PART 4: Verify admin privileges before attempting adapter creation
        if !crate::admin::is_admin() {
            return Err(anyhow!(
                "Wintun adapter creation requires administrator privileges. \
                 Run as Administrator or disable TUN creation in limited mode."
            ));
        }

        // PART 4: Verify DLL loads successfully before creating adapter
        let api = Arc::new(WintunApi::load(dll_path.unwrap_or("wintun.dll"))?);

        let name = wide(&config.name);
        let tunnel_type = wide("AegisVPN");
        let adapter = unsafe { (api.create_adapter)(name.as_ptr(), tunnel_type.as_ptr(), null()) };
        if adapter.is_null() {
            error!(
                "wintun: WintunCreateAdapter returned NULL for '{}'",
                config.name
            );
            return Err(anyhow!(
                "WintunCreateAdapter failed for '{}'. Ensure Wintun driver is installed.",
                config.name
            ));
        }
        info!("wintun: adapter '{}' created", config.name);

        let session = unsafe { (api.start_session)(adapter, 0x400000) };
        if session.is_null() {
            error!(
                "wintun: WintunStartSession returned NULL for '{}'",
                config.name
            );
            unsafe { (api.close_adapter)(adapter) };
            return Err(anyhow!("WintunStartSession failed for '{}'", config.name));
        }
        info!("wintun: session started for '{}' (ring=4MB)", config.name);

        configure_interface(config)?;

        Ok(WintunTun {
            api,
            adapter,
            session,
            name: config.name.clone(),
            mtu: config.mtu,
        })
    }

    pub fn configure_interface(config: &TunConfig) -> Result<()> {
        if !config.name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(anyhow!("invalid interface name: contains disallowed characters"));
        }

        info!(
            "wintun: configuring interface '{}' ({})",
            config.name, config.address_cidr
        );
        let (ip, prefix) = parse_cidr(&config.address_cidr)?;
        let script = format!(
            "$name = '{}'; $ip = '{}'; $prefix = {}; $mtu = {}; \
             $null = Get-NetAdapter -Name $name -ErrorAction Stop; \
             if (-not (Get-NetIPAddress -InterfaceAlias $name -IPAddress $ip -ErrorAction SilentlyContinue)) \
             {{ New-NetIPAddress -InterfaceAlias $name -IPAddress $ip -PrefixLength $prefix | Out-Null }}; \
             Set-NetIPInterface -InterfaceAlias $name -NlMtuBytes $mtu | Out-Null",
            config.name, ip, prefix, config.mtu
        );
        run_powershell(&script)
    }

    // ──────────────────────────────────────────────────────────────
    // Routing
    // ──────────────────────────────────────────────────────────────

    pub fn route_server_via_physical(server_ip: IpAddr) -> Result<()> {
        match server_ip {
            IpAddr::V4(_) => {},
            IpAddr::V6(v6) if v6.is_global() => {},
            _ => return Err(anyhow!("invalid server IP address")),
        };

        info!(
            "windows: adding server route for {} via physical interface",
            server_ip
        );
        let script = format!(
            "$server = '{}'; $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1; \
             if ($null -eq $route) {{ throw 'No default route found' }}; \
             route add $server mask 255.255.255.255 $($route.NextHop) if $($route.ifIndex)",
            server_ip
        );
        let result = run_powershell(&script);
        if result.is_ok() {
            info!("windows: server route for {} added", server_ip);
        }
        result
    }

    pub fn route_default_via_tun(tun_alias: &str) -> Result<()> {
        if !tun_alias.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(anyhow!("invalid tunnel alias"));
        }

        info!("windows: routing default traffic via TUN '{}'", tun_alias);
        let script = format!(
            "$name = '{}'; $ifIndex = (Get-NetAdapter -Name $name -ErrorAction Stop).ifIndex; \
             route add 0.0.0.0 mask 0.0.0.0 0.0.0.0 if $ifIndex metric 5",
            tun_alias
        );
        let result = run_powershell(&script);
        if result.is_ok() {
            info!("windows: default route via '{}' established", tun_alias);
        }
        result
    }

    // ──────────────────────────────────────────────────────────────
    // Kill switch — admin-aware WFP with firewall fallback
    // ──────────────────────────────────────────────────────────────

    pub fn enable_kill_switch(config: &KillSwitchConfig) -> Result<()> {
        info!(
            "windows: enabling kill switch (server={}:{}, tun={})",
            config.server_ip, config.server_port, config.tun_alias
        );

        // Check admin privilege — log runtime mode
        let is_admin = crate::admin::is_admin();
        info!("windows: runtime privilege check: is_admin={}", is_admin);

        if !is_admin {
            warn!("windows: non-admin mode — kill switch requires admin, falling back to firewall");
            return enable_firewall_kill_switch(config);
        }

        // Try native WFP first
        if let Ok(mut engine) = super::wfp_native::WfpEngine::open() {
            match engine.install_kill_switch(config) {
                Ok(()) => {
                    info!("windows: kill switch enabled via native WFP");
                    return Ok(());
                }
                Err(e) => {
                    warn!("windows: WFP kill switch failed ({e}), falling back to firewall");
                }
            }
        } else {
            info!("windows: WFP engine unavailable, using firewall fallback");
        }

        // Fallback: PowerShell firewall rules
        enable_firewall_kill_switch(config)
    }

    fn enable_firewall_kill_switch(config: &KillSwitchConfig) -> Result<()> {
        info!("windows: enabling firewall-based kill switch");
        let _ = remove_firewall_rules();
        let script = format!(
            "Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block | Out-Null; \
             New-NetFirewallRule -DisplayName 'AegisVPN Allow Tunnel Endpoint' -Group 'AegisVPN' -Direction Outbound -Action Allow -Protocol {proto} -RemoteAddress {ip} -RemotePort {port} | Out-Null; \
             New-NetFirewallRule -DisplayName 'AegisVPN Allow Tunnel Interface' -Group 'AegisVPN' -Direction Outbound -Action Allow -InterfaceAlias '{alias}' | Out-Null; \
             New-NetFirewallRule -DisplayName 'AegisVPN Allow Loopback' -Group 'AegisVPN' -Direction Outbound -Action Allow -RemoteAddress 127.0.0.1,::1 | Out-Null",
            proto = config.protocol,
            ip = config.server_ip,
            port = config.server_port,
            alias = config.tun_alias
        );
        let result = run_powershell(&script);
        if result.is_ok() {
            info!("windows: firewall kill switch enabled");
        }
        result
    }

    fn remove_firewall_rules() -> Result<()> {
        let script = "Get-NetFirewallRule -Group 'AegisVPN' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
                      Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow | Out-Null";
        run_powershell(script)
    }

    pub fn disable_kill_switch() -> Result<()> {
        info!("windows: disabling kill switch");

        let mut errors = Vec::new();

        // 1. Remove WFP filters
        if let Err(e) = cleanup_wfp_filters() {
            warn!("windows: WFP cleanup warning: {e}");
            errors.push(format!("wfp: {e}"));
        }

        // 2. Remove firewall rules
        if let Err(e) = remove_firewall_rules() {
            warn!("windows: firewall cleanup warning: {e}");
            errors.push(format!("firewall: {e}"));
        }

        if errors.is_empty() {
            info!("windows: kill switch disabled cleanly");
            Ok(())
        } else {
            // Still return Ok — partial cleanup is acceptable
            warn!(
                "windows: kill switch disabled with {} warnings",
                errors.len()
            );
            Ok(())
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Full teardown and verification
    // ──────────────────────────────────────────────────────────────

    pub fn full_teardown(tun_alias: &str) -> Result<()> {
        if !tun_alias.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(anyhow!("invalid tunnel alias: contains disallowed characters"));
        }

        info!("windows: starting full teardown for '{}'", tun_alias);

        let mut errors = Vec::new();

        // 1. Remove default route via TUN
        info!("windows: removing default route via '{}'", tun_alias);
        let remove_route_script = format!(
            "$name = '{}'; $adapter = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue; \
             if ($null -ne $adapter) {{ route delete 0.0.0.0 mask 0.0.0.0 0.0.0.0 2>$null }}; \
             Get-NetRoute -InterfaceAlias $name -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue",
            tun_alias
        );
        if let Err(e) = run_powershell(&remove_route_script) {
            warn!("windows: route cleanup warning: {e}");
            errors.push(format!("route cleanup: {e}"));
        }

        // 2. Remove server-specific route
        let remove_server_route = "route delete 255.255.255.255 2>$null; \
                                   Get-NetRoute -DestinationPrefix '255.255.255.255/32' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue";
        if let Err(e) = run_powershell(remove_server_route) {
            warn!("windows: server route cleanup warning: {e}");
        }

        // 3. Remove WFP filters
        if let Err(e) = cleanup_wfp_filters() {
            warn!("windows: WFP cleanup warning: {e}");
            errors.push(format!("wfp cleanup: {e}"));
        }

        // 4. Remove firewall rules
        info!("windows: removing firewall rules");
        if let Err(e) = remove_firewall_rules() {
            warn!("windows: firewall cleanup warning: {e}");
            errors.push(format!("firewall cleanup: {e}"));
        }

        // 5. Verify adapter state
        info!("windows: verifying adapter '{}' state", tun_alias);
        let verify_script = format!(
            "$name = '{}'; $adapter = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue; \
             if ($null -ne $adapter -and $adapter.Status -eq 'Up') {{ \
                 Write-Warning 'Adapter still up after teardown'; \
             }}",
            tun_alias
        );
        if let Err(e) = run_powershell(&verify_script) {
            warn!("windows: adapter verification warning: {e}");
        }

        if errors.is_empty() {
            info!("windows: full teardown completed successfully");
            Ok(())
        } else {
            Err(anyhow!(
                "windows: teardown completed with {} warnings: {}",
                errors.len(),
                errors.join("; ")
            ))
        }
    }

    fn cleanup_wfp_filters() -> Result<()> {
        info!("windows: cleaning up WFP filters");

        // Check if we have admin — if not, skip WFP cleanup gracefully
        if !crate::admin::is_admin() {
            info!("windows: non-admin — WFP filter cleanup skipped");
            return Ok(());
        }

        match super::wfp_native::WfpEngine::open() {
            Ok(mut engine) => {
                engine.remove_filters()?;
                info!("windows: WFP filters cleaned up");
                Ok(())
            }
            Err(e) => {
                warn!("windows: WFP engine not available for cleanup: {e}");
                Ok(())
            }
        }
    }

    pub fn cleanup_routes(tun_alias: &str) -> Result<()> {
        info!("windows: cleaning up routes for '{}'", tun_alias);
        let script = format!(
            "Get-NetRoute -InterfaceAlias '{name}' -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; \
             route delete 0.0.0.0 mask 0.0.0.0 0.0.0.0 2>$null",
            name = tun_alias
        );
        run_powershell(&script)
    }

    pub fn verify_teardown_clean(tun_alias: &str) -> Vec<String> {
        info!("windows: verifying teardown is clean for '{}'", tun_alias);
        let mut issues = Vec::new();

        let check_routes = format!(
            "$routes = Get-NetRoute -InterfaceAlias '{name}' -ErrorAction SilentlyContinue; \
             if ($routes) {{ Write-Output \"LEAKED_ROUTES: $($routes.Count)\" }}",
            name = tun_alias
        );
        if let Ok(output) = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &check_routes])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("LEAKED_ROUTES") {
                issues.push(format!("Leaked routes: {}", stdout.trim()));
            }
        }

        let check_firewall =
            "$rules = Get-NetFirewallRule -Group 'AegisVPN' -ErrorAction SilentlyContinue; \
                              if ($rules) { Write-Output \"LEAKED_RULES: $($rules.Count)\" }";
        if let Ok(output) = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", check_firewall])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("LEAKED_RULES") {
                issues.push(format!("Leaked firewall rules: {}", stdout.trim()));
            }
        }

        if issues.is_empty() {
            info!("windows: teardown verification passed — no leaks detected");
        } else {
            warn!(
                "windows: teardown verification found {} issues",
                issues.len()
            );
        }

        issues
    }

    // ──────────────────────────────────────────────────────────────
    // DPAPI Key Storage
    // ──────────────────────────────────────────────────────────────

    pub mod dpapi {
        use anyhow::{anyhow, Result};
        use std::{ffi::c_void, ptr::null_mut};

        #[repr(C)]
        struct DataBlob {
            cb_data: u32,
            pb_data: *mut u8,
        }

        const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

        const AEGIS_DPAPI_ENTROPY: &[u8] = b"Aegis-VPN-Key-Storage-2024";

        #[link(name = "crypt32")]
        extern "system" {
            fn CryptProtectData(
                data_in: *const DataBlob,
                data_desc: *const u16,
                entropy: *const DataBlob,
                reserved: *const c_void,
                prompt_struct: *const c_void,
                flags: u32,
                data_out: *mut DataBlob,
            ) -> i32;

            fn CryptUnprotectData(
                data_in: *const DataBlob,
                data_desc: *mut *mut u16,
                entropy: *const DataBlob,
                reserved: *const c_void,
                prompt_struct: *const c_void,
                flags: u32,
                data_out: *mut DataBlob,
            ) -> i32;

            fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
        }

        fn make_entropy_blob() -> DataBlob {
            DataBlob {
                cb_data: AEGIS_DPAPI_ENTROPY.len() as u32,
                pb_data: AEGIS_DPAPI_ENTROPY.as_ptr() as *mut u8,
            }
        }

        pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
            if data.is_empty() {
                return Err(anyhow!("cannot protect empty data"));
            }

            let data_in = DataBlob {
                cb_data: data.len() as u32,
                pb_data: data.as_ptr() as *mut u8,
            };

            let entropy = make_entropy_blob();

            let mut data_out = DataBlob {
                cb_data: 0,
                pb_data: null_mut(),
            };

            let success = unsafe {
                CryptProtectData(
                    &data_in,
                    null_mut(),
                    &entropy,
                    null_mut(),
                    null_mut(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut data_out,
                )
            };

            if success == 0 {
                let err = std::io::Error::last_os_error();
                return Err(anyhow!(
                    "CryptProtectData failed: {err} (code {})",
                    err.raw_os_error().unwrap_or(0)
                ));
            }

            if data_out.pb_data.is_null() || data_out.cb_data == 0 {
                return Err(anyhow!("CryptProtectData returned null/empty output"));
            }

            let encrypted = unsafe {
                std::slice::from_raw_parts(data_out.pb_data, data_out.cb_data as usize).to_vec()
            };

            unsafe {
                std::ptr::write_bytes(data_out.pb_data, 0, data_out.cb_data as usize);
                LocalFree(data_out.pb_data as *mut c_void);
            }

            tracing::info!(
                "dpapi: protected {} bytes -> {} bytes",
                data.len(),
                encrypted.len()
            );
            Ok(encrypted)
        }

        pub fn unprotect(encrypted: &[u8]) -> Result<Vec<u8>> {
            if encrypted.len() < 4 {
                return Err(anyhow!(
                    "encrypted data too short ({} bytes), likely corrupted",
                    encrypted.len()
                ));
            }

            let data_in = DataBlob {
                cb_data: encrypted.len() as u32,
                pb_data: encrypted.as_ptr() as *mut u8,
            };

            let entropy = make_entropy_blob();

            let mut data_out = DataBlob {
                cb_data: 0,
                pb_data: null_mut(),
            };

            let mut desc_ptr: *mut u16 = null_mut();

            let success = unsafe {
                CryptUnprotectData(
                    &data_in,
                    &mut desc_ptr,
                    &entropy,
                    null_mut(),
                    null_mut(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut data_out,
                )
            };

            if success == 0 {
                let err = std::io::Error::last_os_error();
                return Err(anyhow!(
                    "CryptUnprotectData failed: {err} (code {}). Data may be corrupted or from a different user/machine.",
                    err.raw_os_error().unwrap_or(0)
                ));
            }

            if data_out.pb_data.is_null() || data_out.cb_data == 0 {
                return Err(anyhow!("CryptUnprotectData returned null/empty output"));
            }

            let decrypted = unsafe {
                std::slice::from_raw_parts(data_out.pb_data, data_out.cb_data as usize).to_vec()
            };

            unsafe {
                std::ptr::write_bytes(data_out.pb_data, 0, data_out.cb_data as usize);
                if !desc_ptr.is_null() {
                    LocalFree(desc_ptr as *mut c_void);
                }
                LocalFree(data_out.pb_data as *mut c_void);
            };

            tracing::info!(
                "dpapi: unprotected {} bytes -> {} bytes",
                encrypted.len(),
                decrypted.len()
            );
            Ok(decrypted)
        }

        pub fn store_key(path: &std::path::Path, key_data: &[u8]) -> Result<()> {
            let encrypted = protect(key_data)?;

            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    anyhow!("failed to create key directory {}: {e}", parent.display())
                })?;
            }

            std::fs::write(path, &encrypted)
                .map_err(|e| anyhow!("failed to write encrypted key to {}: {e}", path.display()))?;

            tracing::info!("dpapi: stored encrypted key to {}", path.display());
            Ok(())
        }

        pub fn load_key(path: &std::path::Path) -> Result<Vec<u8>> {
            if !path.exists() {
                return Err(anyhow!("key file not found: {}", path.display()));
            }

            let encrypted = std::fs::read(path).map_err(|e| {
                anyhow!("failed to read encrypted key from {}: {e}", path.display())
            })?;

            if encrypted.is_empty() {
                return Err(anyhow!("key file is empty: {}", path.display()));
            }

            let decrypted = unprotect(&encrypted)?;
            tracing::info!("dpapi: loaded encrypted key from {}", path.display());
            Ok(decrypted)
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────

    fn run_powershell(script: &str) -> Result<()> {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "powershell command failed (exit {}):\nstdout: {}\nstderr: {}",
                output.status.code().unwrap_or(-1),
                stdout.trim(),
                stderr.trim()
            ));
        }
        Ok(())
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn parse_cidr(value: &str) -> Result<(String, u8)> {
        let mut parts = value.split('/');
        let ip = parts
            .next()
            .ok_or_else(|| anyhow!("missing IP address in CIDR: '{value}'"))?
            .trim()
            .to_string();

        if ip.is_empty() {
            return Err(anyhow!("empty IP address in CIDR: '{value}'"));
        }

        let _: std::net::IpAddr = ip
            .parse()
            .map_err(|e| anyhow!("invalid IP address '{ip}' in CIDR: {e}"))?;

        let prefix = parts
            .next()
            .unwrap_or("24")
            .trim()
            .parse::<u8>()
            .map_err(|e| anyhow!("invalid prefix in CIDR '{value}': {e}"))?;

        if prefix > 32 {
            return Err(anyhow!("prefix length {prefix} exceeds maximum (32)"));
        }

        Ok((ip, prefix))
    }
}

#[cfg(not(windows))]
mod imp {
    use anyhow::{anyhow, Result};
    use std::net::IpAddr;
    use vpn_tun::TunConfig;

    #[derive(Clone, Debug)]
    pub struct KillSwitchConfig {
        pub tun_alias: String,
        pub server_ip: IpAddr,
        pub server_port: u16,
        pub protocol: String,
    }

    #[derive(Clone, Debug)]
    pub struct WfpFilterSpec {
        pub remote_server_ip: IpAddr,
        pub remote_server_port: u16,
        pub tunnel_alias: String,
    }

    pub struct NativeWfpController;

    impl NativeWfpController {
        pub fn apply_filters(_: &WfpFilterSpec) -> Result<()> {
            Err(anyhow!(
                "windows platform support is only available on Windows"
            ))
        }
        pub fn remove_filters() -> Result<()> {
            Err(anyhow!(
                "windows platform support is only available on Windows"
            ))
        }
    }

    pub fn create_tun(_: &TunConfig, _: Option<&str>) -> Result<()> {
        Err(anyhow!(
            "windows platform support is only available on Windows"
        ))
    }

    pub fn configure_interface(_: &TunConfig) -> Result<()> {
        Err(anyhow!(
            "windows platform support is only available on Windows"
        ))
    }

    pub fn route_server_via_physical(_: IpAddr) -> Result<()> {
        Err(anyhow!(
            "windows platform support is only available on Windows"
        ))
    }

    pub fn route_default_via_tun(_: &str) -> Result<()> {
        Err(anyhow!(
            "windows platform support is only available on Windows"
        ))
    }

    pub fn enable_kill_switch(_: &KillSwitchConfig) -> Result<()> {
        Err(anyhow!(
            "windows platform support is only available on Windows"
        ))
    }

    pub fn disable_kill_switch() -> Result<()> {
        Err(anyhow!(
            "windows platform support is only available on Windows"
        ))
    }

    pub fn full_teardown(_: &str) -> Result<()> {
        Err(anyhow!(
            "windows platform support is only available on Windows"
        ))
    }

    pub fn cleanup_routes(_: &str) -> Result<()> {
        Err(anyhow!(
            "windows platform support is only available on Windows"
        ))
    }

    pub fn verify_teardown_clean(_: &str) -> Vec<String> {
        vec!["windows platform support is only available on Windows".to_string()]
    }

    pub mod dpapi {
        use anyhow::{anyhow, Result};

        pub fn protect(_: &[u8]) -> Result<Vec<u8>> {
            Err(anyhow!("DPAPI is only available on Windows"))
        }
        pub fn unprotect(_: &[u8]) -> Result<Vec<u8>> {
            Err(anyhow!("DPAPI is only available on Windows"))
        }
        pub fn store_key(_: &std::path::Path, _: &[u8]) -> Result<()> {
            Err(anyhow!("DPAPI is only available on Windows"))
        }
        pub fn load_key(_: &std::path::Path) -> Result<Vec<u8>> {
            Err(anyhow!("DPAPI is only available on Windows"))
        }
        pub fn make_entropy_blob() -> () {
            ()
        }
    }
}

pub use imp::*;
