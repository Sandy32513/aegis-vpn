// ═══════════════════════════════════════════════════════════════
// Windows Platform Integration for Aegis VPN
// ═══════════════════════════════════════════════════════════════

#[cfg(windows)]
mod imp {
    use anyhow::{anyhow, Result};
    use std::{
        ffi::c_void,
        net::IpAddr,
        process::Command,
        sync::atomic::{AtomicBool, Ordering},
    };
    use tracing::{error, info, warn};

    use super::wfp_native;
    use crate::KillSwitchConfig;

    // ──────────────────────────────────────────────────────────────
    // TUN Interface Management
    // ──────────────────────────────────────────────────────────────

    pub fn create_tun(config: &vpn_tun::TunConfig, dll_path: Option<&str>) -> Result<()> {
        // Verify admin privileges
        if !super::admin::is_admin() {
            return Err(anyhow!(
                "Wintun adapter creation requires administrator privileges"
            ));
        }

        // Validate interface name
        if !config
            .name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(anyhow!("invalid interface name"));
        }

        // Create TUN via wfp_native module
        let _tun = super::wfp_native::create_tun(config, dll_path)?;
        Ok(())
    }

    pub fn configure_interface(config: &vpn_tun::TunConfig) -> Result<()> {
        // Validate interface name strictly to prevent PowerShell injection
        if !config
            .name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(anyhow!(
                "invalid interface name: contains disallowed characters"
            ));
        }
        if config.name.len() > 255 {
            return Err(anyhow!("interface name exceeds maximum length"));
        }

        info!(
            "wintun: configuring interface '{}' ({})",
            config.name, config.address_cidr
        );
        let (ip, prefix) = parse_cidr(&config.address_cidr)?;
        if ip.parse::<std::net::IpAddr>().is_err() {
            return Err(anyhow!("invalid IP address in CIDR: {}", ip));
        }

        // SECURITY: Use splatted parameters to prevent PowerShell injection
        let escaped_name = powershell_escape(&config.name);
        let escaped_ip = powershell_escape(&ip);
        let script = format!(
            "$params = @{{Name='{}'; IPAddress='{}'; PrefixLength={}; NlMtuBytes={}}}; \
             $adapter = Get-NetAdapter @params -ErrorAction Stop; \
             if (-not (Get-NetIPAddress -InterfaceAlias $params.Name -IPAddress $params.IPAddress -ErrorAction SilentlyContinue)) \
             {{ New-NetIPAddress @params | Out-Null }}; \
             Set-NetIPInterface -InterfaceAlias $params.Name -NlMtuBytes $params.NlMtuBytes | Out-Null; \
             Write-Output 'SUCCESS'",
            escaped_name, escaped_ip, prefix, config.mtu
        );

        let result = run_powershell(&script);
        if result.is_ok() {
            info!("wintun: interface '{}' configured", config.name);
        }
        result
    }

    // ──────────────────────────────────────────────────────────────
    // Routing
    // ──────────────────────────────────────────────────────────────

    pub fn route_server_via_physical(server_ip: IpAddr) -> Result<()> {
        match server_ip {
            IpAddr::V4(_) => {}
            IpAddr::V6(v6) if v6.is_global() => {}
            _ => return Err(anyhow!("invalid server IP address")),
        };

        info!(
            "windows: adding server route for {} via physical interface",
            server_ip
        );
        let ip_str = server_ip.to_string();
        if !ip_str.chars().all(|c| {
            c.is_ascii_digit()
                || c == '.'
                || c == ':'
                || c == 'a'
                || c == 'b'
                || c == 'c'
                || c == 'd'
                || c == 'e'
                || c == 'f'
                || c == 'A'
                || c == 'B'
                || c == 'C'
                || c == 'D'
                || c == 'E'
                || c == 'F'
        }) {
            return Err(anyhow!("invalid characters in IP address"));
        }
        let script = format!(
            "$params = @{{DestinationPrefix='{}/32'; NextHop=(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop; InterfaceIndex=(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).ifIndex}}; \
             if ($null -eq $params.NextHop) {{ throw 'No default route found' }}; \
             New-NetRoute @params -ErrorAction Stop; \
             Write-Output 'SUCCESS'",
            ip_str
        );
        run_powershell(&script)
    }

    pub fn route_default_via_tun(tun_alias: &str) -> Result<()> {
        if !tun_alias
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(anyhow!("invalid tunnel alias"));
        }
        if tun_alias.len() > 255 {
            return Err(anyhow!("tunnel alias exceeds maximum length"));
        }
        if tun_alias.contains('\\') || tun_alias.contains('/') {
            return Err(anyhow!("invalid tunnel alias"));
        }

        info!("windows: routing default traffic via TUN '{}'", tun_alias);
        let escaped_alias = powershell_escape(tun_alias);
        let script = format!(
            "$params = @{{Name='{}'}}; \
             $adapter = Get-NetAdapter @params -ErrorAction Stop; \
             $ifIndex = $adapter.ifIndex; \
             $route_params = @{{DestinationPrefix='0.0.0.0/0'; NextHop='0.0.0.0'; InterfaceIndex=$ifIndex; RouteMetric=5}}; \
             New-NetRoute @route_params -ErrorAction Stop; \
             Write-Output 'SUCCESS'",
            escaped_alias
        );
        run_powershell(&script)
    }

    // ──────────────────────────────────────────────────────────────
    // Kill Switch
    // ──────────────────────────────────────────────────────────────

    pub fn enable_kill_switch(config: &KillSwitchConfig) -> Result<()> {
        info!(
            "windows: enabling kill switch (server={}:{}, tun={})",
            config.server_ip, config.server_port, config.tun_alias
        );

        let is_admin = super::admin::is_admin();
        info!("windows: runtime privilege check: is_admin={}", is_admin);

        if !is_admin {
            warn!("windows: non-admin mode — using firewall fallback");
            return enable_firewall_kill_switch(config);
        }

        if let Ok(mut engine) = super::wfp_native::WfpEngine::open() {
            match engine.install_kill_switch(config) {
                Ok(()) => {
                    info!("windows: kill switch enabled via native WFP");
                    return Ok(());
                }
                Err(e) => {
                    warn!("windows: WFP kill switch failed ({e}), falling back");
                }
            }
        }

        enable_firewall_kill_switch(config)
    }

    fn enable_firewall_kill_switch(config: &KillSwitchConfig) -> Result<()> {
        info!("windows: enabling firewall-based kill switch");
        let _ = remove_firewall_rules();

        let proto = match config.protocol.to_uppercase().as_str() {
            "TCP" | "UDP" => config.protocol.as_str(),
            _ => return Err(anyhow!("invalid protocol")),
        };

        let escaped_ip = powershell_escape(&config.server_ip.to_string());
        let escaped_port = config.server_port.to_string();
        let escaped_alias = powershell_escape(&config.tun_alias);
        let escaped_proto = proto.to_string();

        let script = format!(
            "$profile_params = @{{Profile='Domain,Public,Private'; DefaultOutboundAction='Block'}}; \
             Set-NetFirewallProfile @profile_params | Out-Null; \
             $rule1_params = @{{DisplayName='AegisVPN Allow Tunnel Endpoint'; Group='AegisVPN'; Direction='Outbound'; Action='Allow'; Protocol='{}'; RemoteAddress='{}'; RemotePort='{}'}}; \
             New-NetFirewallRule @rule1_params | Out-Null; \
             $rule2_params = @{{DisplayName='AegisVPN Allow Tunnel Interface'; Group='AegisVPN'; Direction='Outbound'; Action='Allow'; InterfaceAlias='{}'}}; \
             New-NetFirewallRule @rule2_params | Out-Null; \
             $rule3_params = @{{DisplayName='AegisVPN Allow Loopback'; Group='AegisVPN'; Direction='Outbound'; Action='Allow'; RemoteAddress=@('127.0.0.1','::1')}}; \
             New-NetFirewallRule @rule3_params | Out-Null; \
             Write-Output 'SUCCESS'",
            escaped_proto, escaped_ip, escaped_port, escaped_alias
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

        if let Err(e) = cleanup_wfp_filters() {
            warn!("windows: WFP cleanup warning: {e}");
            errors.push(format!("wfp: {e}"));
        }

        if let Err(e) = remove_firewall_rules() {
            warn!("windows: firewall cleanup warning: {e}");
            errors.push(format!("firewall: {e}"));
        }

        if errors.is_empty() {
            info!("windows: kill switch disabled cleanly");
            Ok(())
        } else {
            warn!(
                "windows: kill switch disabled with {} warnings",
                errors.len()
            );
            Ok(())
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Cleanup & Verification
    // ──────────────────────────────────────────────────────────────

    pub fn full_teardown(tun_alias: &str) -> Result<()> {
        info!("windows: full teardown for '{}'", tun_alias);
        disable_kill_switch()?;
        cleanup_routes(tun_alias)?;
        verify_teardown_clean(tun_alias);
        Ok(())
    }

    fn cleanup_wfp_filters() -> Result<()> {
        info!("windows: cleaning up WFP filters");
        if !super::admin::is_admin() {
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
                warn!("windows: WFP engine not available: {e}");
                Ok(())
            }
        }
    }

    pub fn cleanup_routes(tun_alias: &str) -> Result<()> {
        // SECURITY: Strict input validation to prevent path traversal and command injection
        if tun_alias.is_empty() {
            return Err(anyhow!("tunnel alias cannot be empty"));
        }
        if !tun_alias
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(anyhow!(
                "invalid tunnel alias: contains disallowed characters"
            ));
        }
        if tun_alias.len() > 255 {
            return Err(anyhow!("tunnel alias exceeds maximum length"));
        }
        if tun_alias.contains('\\') || tun_alias.contains('/') || tun_alias.contains("..") {
            return Err(anyhow!("invalid tunnel alias: path separator detected"));
        }

        info!("windows: cleaning up routes for '{}'", tun_alias);
        let escaped_alias = powershell_escape(tun_alias);
        let script = format!(
            "$params = @{{Name='{}'; ErrorAction='SilentlyContinue'}}; \
             $routes = Get-NetRoute @params; \
             if ($routes) {{ $routes | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }}; \
             Write-Output 'SUCCESS'",
            escaped_alias
        );
        run_powershell(&script)
    }

    pub fn verify_teardown_clean(tun_alias: &str) -> Vec<String> {
        info!("windows: verifying teardown is clean for '{}'", tun_alias);
        let mut issues = Vec::new();

        let check_routes = format!(
            "$routes = Get-NetRoute -InterfaceAlias '{}' -ErrorAction SilentlyContinue; \
             if ($routes) {{ Write-Output \"LEAKED_ROUTES: $($routes.Count)\" }}",
            tun_alias
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
            info!("windows: teardown verification passed");
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
        use tracing::info;

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
            info!(
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
            info!(
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
            let path_str = path.to_string_lossy();
            let path_for_write = if cfg!(windows) && !path_str.starts_with(r"\\?\") {
                match dunce::canonicalize(path) {
                    Ok(canon) => {
                        let canon_str = canon.to_string_lossy();
                        if canon_str.len() > 240 {
                            format!(r"\\?\{}", canon_str)
                        } else {
                            canon_str.to_string()
                        }
                    }
                    Err(_) => {
                        if path_str.len() > 240 {
                            format!(
                                r"\\?\{}",
                                std::fs::canonicalize(".")
                                    .unwrap_or(path.into())
                                    .parent()
                                    .unwrap_or_else(|| std::path::Path::new("."))
                                    .join(path)
                                    .to_string_lossy()
                            )
                        } else {
                            path_str.to_string()
                        }
                    }
                }
            } else {
                path_str.to_string()
            };
            std::fs::write(&path_for_write, &encrypted)
                .map_err(|e| anyhow!("failed to write encrypted key to {}: {e}", path.display()))?;
            info!("dpapi: stored encrypted key to {}", path.display());
            Ok(())
        }

        pub fn load_key(path: &std::path::Path) -> Result<Vec<u8>> {
            if !path.exists() {
                return Err(anyhow!("key file not found: {}", path.display()));
            }
            let path_str = path.to_string_lossy();
            let path_for_read = if cfg!(windows) && !path_str.starts_with(r"\\?\") {
                match dunce::canonicalize(path) {
                    Ok(canon) => {
                        let canon_str = canon.to_string_lossy();
                        if canon_str.len() > 240 {
                            format!(r"\\?\{}", canon_str)
                        } else {
                            canon_str.to_string()
                        }
                    }
                    Err(_) => path_str.to_string(),
                }
            } else {
                path_str.to_string()
            };
            let encrypted = std::fs::read(&path_for_read).map_err(|e| {
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

        let _: std::net::IpAddr = ip.parse().map_err(|e| anyhow!("invalid IP '{ip}': {e}"))?;

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
                "powershell failed (exit {}):\nstdout: {}\nstderr: {}",
                output.status.code().unwrap_or(-1),
                stdout.trim(),
                stderr.trim()
            ));
        }
        Ok(())
    }

    fn powershell_escape(input: &str) -> String {
        input.replace('\'', "''")
    }
}

#[cfg(not(windows))]
mod imp {
    use anyhow::{anyhow, Result};
    use std::net::IpAddr;
    use vpn_tun::TunConfig;

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

    pub fn enable_kill_switch(_: &super::KillSwitchConfig) -> Result<()> {
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
}

// ─══════════════════════════════════════════════════════════════
// Public API
// ─══════════════════════════════════════════════════════════════

use crate::KillSwitchConfig;
pub use imp::*;

// Re-export wfp_native module
#[cfg(windows)]
pub mod wfp_native {
    pub use super::super::wfp_native::*;
}

#[cfg(windows)]
pub mod admin {
    pub use super::super::admin::*;
}

// Re-export types
pub use crate::KillSwitchConfig;
pub use vpn_tun::TunConfig;
