//! Windows platform integration for Aegis VPN.

pub mod admin;
pub mod service_installer;
pub mod wfp_native;

use anyhow::{anyhow, Result};
use std::{net::IpAddr, path::PathBuf, process::Command};

pub use vpn_tun::TunConfig;

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
    pub fn apply_filters(spec: &WfpFilterSpec) -> Result<()> {
        validate_tunnel_alias(&spec.tunnel_alias)?;
        validate_server_endpoint(spec.remote_server_ip, spec.remote_server_port)?;
        wfp_native::install_kill_switch(&KillSwitchConfig {
            tun_alias: spec.tunnel_alias.clone(),
            server_ip: spec.remote_server_ip,
            server_port: spec.remote_server_port,
            protocol: "UDP".to_string(),
        })
    }

    pub fn remove_filters() -> Result<()> {
        wfp_native::remove_filters()
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use libloading::Library;
    use std::{
        ffi::{c_void, OsStr},
        io,
        os::windows::ffi::OsStrExt,
        ptr::{null, null_mut},
        sync::Arc,
    };
    use tracing::info;
    use vpn_tun::TunDevice;

    type WintunAdapterHandle = *mut c_void;
    type WintunSessionHandle = *mut c_void;

    type WintunCreateAdapter =
        unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> WintunAdapterHandle;
    type WintunOpenAdapter = unsafe extern "system" fn(*const u16) -> WintunAdapterHandle;
    type WintunCloseAdapter = unsafe extern "system" fn(WintunAdapterHandle);
    type WintunStartSession =
        unsafe extern "system" fn(WintunAdapterHandle, u32) -> WintunSessionHandle;
    type WintunEndSession = unsafe extern "system" fn(WintunSessionHandle);
    type WintunReceivePacket = unsafe extern "system" fn(WintunSessionHandle, *mut u32) -> *mut u8;
    type WintunReleaseReceivePacket = unsafe extern "system" fn(WintunSessionHandle, *const u8);
    type WintunAllocateSendPacket = unsafe extern "system" fn(WintunSessionHandle, u32) -> *mut u8;
    type WintunSendPacket = unsafe extern "system" fn(WintunSessionHandle, *const u8);

    struct WintunApi {
        _library: Library,
        create_adapter: WintunCreateAdapter,
        open_adapter: WintunOpenAdapter,
        close_adapter: WintunCloseAdapter,
        start_session: WintunStartSession,
        end_session: WintunEndSession,
        receive_packet: WintunReceivePacket,
        release_receive_packet: WintunReleaseReceivePacket,
        allocate_send_packet: WintunAllocateSendPacket,
        send_packet: WintunSendPacket,
    }

    impl WintunApi {
        fn load(dll_path: Option<&str>) -> Result<Arc<Self>> {
            let path = resolve_wintun_dll(dll_path)?;
            let library = unsafe { Library::new(&path) }
                .map_err(|e| anyhow!("failed to load {}: {e}", path.display()))?;

            unsafe fn symbol<T: Copy>(library: &Library, name: &[u8]) -> Result<T> {
                Ok(*library.get::<T>(name)?)
            }

            let create_adapter = unsafe { symbol(&library, b"WintunCreateAdapter\0")? };
            let open_adapter = unsafe { symbol(&library, b"WintunOpenAdapter\0")? };
            let close_adapter = unsafe { symbol(&library, b"WintunCloseAdapter\0")? };
            let start_session = unsafe { symbol(&library, b"WintunStartSession\0")? };
            let end_session = unsafe { symbol(&library, b"WintunEndSession\0")? };
            let receive_packet = unsafe { symbol(&library, b"WintunReceivePacket\0")? };
            let release_receive_packet =
                unsafe { symbol(&library, b"WintunReleaseReceivePacket\0")? };
            let allocate_send_packet = unsafe { symbol(&library, b"WintunAllocateSendPacket\0")? };
            let send_packet = unsafe { symbol(&library, b"WintunSendPacket\0")? };

            Ok(Arc::new(Self {
                _library: library,
                create_adapter,
                open_adapter,
                close_adapter,
                start_session,
                end_session,
                receive_packet,
                release_receive_packet,
                allocate_send_packet,
                send_packet,
            }))
        }
    }

    pub struct WindowsTun {
        api: Arc<WintunApi>,
        adapter: WintunAdapterHandle,
        session: WintunSessionHandle,
        name: String,
        mtu: u32,
    }

    unsafe impl Send for WindowsTun {}

    impl WindowsTun {
        fn create(config: &TunConfig, dll_path: Option<&str>) -> Result<Self> {
            let api = WintunApi::load(dll_path)?;
            let adapter_name = wide(&config.name);
            let tunnel_type = wide("AegisVPN");

            let mut adapter = unsafe { (api.open_adapter)(adapter_name.as_ptr()) };
            if adapter.is_null() {
                adapter = unsafe {
                    (api.create_adapter)(adapter_name.as_ptr(), tunnel_type.as_ptr(), null())
                };
            }
            if adapter.is_null() {
                return Err(anyhow!(
                    "Wintun adapter open/create failed for '{}': {}",
                    config.name,
                    io::Error::last_os_error()
                ));
            }

            let session = unsafe { (api.start_session)(adapter, 0x400000) };
            if session.is_null() {
                let err = io::Error::last_os_error();
                unsafe { (api.close_adapter)(adapter) };
                return Err(anyhow!("WintunStartSession failed: {err}"));
            }

            info!("wintun: adapter '{}' opened", config.name);
            Ok(Self {
                api,
                adapter,
                session,
                name: config.name.clone(),
                mtu: config.mtu,
            })
        }
    }

    impl TunDevice for WindowsTun {
        fn name(&self) -> &str {
            &self.name
        }

        fn mtu(&self) -> u32 {
            self.mtu
        }

        fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut packet_size = 0u32;
            let packet = unsafe { (self.api.receive_packet)(self.session, &mut packet_size) };
            if packet.is_null() {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(259) {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, err));
                }
                return Err(err);
            }

            let packet_size = packet_size as usize;
            if packet_size > buf.len() {
                unsafe { (self.api.release_receive_packet)(self.session, packet) };
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "packet size {packet_size} exceeds buffer size {}",
                        buf.len()
                    ),
                ));
            }

            unsafe {
                std::ptr::copy_nonoverlapping(packet, buf.as_mut_ptr(), packet_size);
                (self.api.release_receive_packet)(self.session, packet);
            }
            Ok(packet_size)
        }

        fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
            if packet.is_empty() || packet.len() > u32::MAX as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "packet size is outside Wintun bounds",
                ));
            }

            let send_packet =
                unsafe { (self.api.allocate_send_packet)(self.session, packet.len() as u32) };
            if send_packet.is_null() {
                return Err(io::Error::last_os_error());
            }

            unsafe {
                std::ptr::copy_nonoverlapping(packet.as_ptr(), send_packet, packet.len());
                (self.api.send_packet)(self.session, send_packet);
            }
            Ok(())
        }
    }

    impl Drop for WindowsTun {
        fn drop(&mut self) {
            if !self.session.is_null() {
                unsafe { (self.api.end_session)(self.session) };
                self.session = null_mut();
            }
            if !self.adapter.is_null() {
                unsafe { (self.api.close_adapter)(self.adapter) };
                self.adapter = null_mut();
            }
        }
    }

    pub fn create_tun(config: &TunConfig, dll_path: Option<&str>) -> Result<WindowsTun> {
        if !admin::is_admin() {
            return Err(anyhow!(
                "Wintun adapter creation requires administrator privileges"
            ));
        }
        validate_tun_config(config)?;
        WindowsTun::create(config, dll_path)
    }

    fn resolve_wintun_dll(dll_path: Option<&str>) -> Result<PathBuf> {
        let path = match dll_path {
            Some(value) => PathBuf::from(value),
            None => std::env::current_exe()?
                .parent()
                .ok_or_else(|| anyhow!("cannot resolve current executable directory"))?
                .join("wintun.dll"),
        };

        if !path.is_absolute() {
            return Err(anyhow!(
                "wintun.dll path must be absolute to prevent DLL search hijacking"
            ));
        }
        if !path.is_file() {
            return Err(anyhow!("wintun.dll not found: {}", path.display()));
        }
        Ok(path)
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    pub mod dpapi {
        use anyhow::{anyhow, Result};
        use std::{ffi::c_void, path::Path, ptr::null_mut};
        use tracing::info;

        #[repr(C)]
        struct DataBlob {
            cb_data: u32,
            pb_data: *mut u8,
        }

        const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
        const AEGIS_DPAPI_ENTROPY: &[u8] = b"Aegis-VPN-Key-Storage-2026";

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

        fn entropy_blob() -> DataBlob {
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
            let entropy = entropy_blob();
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
                return Err(anyhow!(
                    "CryptProtectData failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if data_out.pb_data.is_null() || data_out.cb_data == 0 {
                return Err(anyhow!("CryptProtectData returned empty output"));
            }

            let encrypted = unsafe {
                std::slice::from_raw_parts(data_out.pb_data, data_out.cb_data as usize).to_vec()
            };
            unsafe {
                std::ptr::write_bytes(data_out.pb_data, 0, data_out.cb_data as usize);
                LocalFree(data_out.pb_data as *mut c_void);
            }
            Ok(encrypted)
        }

        pub fn unprotect(encrypted: &[u8]) -> Result<Vec<u8>> {
            if encrypted.len() < 16 {
                return Err(anyhow!(
                    "encrypted data too short ({} bytes), likely corrupted",
                    encrypted.len()
                ));
            }

            let data_in = DataBlob {
                cb_data: encrypted.len() as u32,
                pb_data: encrypted.as_ptr() as *mut u8,
            };
            let entropy = entropy_blob();
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
                return Err(anyhow!(
                    "CryptUnprotectData failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if data_out.pb_data.is_null() || data_out.cb_data == 0 {
                return Err(anyhow!("CryptUnprotectData returned empty output"));
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
            }
            Ok(decrypted)
        }

        pub fn store_key(path: &Path, key_data: &[u8]) -> Result<()> {
            let encrypted = protect(key_data)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, encrypted)?;
            harden_key_file_permissions(path)?;
            info!("dpapi: stored encrypted key at {}", path.display());
            Ok(())
        }

        pub fn load_key(path: &Path) -> Result<Vec<u8>> {
            if !path.is_file() {
                return Err(anyhow!("key file not found: {}", path.display()));
            }
            let encrypted = std::fs::read(path)?;
            if encrypted.is_empty() {
                return Err(anyhow!("key file is empty: {}", path.display()));
            }
            unprotect(&encrypted)
        }

        fn harden_key_file_permissions(path: &Path) -> Result<()> {
            let path = path
                .canonicalize()
                .map_err(|e| anyhow!("failed to canonicalize key path {}: {e}", path.display()))?;
            let escaped = super::powershell_escape(&path.display().to_string());
            let script = format!(
                "$path='{}'; \
                 $identity=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name; \
                 icacls $path /inheritance:r /grant:r \"$($identity):F\" '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null",
                escaped
            );
            super::run_powershell(&script)
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use std::io;
    use vpn_tun::TunDevice;

    pub struct WindowsTun {
        name: String,
        mtu: u32,
    }

    impl TunDevice for WindowsTun {
        fn name(&self) -> &str {
            &self.name
        }

        fn mtu(&self) -> u32 {
            self.mtu
        }

        fn read_packet(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Wintun is only available on Windows",
            ))
        }

        fn write_packet(&mut self, _: &[u8]) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Wintun is only available on Windows",
            ))
        }
    }

    pub fn create_tun(_: &TunConfig, _: Option<&str>) -> Result<WindowsTun> {
        Err(anyhow!(
            "windows platform support is only available on Windows"
        ))
    }

    pub mod dpapi {
        use anyhow::{anyhow, Result};
        use std::path::Path;

        pub fn protect(_: &[u8]) -> Result<Vec<u8>> {
            Err(anyhow!("DPAPI is only available on Windows"))
        }

        pub fn unprotect(_: &[u8]) -> Result<Vec<u8>> {
            Err(anyhow!("DPAPI is only available on Windows"))
        }

        pub fn store_key(_: &Path, _: &[u8]) -> Result<()> {
            Err(anyhow!("DPAPI is only available on Windows"))
        }

        pub fn load_key(_: &Path) -> Result<Vec<u8>> {
            Err(anyhow!("DPAPI is only available on Windows"))
        }
    }
}

pub use imp::create_tun;
pub use imp::dpapi;
pub use imp::WindowsTun;

pub fn configure_interface(config: &TunConfig) -> Result<()> {
    validate_tun_config(config)?;
    let (ip, prefix) = parse_cidr(&config.address_cidr)?;
    let escaped_name = powershell_escape(&config.name);
    let escaped_ip = powershell_escape(&ip.to_string());
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         $adapter = Get-NetAdapter -Name '{}' -ErrorAction Stop; \
         if (-not (Get-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress '{}' -ErrorAction SilentlyContinue)) {{ \
             New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress '{}' -PrefixLength {} -ErrorAction Stop | Out-Null \
         }}; \
         Set-NetIPInterface -InterfaceAlias $adapter.Name -NlMtuBytes {} -ErrorAction Stop | Out-Null",
        escaped_name, escaped_ip, escaped_ip, prefix, config.mtu
    );
    run_powershell(&script)
}

pub fn route_server_via_physical(server_ip: IpAddr) -> Result<()> {
    validate_server_ip(server_ip)?;
    let (default_prefix, destination_prefix, null_hop) = match server_ip {
        IpAddr::V4(_) => ("0.0.0.0/0", format!("{server_ip}/32"), "0.0.0.0"),
        IpAddr::V6(_) => ("::/0", format!("{server_ip}/128"), "::"),
    };

    let escaped_default = powershell_escape(default_prefix);
    let escaped_destination = powershell_escape(&destination_prefix);
    let escaped_null_hop = powershell_escape(null_hop);
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         $default = Get-NetRoute -DestinationPrefix '{}' -ErrorAction Stop | \
             Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1; \
         if ($null -eq $default) {{ throw 'No default route found' }}; \
         $existing = Get-NetRoute -DestinationPrefix '{}' -ErrorAction SilentlyContinue | \
             Where-Object {{ $_.InterfaceIndex -ne $default.ifIndex -or $_.NextHop -ne $default.NextHop }}; \
         if ($existing) {{ $existing | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }}; \
         if (-not (Get-NetRoute -DestinationPrefix '{}' -InterfaceIndex $default.ifIndex -ErrorAction SilentlyContinue | \
             Where-Object {{ $_.NextHop -eq $default.NextHop }})) {{ \
             New-NetRoute -DestinationPrefix '{}' -InterfaceIndex $default.ifIndex -NextHop $default.NextHop -RouteMetric 1 -ErrorAction Stop | Out-Null \
         }}; \
         if ($default.NextHop -eq '{}') {{ Write-Verbose 'Default route is on-link' }}",
        escaped_default,
        escaped_destination,
        escaped_destination,
        escaped_destination,
        escaped_null_hop
    );
    run_powershell(&script)
}

pub fn route_default_via_tun(tun_alias: &str) -> Result<()> {
    validate_tunnel_alias(tun_alias)?;
    let escaped_alias = powershell_escape(tun_alias);
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         $adapter = Get-NetAdapter -Name '{}' -ErrorAction Stop; \
         $ifIndex = $adapter.ifIndex; \
         Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue | \
             Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; \
         New-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceIndex $ifIndex -NextHop '0.0.0.0' -RouteMetric 5 -ErrorAction Stop | Out-Null; \
         if (Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue) {{ \
             Get-NetRoute -DestinationPrefix '::/0' -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue | \
                 Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; \
             New-NetRoute -DestinationPrefix '::/0' -InterfaceIndex $ifIndex -NextHop '::' -RouteMetric 5 -ErrorAction Stop | Out-Null \
         }}",
        escaped_alias
    );
    run_powershell(&script)
}

pub fn enable_kill_switch(config: &KillSwitchConfig) -> Result<()> {
    validate_kill_switch_config(config)?;
    if !admin::is_admin() {
        return Err(anyhow!(
            "kill switch changes require administrator privileges; refusing unsafe non-admin fallback"
        ));
    }

    if native_wfp_opt_in_enabled() {
        match wfp_native::install_kill_switch(config) {
            Ok(()) => Ok(()),
            Err(e) => {
                tracing::warn!("native WFP kill switch failed, using firewall fallback: {e}");
                enable_firewall_kill_switch(config)
            }
        }
    } else {
        tracing::warn!(
            "native WFP kill switch is disabled until interface-scoped packet validation is complete; using firewall fallback"
        );
        enable_firewall_kill_switch(config)
    }
}

pub fn disable_kill_switch() -> Result<()> {
    let mut errors = Vec::new();
    if let Err(e) = wfp_native::remove_filters() {
        errors.push(format!("wfp: {e}"));
    }
    if let Err(e) = remove_firewall_rules() {
        errors.push(format!("firewall: {e}"));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!("kill switch cleanup failed: {}", errors.join("; ")))
    }
}

pub fn full_teardown(tun_alias: &str) -> Result<()> {
    validate_tunnel_alias(tun_alias)?;
    disable_kill_switch()?;
    cleanup_routes(tun_alias)?;
    let issues = verify_teardown_clean(tun_alias);
    if issues.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(
            "teardown verification failed: {}",
            issues.join("; ")
        ))
    }
}

pub fn cleanup_routes(tun_alias: &str) -> Result<()> {
    validate_tunnel_alias(tun_alias)?;
    let escaped_alias = powershell_escape(tun_alias);
    let script = format!(
        "$routes = Get-NetRoute -InterfaceAlias '{}' -ErrorAction SilentlyContinue; \
         if ($routes) {{ $routes | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }}",
        escaped_alias
    );
    run_powershell(&script)
}

pub fn verify_teardown_clean(tun_alias: &str) -> Vec<String> {
    if let Err(e) = validate_tunnel_alias(tun_alias) {
        return vec![format!("invalid tunnel alias: {e}")];
    }

    let escaped_alias = powershell_escape(tun_alias);
    let mut issues = Vec::new();
    let route_script = format!(
        "$routes = Get-NetRoute -InterfaceAlias '{}' -ErrorAction SilentlyContinue; \
         if ($routes) {{ Write-Output \"LEAKED_ROUTES:$($routes.Count)\" }}",
        escaped_alias
    );
    if let Ok(output) = powershell_output(&route_script) {
        if output.contains("LEAKED_ROUTES") {
            issues.push(output.trim().to_string());
        }
    }

    let firewall_script =
        "$rules = Get-NetFirewallRule -Group 'AegisVPN' -ErrorAction SilentlyContinue; \
         if ($rules) { Write-Output \"LEAKED_FIREWALL_RULES:$($rules.Count)\" }";
    if let Ok(output) = powershell_output(firewall_script) {
        if output.contains("LEAKED_FIREWALL_RULES") {
            issues.push(output.trim().to_string());
        }
    }

    if wfp_native::wfp_filters_installed() {
        issues.push("WFP_FILTER_STATE_STILL_INSTALLED".to_string());
    }
    issues
}

fn enable_firewall_kill_switch(config: &KillSwitchConfig) -> Result<()> {
    let _ = remove_firewall_rules();
    let proto = normalize_protocol(&config.protocol)?;
    let ip = powershell_escape(&config.server_ip.to_string());
    let port = config.server_port.to_string();
    let alias = powershell_escape(&config.tun_alias);
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         $backupKey='HKLM:\\Software\\AegisVPN\\Firewall'; \
         if (-not (Test-Path $backupKey)) {{ New-Item -Path $backupKey -Force | Out-Null }}; \
         $profiles = Get-NetFirewallProfile | Select-Object Name,DefaultOutboundAction; \
         if (-not (Get-ItemProperty -Path $backupKey -Name ProfileDefaultsJson -ErrorAction SilentlyContinue)) {{ \
             New-ItemProperty -Path $backupKey -Name ProfileDefaultsJson -Value ($profiles | ConvertTo-Json -Compress) -PropertyType String -Force | Out-Null \
         }}; \
         Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block; \
         New-NetFirewallRule -DisplayName 'AegisVPN Allow Tunnel Endpoint' -Group 'AegisVPN' -Direction Outbound -Action Allow -Protocol '{}' -RemoteAddress '{}' -RemotePort '{}' | Out-Null; \
         New-NetFirewallRule -DisplayName 'AegisVPN Allow Tunnel Interface' -Group 'AegisVPN' -Direction Outbound -Action Allow -InterfaceAlias '{}' | Out-Null; \
         New-NetFirewallRule -DisplayName 'AegisVPN Allow Loopback' -Group 'AegisVPN' -Direction Outbound -Action Allow -RemoteAddress 127.0.0.1,::1 | Out-Null",
        proto, ip, port, alias
    );
    run_powershell(&script)
}

fn native_wfp_opt_in_enabled() -> bool {
    std::env::var("AEGIS_ENABLE_NATIVE_WFP")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn remove_firewall_rules() -> Result<()> {
    let script =
        "$ErrorActionPreference='Stop'; \
         Get-NetFirewallRule -Group 'AegisVPN' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; \
         $backupKey='HKLM:\\Software\\AegisVPN\\Firewall'; \
         $backup = Get-ItemProperty -Path $backupKey -Name ProfileDefaultsJson -ErrorAction SilentlyContinue; \
         if ($backup -and $backup.ProfileDefaultsJson) { \
             $profiles = $backup.ProfileDefaultsJson | ConvertFrom-Json; \
             foreach ($profile in @($profiles)) { \
                 Set-NetFirewallProfile -Profile $profile.Name -DefaultOutboundAction $profile.DefaultOutboundAction \
             }; \
             Remove-ItemProperty -Path $backupKey -Name ProfileDefaultsJson -ErrorAction SilentlyContinue \
         }";
    run_powershell(script)
}

fn validate_tun_config(config: &TunConfig) -> Result<()> {
    validate_tunnel_alias(&config.name)?;
    parse_cidr(&config.address_cidr)?;
    if !(576..=9000).contains(&config.mtu) {
        return Err(anyhow!("MTU must be between 576 and 9000"));
    }
    Ok(())
}

fn validate_kill_switch_config(config: &KillSwitchConfig) -> Result<()> {
    validate_tunnel_alias(&config.tun_alias)?;
    validate_server_endpoint(config.server_ip, config.server_port)?;
    normalize_protocol(&config.protocol)?;
    Ok(())
}

fn validate_tunnel_alias(alias: &str) -> Result<()> {
    if alias.is_empty() || alias.len() > 128 {
        return Err(anyhow!("tunnel alias must be 1-128 characters"));
    }
    if !alias
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(anyhow!(
            "tunnel alias may only contain ASCII letters, digits, dash, or underscore"
        ));
    }
    Ok(())
}

fn validate_server_endpoint(ip: IpAddr, port: u16) -> Result<()> {
    validate_server_ip(ip)?;
    if port == 0 {
        return Err(anyhow!("server port cannot be zero"));
    }
    Ok(())
}

fn validate_server_ip(ip: IpAddr) -> Result<()> {
    match ip {
        IpAddr::V4(v4) if v4.is_unspecified() || v4.is_loopback() || v4.is_multicast() => {
            Err(anyhow!("invalid IPv4 server address: {v4}"))
        }
        IpAddr::V6(v6) if v6.is_unspecified() || v6.is_loopback() || v6.is_multicast() => {
            Err(anyhow!("invalid IPv6 server address: {v6}"))
        }
        _ => Ok(()),
    }
}

fn normalize_protocol(protocol: &str) -> Result<&'static str> {
    match protocol.trim().to_ascii_uppercase().as_str() {
        "TCP" => Ok("TCP"),
        "UDP" => Ok("UDP"),
        _ => Err(anyhow!("protocol must be TCP or UDP")),
    }
}

fn parse_cidr(value: &str) -> Result<(IpAddr, u8)> {
    let mut parts = value.split('/');
    let ip = parts
        .next()
        .ok_or_else(|| anyhow!("missing IP address in CIDR"))?
        .trim()
        .parse::<IpAddr>()?;
    let default_prefix = match ip {
        IpAddr::V4(_) => 24,
        IpAddr::V6(_) => 64,
    };
    let prefix = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::parse::<u8>)
        .transpose()?
        .unwrap_or(default_prefix);
    if parts.next().is_some() {
        return Err(anyhow!("CIDR contains too many '/' separators"));
    }
    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max_prefix {
        return Err(anyhow!(
            "prefix length {prefix} exceeds maximum {max_prefix}"
        ));
    }
    Ok((ip, prefix))
}

fn run_powershell(script: &str) -> Result<()> {
    let output = powershell_command(script).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "PowerShell failed (exit {}): stdout={} stderr={}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn powershell_output(script: &str) -> Result<String> {
    let output = powershell_command(script).output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "PowerShell failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn powershell_command(script: &str) -> Command {
    let mut command = Command::new(system32_path(r"WindowsPowerShell\v1.0\powershell.exe"));
    command.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
    ]);
    command
}

fn powershell_escape(input: &str) -> String {
    input.replace('\'', "''")
}

fn system32_path(relative: &str) -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32")
        .join(relative)
}
