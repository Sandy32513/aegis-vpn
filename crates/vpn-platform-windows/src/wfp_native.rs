// ═══════════════════════════════════════════════════════════════
// WFP Native Engine — Crash-safe, admin-aware, double-cleanup-proof
// ═══════════════════════════════════════════════════════════════

#[cfg(windows)]
mod native {
    use anyhow::{anyhow, Result};
    use std::{
        ffi::c_void,
        net::IpAddr,
        ptr::null_mut,
        sync::atomic::{AtomicBool, Ordering},
    };
    use tracing::{error, info, warn};

    use crate::KillSwitchConfig;

    // ──────────────────────────────────────────────────────────────
    // WFP FFI types
    // ──────────────────────────────────────────────────────────────

    const RPC_C_AUTHN_WINNT: u32 = 10;
    const FWPM_SESSION_FLAG_DYNAMIC: u32 = 0x00000001;

    const FWPM_LAYER_ALE_AUTH_CONNECT_V4: u32 = 0xed785420;
    const FWPM_LAYER_ALE_AUTH_CONNECT_V6: u32 = 0x66b1c999;

    const FWPM_CONDITION_IP_REMOTE_ADDRESS: u32 = 0x1a;
    const FWPM_CONDITION_IP_REMOTE_PORT: u32 = 0x1b;
    const FWPM_CONDITION_IP_PROTOCOL: u32 = 0x18;

    const FWP_ACTION_BLOCK: u32 = 0x00000001;
    const FWP_ACTION_PERMIT: u32 = 0x00000002;

    const FWP_MATCH_EQUAL: u32 = 0;

    const FWP_UINT8: u32 = 5;
    const FWP_UINT16: u32 = 7;
    const FWP_UINT32: u32 = 8;

    const FWP_EMPTY: u32 = 0;

    const IPPROTO_UDP: u8 = 17;

    // ──────────────────────────────────────────────────────────────
    // repr(C) FFI structs
    // ──────────────────────────────────────────────────────────────

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FwpmDisplayData0 {
        name: *mut u16,
        description: *mut u16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FwpmSession0 {
        session_key: *mut c_void,
        display_data: FwpmDisplayData0,
        flags: u32,
        txn_wait_timeout_in_ms: u32,
        process_id: u32,
        sid: *mut c_void,
        username: *mut u16,
        kernel_mode: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FwpmFilter0 {
        filter_key: *mut c_void,
        display_data: FwpmDisplayData0,
        flags: u32,
        provider_key: *mut c_void,
        provider_data: FwpmBlob,
        layer_key: FwpGuid,
        sub_layer_key: FwpGuid,
        weight: FwpValue,
        num_filter_conditions: u32,
        filter_conditions: *const FwpmFilterCondition0,
        action: FwpmAction,
        raw_context: u64,
        reserved: *mut c_void,
        filter_id: u64,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FwpGuid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FwpValue {
        r#type: u32,
        value: FwpValueUnion,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    union FwpValueUnion {
        uint8: u8,
        uint16: u16,
        uint32: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FwpmAction {
        r#type: u32,
        filter_type: FwpGuid,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FwpmBlob {
        size: u32,
        data: *mut u8,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FwpmFilterCondition0 {
        field_key: FwpGuid,
        match_type: u32,
        condition_value: FwpmConditionValue0,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FwpmConditionValue0 {
        r#type: u32,
        value: FwpValueUnion,
    }

    // ──────────────────────────────────────────────────────────────
    // WFP FFI declarations
    // ──────────────────────────────────────────────────────────────

    #[link(name = "fwpuclnt")]
    extern "system" {
        fn FwpmEngineOpen0(
            server_name: *const u16,
            authn_service: u32,
            auth_identity: *const c_void,
            session: *const FwpmSession0,
            engine_handle: *mut *mut c_void,
        ) -> u32;

        fn FwpmEngineClose0(engine_handle: *mut c_void) -> u32;

        fn FwpmFilterAdd0(
            engine_handle: *mut c_void,
            filter: *const FwpmFilter0,
            sd: *const c_void,
            id: *mut u64,
        ) -> u32;

        fn FwpmFilterDeleteById0(engine_handle: *mut c_void, id: u64) -> u32;

        fn FwpmTransactionBegin0(engine_handle: *mut c_void, flags: u32) -> u32;
        fn FwpmTransactionCommit0(engine_handle: *mut c_void, flags: u32) -> u32;
        fn FwpmTransactionAbort0(engine_handle: *mut c_void) -> u32;
    }

    // ──────────────────────────────────────────────────────────────
    // Persistent filter ID store — survives engine session drops
    // ──────────────────────────────────────────────────────────────

    use std::sync::Mutex;

    static INSTALLED_FILTER_IDS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
    static WFP_FILTERS_INSTALLED: AtomicBool = AtomicBool::new(false);

    /// Check if WFP filters are currently installed (cached state).
    pub fn wfp_filters_installed() -> bool {
        WFP_FILTERS_INSTALLED.load(Ordering::SeqCst)
    }

    // ──────────────────────────────────────────────────────────────
    // WfpEngine — crash-safe with NULL checks and AtomicBool cleaned
    // ──────────────────────────────────────────────────────────────

    pub struct WfpEngine {
        handle: *mut c_void,
        cleaned: AtomicBool,
    }

    // SAFETY: WFP engine handle is only used within &mut self methods.
    unsafe impl Send for WfpEngine {}

    impl WfpEngine {
        /// Open a WFP engine session with dynamic flags.
        /// Returns Err if the engine cannot be opened (e.g., non-admin).
        pub fn open() -> Result<Self> {
            let mut session_key_bytes = [0u8; 16];
            let session_key_ptr = session_key_bytes.as_mut_ptr() as *mut c_void;

            let session = FwpmSession0 {
                session_key: session_key_ptr,
                display_data: FwpmDisplayData0 {
                    name: null_mut(),
                    description: null_mut(),
                },
                flags: FWPM_SESSION_FLAG_DYNAMIC,
                txn_wait_timeout_in_ms: 5000,
                process_id: std::process::id(),
                sid: null_mut(),
                username: null_mut(),
                kernel_mode: 0,
            };

            let mut handle = null_mut();
            let status = unsafe {
                FwpmEngineOpen0(
                    std::ptr::null(),
                    RPC_C_AUTHN_WINNT,
                    std::ptr::null(),
                    &session,
                    &mut handle,
                )
            };
            if status != 0 || handle.is_null() {
                error!(
                    "wfp engine open failed: status=0x{status:08x} handle_null={}",
                    handle.is_null()
                );
                return Err(anyhow!(
                    "FwpmEngineOpen0 failed with status 0x{status:08x}. \
                     This typically requires administrator privileges."
                ));
            }

            info!("wfp engine opened successfully (handle={:p})", handle);

            Ok(Self {
                handle,
                cleaned: AtomicBool::new(false),
            })
        }

        /// Verify engine handle is valid before any operation.
        fn verify_handle(&self) -> Result<()> {
            if self.handle.is_null() {
                return Err(anyhow!(
                    "WFP engine handle is NULL — engine not opened or already closed"
                ));
            }
            if self.cleaned.load(Ordering::SeqCst) {
                return Err(anyhow!("WFP engine already cleaned up — cannot reuse"));
            }
            Ok(())
        }

        /// Install the kill switch WFP filters within a transaction.
        /// Handles partial failure with automatic transaction abort.
        pub fn install_kill_switch(&mut self, config: &KillSwitchConfig) -> Result<()> {
            self.verify_handle()?;

            // Check admin privilege before attempting WFP operations
            if !crate::admin::is_admin() {
                return Err(anyhow!(
                    "WFP kill switch requires administrator privileges. \
                     Run the daemon as Administrator or use --safe-mode."
                ));
            }

            info!(
                "wfp: installing kill switch: server={}:{} proto={}",
                config.server_ip, config.server_port, config.protocol
            );

            let status = unsafe { FwpmTransactionBegin0(self.handle, 0) };
            if status != 0 {
                error!("FwpmTransactionBegin0 failed: 0x{status:08x}");
                return Err(anyhow!(
                    "FwpmTransactionBegin0 failed with status 0x{status:08x}"
                ));
            }

            let result = self.install_filters_inner(config);

            match result {
                Ok(()) => {
                    let status = unsafe { FwpmTransactionCommit0(self.handle, 0) };
                    if status != 0 {
                        let mut ids = INSTALLED_FILTER_IDS
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        ids.clear();
                        error!("FwpmTransactionCommit0 failed: 0x{status:08x}");
                        return Err(anyhow!(
                            "FwpmTransactionCommit0 failed with status 0x{status:08x}"
                        ));
                    }
                    WFP_FILTERS_INSTALLED.store(true, Ordering::SeqCst);
                    let count = INSTALLED_FILTER_IDS
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .len();
                    info!("wfp: kill switch installed — {count} filters active");
                    Ok(())
                }
                Err(e) => {
                    let abort_status = unsafe { FwpmTransactionAbort0(self.handle) };
                    if abort_status != 0 {
                        warn!("FwpmTransactionAbort0 also failed: 0x{abort_status:08x}");
                    }
                    let mut ids = INSTALLED_FILTER_IDS
                        .lock()
                        .unwrap_or_else(|e| e.into_inner());
                    ids.clear();
                    Err(e)
                }
            }
        }

        fn install_filters_inner(&mut self, config: &KillSwitchConfig) -> Result<()> {
            self.verify_handle()?;

            // Filter 1: Default block all outbound IPv4
            let mut block_name = wide("Aegis VPN - Block All Outbound IPv4");
            let mut block_desc = wide("Default deny all outbound IPv4 connections");

            let block_all = FwpmFilter0 {
                filter_key: null_mut(),
                display_data: FwpmDisplayData0 {
                    name: block_name.as_mut_ptr(),
                    description: block_desc.as_mut_ptr(),
                },
                flags: 0,
                provider_key: null_mut(),
                provider_data: FwpmBlob {
                    size: 0,
                    data: null_mut(),
                },
                layer_key: fwpm_guid(FWPM_LAYER_ALE_AUTH_CONNECT_V4),
                sub_layer_key: zero_guid(),
                weight: FwpValue {
                    r#type: FWP_EMPTY,
                    value: FwpValueUnion { uint32: 0 },
                },
                num_filter_conditions: 0,
                filter_conditions: null_mut(),
                action: FwpmAction {
                    r#type: FWP_ACTION_BLOCK,
                    filter_type: zero_guid(),
                },
                raw_context: 0,
                reserved: null_mut(),
                filter_id: 0,
            };

            let mut filter_id: u64 = 0;
            let status = unsafe {
                FwpmFilterAdd0(self.handle, &block_all, std::ptr::null(), &mut filter_id)
            };
            if status != 0 {
                error!("wfp block-all-v4 filter add failed: 0x{status:08x}");
                return Err(anyhow!(
                    "WFP block-all-v4 filter failed with status 0x{status:08x}"
                ));
            }
            INSTALLED_FILTER_IDS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(filter_id);
            info!("wfp filter added: block-all-v4 (id={filter_id})");

            // Filter 2: Default block all outbound IPv6
            let mut block6_name = wide("Aegis VPN - Block All Outbound IPv6");
            let mut block6_desc = wide("Default deny all outbound IPv6 connections");

            let block_all_v6 = FwpmFilter0 {
                filter_key: null_mut(),
                display_data: FwpmDisplayData0 {
                    name: block6_name.as_mut_ptr(),
                    description: block6_desc.as_mut_ptr(),
                },
                flags: 0,
                provider_key: null_mut(),
                provider_data: FwpmBlob {
                    size: 0,
                    data: null_mut(),
                },
                layer_key: fwpm_guid(FWPM_LAYER_ALE_AUTH_CONNECT_V6),
                sub_layer_key: zero_guid(),
                weight: FwpValue {
                    r#type: FWP_EMPTY,
                    value: FwpValueUnion { uint32: 0 },
                },
                num_filter_conditions: 0,
                filter_conditions: null_mut(),
                action: FwpmAction {
                    r#type: FWP_ACTION_BLOCK,
                    filter_type: zero_guid(),
                },
                raw_context: 0,
                reserved: null_mut(),
                filter_id: 0,
            };

            let mut filter_id_v6: u64 = 0;
            let status = unsafe {
                FwpmFilterAdd0(
                    self.handle,
                    &block_all_v6,
                    std::ptr::null(),
                    &mut filter_id_v6,
                )
            };
            if status != 0 {
                error!("wfp block-all-v6 filter add failed: 0x{status:08x}");
                return Err(anyhow!(
                    "WFP block-all-v6 filter failed with status 0x{status:08x}"
                ));
            }
            INSTALLED_FILTER_IDS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(filter_id_v6);
            info!("wfp filter added: block-all-v6 (id={filter_id_v6})");

            // Filter 3: Permit VPN server UDP endpoint
            self.add_permit_server_filter(config.server_ip, config.server_port)?;

            // Filter 4: Permit loopback traffic
            self.add_permit_loopback_filter()?;

            Ok(())
        }

        fn add_permit_server_filter(&mut self, server_ip: IpAddr, server_port: u16) -> Result<()> {
            self.verify_handle()?;

            let v4 = match server_ip {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => {
                    warn!("wfp: IPv6 server endpoint not yet supported in WFP filter — skipping permit rule");
                    return Ok(());
                }
            };

            let ip_be = u32::from(v4).to_be();
            let condition_addr = FwpmFilterCondition0 {
                field_key: fwpm_guid(FWPM_CONDITION_IP_REMOTE_ADDRESS),
                match_type: FWP_MATCH_EQUAL,
                condition_value: FwpmConditionValue0 {
                    r#type: FWP_UINT32,
                    value: FwpValueUnion { uint32: ip_be },
                },
            };

            let port_be = server_port.to_be();
            let condition_port = FwpmFilterCondition0 {
                field_key: fwpm_guid(FWPM_CONDITION_IP_REMOTE_PORT),
                match_type: FWP_MATCH_EQUAL,
                condition_value: FwpmConditionValue0 {
                    r#type: FWP_UINT16,
                    value: FwpValueUnion { uint16: port_be },
                },
            };

            let condition_proto = FwpmFilterCondition0 {
                field_key: fwpm_guid(FWPM_CONDITION_IP_PROTOCOL),
                match_type: FWP_MATCH_EQUAL,
                condition_value: FwpmConditionValue0 {
                    r#type: FWP_UINT8,
                    value: FwpValueUnion { uint8: IPPROTO_UDP },
                },
            };

            let conditions = [condition_addr, condition_port, condition_proto];

            let mut filter_name = wide("Aegis VPN - Permit Server Endpoint");
            let mut filter_desc = wide(&format!(
                "Allow UDP traffic to VPN server {server_ip}:{server_port}"
            ));

            let permit_filter = FwpmFilter0 {
                filter_key: null_mut(),
                display_data: FwpmDisplayData0 {
                    name: filter_name.as_mut_ptr(),
                    description: filter_desc.as_mut_ptr(),
                },
                flags: 0,
                provider_key: null_mut(),
                provider_data: FwpmBlob {
                    size: 0,
                    data: null_mut(),
                },
                layer_key: fwpm_guid(FWPM_LAYER_ALE_AUTH_CONNECT_V4),
                sub_layer_key: zero_guid(),
                weight: FwpValue {
                    r#type: FWP_UINT8,
                    value: FwpValueUnion { uint8: 15 },
                },
                num_filter_conditions: conditions.len() as u32,
                filter_conditions: conditions.as_ptr(),
                action: FwpmAction {
                    r#type: FWP_ACTION_PERMIT,
                    filter_type: zero_guid(),
                },
                raw_context: 0,
                reserved: null_mut(),
                filter_id: 0,
            };

            let mut filter_id: u64 = 0;
            let status = unsafe {
                FwpmFilterAdd0(
                    self.handle,
                    &permit_filter,
                    std::ptr::null(),
                    &mut filter_id,
                )
            };
            if status != 0 {
                error!("wfp permit-server filter add failed: 0x{status:08x}");
                return Err(anyhow!(
                    "WFP permit-server filter failed with status 0x{status:08x}"
                ));
            }
            INSTALLED_FILTER_IDS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(filter_id);
            info!(
                "wfp filter added: permit-server {}:{server_port} udp (id={filter_id})",
                server_ip
            );

            Ok(())
        }

        fn add_permit_loopback_filter(&mut self) -> Result<()> {
            self.verify_handle()?;

            let loopback_be: u32 = 0x7F000001u32.to_be();
            let condition = FwpmFilterCondition0 {
                field_key: fwpm_guid(FWPM_CONDITION_IP_REMOTE_ADDRESS),
                match_type: FWP_MATCH_EQUAL,
                condition_value: FwpmConditionValue0 {
                    r#type: FWP_UINT32,
                    value: FwpValueUnion {
                        uint32: loopback_be,
                    },
                },
            };

            let mut filter_name = wide("Aegis VPN - Permit Loopback");
            let mut filter_desc = wide("Allow loopback traffic for IPC");

            let permit_filter = FwpmFilter0 {
                filter_key: null_mut(),
                display_data: FwpmDisplayData0 {
                    name: filter_name.as_mut_ptr(),
                    description: filter_desc.as_mut_ptr(),
                },
                flags: 0,
                provider_key: null_mut(),
                provider_data: FwpmBlob {
                    size: 0,
                    data: null_mut(),
                },
                layer_key: fwpm_guid(FWPM_LAYER_ALE_AUTH_CONNECT_V4),
                sub_layer_key: zero_guid(),
                weight: FwpValue {
                    r#type: FWP_UINT8,
                    value: FwpValueUnion { uint8: 15 },
                },
                num_filter_conditions: 1,
                filter_conditions: &condition,
                action: FwpmAction {
                    r#type: FWP_ACTION_PERMIT,
                    filter_type: zero_guid(),
                },
                raw_context: 0,
                reserved: null_mut(),
                filter_id: 0,
            };

            let mut filter_id: u64 = 0;
            let status = unsafe {
                FwpmFilterAdd0(
                    self.handle,
                    &permit_filter,
                    std::ptr::null(),
                    &mut filter_id,
                )
            };
            if status != 0 {
                error!("wfp permit-loopback filter add failed: 0x{status:08x}");
                return Err(anyhow!(
                    "WFP permit-loopback filter failed with status 0x{status:08x}"
                ));
            }
            INSTALLED_FILTER_IDS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(filter_id);
            info!("wfp filter added: permit-loopback (id={filter_id})");

            Ok(())
        }

        /// Remove all filters tracked in the static store.
        /// Idempotent — safe to call multiple times.
        /// Protected by AtomicBool `cleaned` to prevent double cleanup.
        pub fn remove_filters(&mut self) -> Result<()> {
            // Already cleaned — no-op
            if self.cleaned.swap(true, Ordering::SeqCst) {
                info!("wfp: filters already cleaned (idempotent skip)");
                return Ok(());
            }

            self.verify_handle()?;

            let filter_ids: Vec<u64> = {
                let mut ids = INSTALLED_FILTER_IDS
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                ids.drain(..).collect()
            };

            if filter_ids.is_empty() {
                info!("wfp: no filters to remove");
                WFP_FILTERS_INSTALLED.store(false, Ordering::SeqCst);
                return Ok(());
            }

            info!("wfp: removing {} filters", filter_ids.len());

            let mut errors = Vec::new();
            for id in &filter_ids {
                let status = unsafe { FwpmFilterDeleteById0(self.handle, *id) };
                if status != 0 {
                    // 0x80070002 = ERROR_FILE_NOT_FOUND (already removed)
                    if status == 0x80070002 {
                        info!("wfp filter {id} already removed (not found)");
                    } else {
                        let msg = format!(
                            "FwpmFilterDeleteById0({id}) failed with status 0x{status:08x}"
                        );
                        warn!("{msg}");
                        errors.push(msg);
                    }
                } else {
                    info!("wfp filter removed: id={id}");
                }
            }

            WFP_FILTERS_INSTALLED.store(false, Ordering::SeqCst);

            if errors.is_empty() {
                info!("wfp: all filters removed successfully");
                Ok(())
            } else {
                Err(anyhow!(
                    "wfp filter removal had {} errors: {}",
                    errors.len(),
                    errors.join("; ")
                ))
            }
        }
    }

    // ──────────────────────────────────────────────────────────────
    // CRASH-SAFE DROP — never panics, logs errors, respects cleaned flag
    // ──────────────────────────────────────────────────────────────

    impl Drop for WfpEngine {
        fn drop(&mut self) {
            // If already explicitly cleaned, just close the handle
            if self.cleaned.load(Ordering::SeqCst) {
                if !self.handle.is_null() {
                    let _ = unsafe { FwpmEngineClose0(self.handle) };
                    self.handle = null_mut();
                }
                return;
            }

            // Engine is closed — filters persist with FWPM_SESSION_FLAG_DYNAMIC.
            // Cleanup happens via explicit remove_filters() or cleanup_wfp_filters().
            if !self.handle.is_null() {
                let status = unsafe { FwpmEngineClose0(self.handle) };
                if status != 0 {
                    // Log but never panic in Drop
                    let _ = tracing::warn!("wfp engine close returned non-zero: 0x{status:08x}");
                }
                self.handle = null_mut();
            }
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────

    fn wide(value: &str) -> Vec<u16> {
        use std::ffi::OsStr;
        use std::os::windows::ffi::OsStrExt;
        OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    fn fwpm_guid(value: u32) -> FwpGuid {
        FwpGuid {
            data1: value,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        }
    }

    fn zero_guid() -> FwpGuid {
        FwpGuid {
            data1: 0,
            data2: 0,
            data3: 0,
            data4: [0; 8],
        }
    }
}

// ──────────────────────────────────────────────────────────────
// Non-Windows stub
// ──────────────────────────────────────────────────────────────

#[cfg(not(windows))]
mod native {
    use anyhow::{anyhow, Result};

    use crate::KillSwitchConfig;

    pub struct WfpEngine;

    impl WfpEngine {
        pub fn open() -> Result<Self> {
            Err(anyhow!("native WFP is only available on Windows"))
        }

        pub fn install_kill_switch(&mut self, _: &KillSwitchConfig) -> Result<()> {
            Err(anyhow!("native WFP is only available on Windows"))
        }

        pub fn remove_filters(&mut self) -> Result<()> {
            Err(anyhow!("native WFP is only available on Windows"))
        }
    }

    pub fn wfp_filters_installed() -> bool {
        false
    }
}

pub use native::wfp_filters_installed;
pub use native::WfpEngine;
