//! Native Windows Filtering Platform support.

#[cfg(windows)]
mod native {
    use anyhow::{anyhow, Result};
    use std::{
        ffi::{c_void, OsStr},
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        os::windows::ffi::OsStrExt,
        ptr::{null, null_mut},
        sync::{
            atomic::{AtomicBool, Ordering},
            RwLock,
        },
    };
    use tracing::{info, warn};
    use windows_sys::{
        core::GUID,
        Win32::{
            Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::*,
            System::Rpc::RPC_C_AUTHN_WINNT,
        },
    };

    use crate::KillSwitchConfig;

    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_UDP: u8 = 17;
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const HRESULT_FILE_NOT_FOUND: u32 = 0x80070002;
    const FWP_E_FILTER_NOT_FOUND: u32 = 0x80320003;

    static FILTER_IDS: RwLock<Vec<u64>> = RwLock::new(Vec::new());
    static FILTERS_INSTALLED: AtomicBool = AtomicBool::new(false);

    pub struct WfpEngine {
        handle: HANDLE,
    }

    unsafe impl Send for WfpEngine {}

    impl WfpEngine {
        pub fn open() -> Result<Self> {
            if !crate::admin::is_admin() {
                return Err(anyhow!(
                    "WFP engine access requires administrator privileges"
                ));
            }

            let mut session_name = wide("Aegis VPN dynamic WFP session");
            let session = FWPM_SESSION0 {
                sessionKey: GUID::from_u128(0x2f3b3d74_289d_4cb5_9f18_0539db177a01),
                displayData: FWPM_DISPLAY_DATA0 {
                    name: session_name.as_mut_ptr(),
                    description: null_mut(),
                },
                flags: FWPM_SESSION_FLAG_DYNAMIC,
                txnWaitTimeoutInMSec: 5000,
                processId: std::process::id(),
                sid: null_mut(),
                username: null_mut(),
                kernelMode: 0,
            };

            let mut handle: HANDLE = null_mut();
            let status = unsafe {
                FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut handle)
            };
            if status != 0 || handle.is_null() {
                return Err(anyhow!("FwpmEngineOpen0 failed with status 0x{status:08x}"));
            }
            Ok(Self { handle })
        }

        pub fn install_kill_switch(&mut self, config: &KillSwitchConfig) -> Result<()> {
            validate_config(config)?;
            let _ = self.delete_aegis_filters_by_name();

            let status = unsafe { FwpmTransactionBegin0(self.handle, 0) };
            if status != 0 {
                return Err(anyhow!(
                    "FwpmTransactionBegin0 failed with status 0x{status:08x}"
                ));
            }

            let install_result = (|| -> Result<()> {
                self.add_permit_server_filter(config)?;
                self.add_permit_loopback_filter_v4()?;
                self.add_permit_loopback_filter_v6()?;
                self.add_block_all_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V4, "IPv4")?;
                self.add_block_all_filter(FWPM_LAYER_ALE_AUTH_CONNECT_V6, "IPv6")?;
                Ok(())
            })();

            match install_result {
                Ok(()) => {
                    let status = unsafe { FwpmTransactionCommit0(self.handle) };
                    if status != 0 {
                        clear_filter_ids();
                        return Err(anyhow!(
                            "FwpmTransactionCommit0 failed with status 0x{status:08x}"
                        ));
                    }
                    FILTERS_INSTALLED.store(true, Ordering::SeqCst);
                    info!("wfp: installed {} Aegis filters", filter_count());
                    Ok(())
                }
                Err(error) => {
                    let abort_status = unsafe { FwpmTransactionAbort0(self.handle) };
                    if abort_status != 0 {
                        warn!("FwpmTransactionAbort0 failed with status 0x{abort_status:08x}");
                    }
                    clear_filter_ids();
                    Err(error)
                }
            }
        }

        pub fn remove_filters(&mut self) -> Result<()> {
            let mut errors = Vec::new();
            for id in take_filter_ids() {
                if let Err(e) = self.delete_filter(id) {
                    errors.push(e.to_string());
                }
            }

            match self.delete_aegis_filters_by_name() {
                Ok(recovered) if !recovered.is_empty() => {
                    info!("wfp: recovered {} orphaned Aegis filters", recovered.len());
                }
                Ok(_) => {}
                Err(e) => errors.push(e.to_string()),
            }

            if errors.is_empty() {
                FILTERS_INSTALLED.store(false, Ordering::SeqCst);
                Ok(())
            } else {
                FILTERS_INSTALLED.store(true, Ordering::SeqCst);
                Err(anyhow!("WFP cleanup failed: {}", errors.join("; ")))
            }
        }

        fn add_permit_server_filter(&mut self, config: &KillSwitchConfig) -> Result<()> {
            let protocol = protocol_number(&config.protocol)?;
            match config.server_ip {
                IpAddr::V4(ip) => self.add_permit_server_filter_v4(
                    ip,
                    config.server_port,
                    protocol,
                    "Aegis VPN permit server IPv4",
                ),
                IpAddr::V6(ip) => self.add_permit_server_filter_v6(
                    ip,
                    config.server_port,
                    protocol,
                    "Aegis VPN permit server IPv6",
                ),
            }
        }

        fn add_permit_server_filter_v4(
            &mut self,
            ip: Ipv4Addr,
            port: u16,
            protocol: u8,
            name: &str,
        ) -> Result<()> {
            let mut conditions = vec![
                condition_u32(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    u32::from_be_bytes(ip.octets()),
                ),
                condition_u16(FWPM_CONDITION_IP_REMOTE_PORT, port.to_be()),
                condition_u8(FWPM_CONDITION_IP_PROTOCOL, protocol),
            ];
            self.add_filter(
                name,
                "Permit traffic to the configured VPN endpoint",
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWP_ACTION_PERMIT,
                15,
                &mut conditions,
            )
        }

        fn add_permit_server_filter_v6(
            &mut self,
            ip: Ipv6Addr,
            port: u16,
            protocol: u8,
            name: &str,
        ) -> Result<()> {
            let mut ip_value = FWP_BYTE_ARRAY16 {
                byteArray16: ip.octets(),
            };
            let mut conditions = vec![
                condition_byte_array16(FWPM_CONDITION_IP_REMOTE_ADDRESS, &mut ip_value),
                condition_u16(FWPM_CONDITION_IP_REMOTE_PORT, port.to_be()),
                condition_u8(FWPM_CONDITION_IP_PROTOCOL, protocol),
            ];
            self.add_filter(
                name,
                "Permit traffic to the configured VPN endpoint",
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                FWP_ACTION_PERMIT,
                15,
                &mut conditions,
            )
        }

        fn add_permit_loopback_filter_v4(&mut self) -> Result<()> {
            let mut conditions = vec![condition_u32(
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                u32::from_be_bytes(Ipv4Addr::LOCALHOST.octets()),
            )];
            self.add_filter(
                "Aegis VPN permit loopback IPv4",
                "Permit local IPC traffic",
                FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                FWP_ACTION_PERMIT,
                14,
                &mut conditions,
            )
        }

        fn add_permit_loopback_filter_v6(&mut self) -> Result<()> {
            let mut ip_value = FWP_BYTE_ARRAY16 {
                byteArray16: Ipv6Addr::LOCALHOST.octets(),
            };
            let mut conditions = vec![condition_byte_array16(
                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                &mut ip_value,
            )];
            self.add_filter(
                "Aegis VPN permit loopback IPv6",
                "Permit local IPC traffic",
                FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                FWP_ACTION_PERMIT,
                14,
                &mut conditions,
            )
        }

        fn add_block_all_filter(&mut self, layer: GUID, family: &str) -> Result<()> {
            let mut conditions = Vec::new();
            self.add_filter(
                &format!("Aegis VPN block outbound {family}"),
                "Block outbound traffic that is not explicitly permitted",
                layer,
                FWP_ACTION_BLOCK,
                1,
                &mut conditions,
            )
        }

        fn add_filter(
            &mut self,
            name: &str,
            description: &str,
            layer: GUID,
            action: FWP_ACTION_TYPE,
            weight: u8,
            conditions: &mut [FWPM_FILTER_CONDITION0],
        ) -> Result<()> {
            let mut name = wide(name);
            let mut description = wide(description);
            let filter = FWPM_FILTER0 {
                filterKey: GUID::from_u128(0),
                displayData: FWPM_DISPLAY_DATA0 {
                    name: name.as_mut_ptr(),
                    description: description.as_mut_ptr(),
                },
                flags: 0,
                providerKey: null_mut(),
                providerData: FWP_BYTE_BLOB {
                    size: 0,
                    data: null_mut(),
                },
                layerKey: layer,
                subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
                weight: FWP_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_VALUE0_0 { uint8: weight },
                },
                numFilterConditions: conditions.len() as u32,
                filterCondition: conditions.as_mut_ptr(),
                action: FWPM_ACTION0 {
                    r#type: action,
                    Anonymous: FWPM_ACTION0_0 {
                        filterType: GUID::from_u128(0),
                    },
                },
                Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
                reserved: null_mut(),
                filterId: 0,
                effectiveWeight: FWP_VALUE0::default(),
            };

            let mut id = 0u64;
            let status = unsafe { FwpmFilterAdd0(self.handle, &filter, null(), &mut id) };
            if status != 0 {
                return Err(anyhow!(
                    "FwpmFilterAdd0 failed for {} with status 0x{status:08x}",
                    String::from_utf16_lossy(&name[..name.len().saturating_sub(1)])
                ));
            }
            remember_filter_id(id);
            Ok(())
        }

        fn delete_filter(&mut self, id: u64) -> Result<()> {
            let status = unsafe { FwpmFilterDeleteById0(self.handle, id) };
            if matches!(
                status,
                0 | ERROR_FILE_NOT_FOUND | HRESULT_FILE_NOT_FOUND | FWP_E_FILTER_NOT_FOUND
            ) {
                Ok(())
            } else {
                Err(anyhow!(
                    "FwpmFilterDeleteById0({id}) failed with status 0x{status:08x}"
                ))
            }
        }

        fn delete_aegis_filters_by_name(&mut self) -> Result<Vec<u64>> {
            let mut enum_handle: HANDLE = null_mut();
            let status =
                unsafe { FwpmFilterCreateEnumHandle0(self.handle, null(), &mut enum_handle) };
            if status != 0 {
                return Err(anyhow!(
                    "FwpmFilterCreateEnumHandle0 failed with status 0x{status:08x}"
                ));
            }

            let mut deleted = Vec::new();
            loop {
                let mut entries: *mut *mut FWPM_FILTER0 = null_mut();
                let mut returned = 0u32;
                let status = unsafe {
                    FwpmFilterEnum0(self.handle, enum_handle, 64, &mut entries, &mut returned)
                };
                if status != 0 {
                    unsafe { FwpmFilterDestroyEnumHandle0(self.handle, enum_handle) };
                    return Err(anyhow!("FwpmFilterEnum0 failed with status 0x{status:08x}"));
                }
                if returned == 0 || entries.is_null() {
                    break;
                }

                let filters = unsafe { std::slice::from_raw_parts(entries, returned as usize) };
                for filter_ptr in filters {
                    if filter_ptr.is_null() {
                        continue;
                    }
                    let filter = unsafe { &**filter_ptr };
                    if display_name_contains_aegis(filter.displayData.name) {
                        let id = filter.filterId;
                        if self.delete_filter(id).is_ok() {
                            deleted.push(id);
                        }
                    }
                }

                unsafe {
                    FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut c_void);
                }
            }

            unsafe { FwpmFilterDestroyEnumHandle0(self.handle, enum_handle) };
            Ok(deleted)
        }
    }

    impl Drop for WfpEngine {
        fn drop(&mut self) {
            if !self.handle.is_null() {
                unsafe { FwpmEngineClose0(self.handle) };
                self.handle = null_mut();
            }
        }
    }

    pub fn wfp_filters_installed() -> bool {
        FILTERS_INSTALLED.load(Ordering::SeqCst)
    }

    pub fn recover_orphaned_filters() -> Result<Vec<u64>> {
        let mut engine = WfpEngine::open()?;
        engine.delete_aegis_filters_by_name()
    }

    pub fn install_kill_switch(config: &KillSwitchConfig) -> Result<()> {
        let mut engine = WfpEngine::open()?;
        engine.install_kill_switch(config)
    }

    pub fn remove_filters() -> Result<()> {
        let mut engine = WfpEngine::open()?;
        engine.remove_filters()
    }

    fn remember_filter_id(id: u64) {
        let mut ids = FILTER_IDS
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        ids.push(id);
        FILTERS_INSTALLED.store(true, Ordering::SeqCst);
    }

    fn take_filter_ids() -> Vec<u64> {
        let mut ids = FILTER_IDS
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::take(&mut *ids)
    }

    fn clear_filter_ids() {
        FILTER_IDS
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        FILTERS_INSTALLED.store(false, Ordering::SeqCst);
    }

    fn filter_count() -> usize {
        FILTER_IDS
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    fn condition_u8(field_key: GUID, value: u8) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: field_key,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint8: value },
            },
        }
    }

    fn condition_u16(field_key: GUID, value: u16) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: field_key,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT16,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint16: value },
            },
        }
    }

    fn condition_u32(field_key: GUID, value: u32) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: field_key,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT32,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint32: value },
            },
        }
    }

    fn condition_byte_array16(
        field_key: GUID,
        value: &mut FWP_BYTE_ARRAY16,
    ) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: field_key,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_ARRAY16_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    byteArray16: value as *mut _,
                },
            },
        }
    }

    fn validate_config(config: &KillSwitchConfig) -> Result<()> {
        if config.server_port == 0 {
            return Err(anyhow!("server port cannot be zero"));
        }
        protocol_number(&config.protocol)?;
        Ok(())
    }

    fn protocol_number(protocol: &str) -> Result<u8> {
        match protocol.trim().to_ascii_uppercase().as_str() {
            "TCP" => Ok(IPPROTO_TCP),
            "UDP" => Ok(IPPROTO_UDP),
            _ => Err(anyhow!("protocol must be TCP or UDP")),
        }
    }

    fn display_name_contains_aegis(name: windows_sys::core::PWSTR) -> bool {
        if name.is_null() {
            return false;
        }
        let mut len = 0usize;
        unsafe {
            while *name.add(len) != 0 {
                len += 1;
            }
            let value = String::from_utf16_lossy(std::slice::from_raw_parts(name, len));
            value.starts_with("Aegis VPN")
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

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

    pub fn recover_orphaned_filters() -> Result<Vec<u64>> {
        Ok(Vec::new())
    }

    pub fn install_kill_switch(_: &KillSwitchConfig) -> Result<()> {
        Err(anyhow!("native WFP is only available on Windows"))
    }

    pub fn remove_filters() -> Result<()> {
        Err(anyhow!("native WFP is only available on Windows"))
    }
}

pub use native::install_kill_switch;
pub use native::recover_orphaned_filters;
pub use native::remove_filters;
pub use native::wfp_filters_installed;
pub use native::WfpEngine;
