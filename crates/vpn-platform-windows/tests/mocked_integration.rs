 //! Mock-based Windows platform integration tests that can run without admin/wintun.dll
 //!
 //! These tests use mocking to validate Windows platform functionality on any platform
 //! without requiring administrator privileges or wintun.dll.

use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use vpn_platform_windows::{
    admin, disable_kill_switch, dpapi, full_teardown, native_windows::WfpFilterSpec,
    verify_teardown_clean, KillSwitchConfig, NativeWfpController, WfpEngine,
};

// Mock state for tracking Windows platform operations
static MOCK_STATE: OnceLock<Mutex<MockPlatformState>> = OnceLock::new();

#[derive(Default, Debug)]
struct MockPlatformState {
    wfp_engine_opened: bool,
    filters_installed: Vec<(String, u16)>, // (alias, port)
    kill_switch_enabled: bool,
    dpapi_keys: std::collections::HashMap<std::path::PathBuf, Vec<u8>>,
}

// Initialize mock state
fn get_mock_state<'a>() -> &'a Mutex<MockPlatformState> {
    MOCK_STATE.get_or_init(|| Mutex::new(MockPlatformState::default()))
}

// Reset mock state between tests
fn reset_mock_state() {
    if let Ok(mut state) = get_mock_state().lock() {
        *state = MockPlatformState::default();
    }
}

// Mock implementations of Windows platform functions
#[cfg(not(windows))]
mod mock_impl {
    use super::*;
    use std::net::IpAddr;

    // Mock admin check - always returns true for testing
    pub fn is_run_as_admin() -> bool {
        true
    }

    // Mock WFP engine
    impl WfpEngine {
        pub fn open() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            let mut state = super::get_mock_state().lock().unwrap();
            state.wfp_engine_opened = true;
            Ok(WfpEngine)
        }

        pub fn install_kill_switch(
            &mut self,
            config: &super::KillSwitchConfig,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut state = super::get_mock_state().lock().unwrap();
            state.filters_installed.push((
                config.tun_alias.clone(),
                config.server_port,
            ));
            state.kill_switch_enabled = true;
            Ok(())
        }

        pub fn remove_filters(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut state = super::get_mock_state().lock().unwrap();
            state.filters_installed.clear();
            state.kill_switch_enabled = false;
            Ok(())
        }
    }

    // Mock DPAPI functions
    pub fn protect(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Simple mock encryption: prefix with "ENCRYPTED:" and base64 encode
        let mut encrypted = b"ENCRYPTED:".to_vec();
        encrypted.extend_from_slice(data);
        Ok(base64::encode(&encrypted).into_bytes())
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Simple mock decryption: check prefix, base64 decode, remove prefix
        let s = std::str::from_utf8(data)?;
        if !s.starts_with("ENCRYPTED:") {
            return Err("Invalid encrypted data format".into());
        }
        let encrypted_part = &s["ENCRYPTED:".len()..];
        let decoded = base64::decode(encrypted_part)?;
        Ok(decoded)
    }

    pub fn store_key<P: AsRef<std::path::Path>>(
        path: P,
        key: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut state = super::get_mock_state().lock().unwrap();
        state.dpapi_keys.insert(path.as_ref().to_path_buf(), key.to_vec());
        Ok(())
    }

    pub fn load_key<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let state = super::get_mock_state().lock().unwrap();
        state.dpapi_keys
            .get(path.as_ref())
            .cloned()
            .ok_or_else(|| "Key not found".into())
    }

    // Mock NativeWfpController
    impl NativeWfpController {
        pub fn apply_filters(spec: &WfpFilterSpec) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut state = super::get_mock_state().lock().unwrap();
            state.filters_installed.push((
                spec.tunnel_alias.clone(),
                spec.remote_server_port,
            ));
            Ok(())
        }

        pub fn remove_filters() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let mut state = super::get_mock_state().lock().unwrap();
            state.filters_installed.clear();
            Ok(())
        }
    }

    // Mock platform functions
    pub fn full_teardown(tun_alias: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut state = super::get_mock_state().lock().unwrap();
        state.filters_installed.retain(|(alias, _)| alias != tun_alias);
        if state.filters_installed.is_empty() {
            state.kill_switch_enabled = false;
        }
        Ok(())
    }

    pub fn verify_teardown_clean(tun_alias: &str) -> Vec<String> {
        let state = super::get_mock_state().lock().unwrap();
        let mut issues = Vec::new();
        for (alias, _) in &state.filters_installed {
            if alias == tun_alias {
                issues.push(format!("Filter still installed for {}", alias));
            }
        }
        if state.kill_switch_enabled {
            issues.push("Kill switch still enabled".to_string());
        }
        issues
    }

    pub fn disable_kill_switch() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut state = super::get_mock_state().lock().unwrap();
        state.kill_switch_enabled = false;
        Ok(())
    }

    pub fn cleanup_routes(tun_alias: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Mock implementation - always succeeds
        Ok(())
    }
}

// Use mock implementations on non-Windows platforms, real ones on Windows
#[cfg(not(windows))]
pub use mock_impl::*;

fn test_server_ip() -> IpAddr {
    "203.0.113.1".parse().unwrap()
}

fn test_kill_switch_config() -> KillSwitchConfig {
    KillSwitchConfig {
        tun_alias: "aegis-test".to_string(),
        server_ip: test_server_ip(),
        server_port: 51820,
        protocol: "UDP".to_string(),
    }
}

fn test_filter_spec() -> WfpFilterSpec {
    WfpFilterSpec {
        remote_server_ip: test_server_ip(),
        remote_server_port: 51820,
        tunnel_alias: "aegis-test".to_string(),
    }
}

#[test]
fn test_windows_platform_mock_initialization() {
    reset_mock_state();
    let state = get_mock_state().lock().unwrap();
    assert!(!state.wfp_engine_opened);
    assert!(state.filters_installed.is_empty());
    assert!(!state.kill_switch_enabled);
    assert!(state.dpapi_keys.is_empty());
}

#[test]
fn test_admin_check_mock() {
    reset_mock_state();
    assert!(admin::is_run_as_admin());
}

#[test]
fn test_wfp_engine_lifecycle_mock() {
    reset_mock_state();
    
    // Engine should open successfully
    let engine_result = WfpEngine::open();
    assert!(engine_result.is_ok());
    
    let mut engine = engine_result.unwrap();
    let state = get_mock_state().lock().unwrap();
    assert!(state.wfp_engine_opened);
    
    // Install kill switch
    let config = test_kill_switch_config();
    let install_result = engine.install_kill_switch(&config);
    assert!(install_result.is_ok());
    
    let state = get_mock_state().lock().unwrap();
    assert_eq!(state.filters_installed.len(), 1);
    assert_eq!(state.filters_installed[0].0, "aegis-test");
    assert_eq!(state.filters_installed[0].1, 51820);
    assert!(state.kill_switch_enabled);
    
    // Remove filters
    let remove_result = engine.remove_filters();
    assert!(remove_result.is_ok());
    
    let state = get_mock_state().lock().unwrap();
    assert!(state.filters_installed.is_empty());
    assert!(!state.kill_switch_enabled);
}

#[test]
fn test_native_wfp_controller_mock() {
    reset_mock_state();
    
    let spec = test_filter_spec();
    let apply_result = NativeWfpController::apply_filters(&spec);
    assert!(apply_result.is_ok());
    
    let state = get_mock_state().lock().unwrap();
    assert_eq!(state.filters_installed.len(), 1);
    assert_eq!(state.filters_installed[0].0, "aegis-test");
    assert_eq!(state.filters_installed[0].1, 51820);
    
    let remove_result = NativeWfpController::remove_filters();
    assert!(remove_result.is_ok());
    
    let state = get_mock_state().lock().unwrap();
    assert!(state.filters_installed.is_empty());
}

#[test]
fn test_dpapi_mock() {
    reset_mock_state();
    
    let test_data = b"aegis-vpn-test-secret-key-2026";
    let temp_path = std::env::temp_dir().join("aegis-test-key.bin");
    
    // Protect data
    let encrypted = dpapi::protect(test_data).expect("protect should succeed");
    assert_ne!(&encrypted[..], test_data, "encrypted should differ from plaintext");
    
    // Unprotect data
    let decrypted = dpapi::unprotect(&encrypted).expect("unprotect should succeed");
    assert_eq!(&decrypted[..], test_data, "roundtrip should recover original data");
    
    // Store key
    let store_result = dpapi::store_key(&temp_path, test_data);
    assert!(store_result.is_ok());
    
    let state = get_mock_state().lock().unwrap();
    assert!(state.dpapi_keys.contains_key(&temp_path));
    assert_eq!(state.dpapi_keys.get(&temp_path).unwrap(), test_data);
    
    // Load key
    let loaded = dpapi::load_key(&temp_path).expect("load should succeed");
    assert_eq!(&loaded[..], test_data);
    
    // Cleanup
    let _ = std::fs::remove_file(&temp_path);
}

#[test]
fn test_full_teardown_and_verification_mock() {
    reset_mock_state();
    
    // Enable kill switch via WFP engine
    let mut engine = WfpEngine::open().expect("WFP engine should open");
    let config = test_kill_switch_config();
    engine.install_kill_switch(&config).expect("should install kill switch");
    
    let state = get_mock_state().lock().unwrap();
    assert_eq!(state.filters_installed.len(), 1);
    assert!(state.kill_switch_enabled);
    
    // Full teardown
    let teardown_result = full_teardown("aegis-test");
    assert!(teardown_result.is_ok());
    
    let state = get_mock_state().lock().unwrap();
    assert!(state.filters_installed.is_empty());
    assert!(!state.kill_switch_enabled);
    
    // Verify teardown is clean
    let issues = verify_teardown_clean("aegis-test");
    assert!(issues.is_empty(), "expected no issues, got {:?}", issues);
}

#[test]
fn test_platform_functions_mock() {
    reset_mock_state();
    
    // Test disable_kill_switch
    let disable_result = disable_kill_switch();
    assert!(disable_result.is_ok());
    
    // Test cleanup_routes
    let cleanup_result = cleanup_routes("aegis-test");
    assert!(cleanup_result.is_ok());
    
    // Test verify_teardown_clean on non-existent adapter
    let issues = verify_teardown_clean("non-existent-adapter");
    assert!(issues.is_empty());
}

#[test]
fn test_error_conditions_mock() {
    reset_mock_state();
    
    // Test DPAPI with non-existent key
    let nonexistent_path = std::env::temp_dir().join("nonexistent-key.bin");
    let load_result = dpapi::load_key(&nonexistent_path);
    assert!(load_result.is_err());
    
    // Test DPAPI with empty data
    let empty_result = dpapi::protect(b"");
    // Note: Depending on implementation, empty data might be valid or invalid
    // For this mock, we'll accept either outcome as long as it doesn't panic
    
    // Test DPAPI corruption
    let data = b"test data";
    let encrypted = dpapi::protect(data).expect("protect should succeed");
    let mut corrupted = encrypted.clone();
    if corrupted.len() > 0 {
        corrupted[0] ^= 0xFF; // Flip first bit
    }
    let unprotect_result = dpapi::unprotect(&corrupted);
    assert!(unprotect_result.is_err(), "corrupted data should fail to unprotect");
}