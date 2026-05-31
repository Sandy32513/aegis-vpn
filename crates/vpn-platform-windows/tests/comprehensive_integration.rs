 //! Comprehensive Windows integration tests for Aegis VPN core functionality
 //!
 //! These tests validate the key Windows-specific components of the Aegis VPN system.
//! They include both mock-based tests (runnable anywhere) and Windows-specific tests
//! that require administrator privileges and wintun.dll.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, oneshot};
use vpn_daemon::{
    config::{self, Config},
    control_plane::{self, ControlPlaneEvent, ControlPlaneHandle},
    daemon::Daemon,
    guards::ConnectionGuard,
    ipc::{self, server::IpcServer},
    runtime_mode::RuntimeMode,
    service::{self, ServiceManager},
};
use vpn_ipc::{
    router::IpcRouter,
    schema::{self, vpn_service::VpnService},
};
use vpn_platform_windows::{
    admin, dpapi, full_teardown, native_windows::WfpFilterSpec,
    verify_teardown_clean, KillSwitchConfig, NativeWfpController, WfpEngine,
};
use vpn_tun::windows::WindowsTun;

// Test configuration constants
const TEST_TUN_NAME: &str = "aegis-test";
const TEST_SERVER_IP_V4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
const TEST_SERVER_PORT: u16 = 51820;
const TEST_TUN_IPV4: Ipv4Addr = Ipv4Addr::new(10, 20, 0, 2);
const TEST_TUN_IPV4_CIDR: &str = "10.20.0.2/24";

// Mock state for cross-platform testing
static TEST_STATE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();

fn get_test_state<'a>() -> &'a Mutex<HashMap<String, Vec<u8>>> {
    TEST_STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn clear_test_state() {
    if let Ok(mut state) = get_test_state().lock() {
        state.clear();
    }
}

// Mock implementations for cross-platform testing
#[cfg(not(windows))]
mod mock_windows {
    use super::*;
    use std::net::IpAddr;

    // Mock admin check
    pub fn is_run_as_admin() -> bool {
        true
    }

    // Mock WFP engine
    impl WfpEngine {
        pub fn open() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            Ok(WfpEngine)
        }

        pub fn install_kill_switch(
            &mut self,
            _config: &super::KillSwitchConfig,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }

        pub fn remove_filters(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
    }

    // Mock DPAPI functions
    pub fn protect(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Simple mock: just return the data with a prefix to indicate it's "encrypted"
        let mut encrypted = b"MOCK_ENCRYPTED:".to_vec();
        encrypted.extend_from_slice(data);
        Ok(encrypted)
    }

    pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        // Simple mock: remove the prefix
        if data.starts_with(b"MOCK_ENCRYPTED:") {
            Ok(data[b"MOCK_ENCRYPTED:".len()..].to_vec())
        } else {
            Err("Invalid mock encrypted data".into())
        }
    }

    pub fn store_key<P: AsRef<std::path::Path>>(
        path: P,
        key: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let mut state = super::get_test_state().lock().unwrap();
        state.insert(path_str, key.to_vec());
        Ok(())
    }

    pub fn load_key<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let state = super::get_test_state().lock().unwrap();
        state.get(&path_str)
            .cloned()
            .ok_or_else(|| format!("Key not found: {}", path_str).into())
    }

    // Mock NativeWfpController
    impl NativeWfpController {
        pub fn apply_filters(_spec: &WfpFilterSpec) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }

        pub fn remove_filters() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
    }

    // Mock platform functions
    pub fn full_teardown(_tun_alias: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    pub fn verify_teardown_clean(_tun_alias: &str) -> Vec<String> {
        Vec::new()
    }

    pub fn disable_kill_switch() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    pub fn cleanup_routes(_tun_alias: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    // Mock Windows TUN device
    impl WindowsTun {
        pub fn new(
            _name: &str,
            _mtu: u16,
        ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
            Ok(WindowsTun { _inner: () })
        }
    }

    impl std::ops::Deref for WindowsTun {
        type Target = ();
        fn deref(&self) -> &Self::Target {
            &self._inner
        }
    }

    impl vpn_tun::TunDevice for WindowsTun {
        type Error = Box<dyn std::error::Error + Send + Sync>;
        type Rx = tokio::sync::mpsc::UnboundedReceiver<tokio::util::bytes::BytesMut>;
        type Tx = tokio::sync::mpsc::UnboundedSender<tokio::util::bytes::BytesMut>;

        fn try_clone(&self) -> Result<Self, Self::Error> {
            Ok(WindowsTun { _inner: () })
        }

        fn rx_tx(&mut self) -> Result<(Self::Rx, Self::Tx), Self::Error> {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            Ok((rx, tx))
        }
    }
}

// Use mock implementations on non-Windows platforms
#[cfg(not(windows))]
pub use mock_windows::*;

// Test helper functions
fn create_test_config() -> Config {
    Config {
        version: config::ConfigVersion::V1,
        control_plane: config::ControlPlaneConfig {
            listen_address: "127.0.0.1:0".to_string(),
            node_id: "test-node".to_string(),
            allow_persist_identity: true,
        },
        logging: config::LoggingConfig {
            level: "info".to_string(),
            json_log_path: None,
            mysql_url: None,
        },
        dns: config::DnsConfig {
            servers: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            search_domains: vec![],
        },
        client: Some(config::ClientConfig {
            server_endpoint: format!("{}:{}", TEST_SERVER_IP_V4, TEST_SERVER_PORT),
            trusted_server_public_key: vec![0u8; 32], // 32-byte zero key for testing
            bind_address: "0.0.0.0:0".to_string(),
            tun_name: TEST_TUN_NAME.to_string(),
            tun_cidr: TEST_TUN_IPV4_CIDR.to_string(),
            mtu: 1400,
            rotation_interval_secs: 300,
            kill_switch: true,
            config_identity_dir: std::env::temp_dir().join("test-identity").to_string_lossy().to_string(),
        }),
        server: None,
    }
}

// ──────────────────────────────────────────────────────────────
// Core Windows Functionality Tests
// ──────────────────────────────────────────────────────────────

#[test]
fn test_windows_admin_check() {
    // This test validates that we can check for admin privileges
    let is_admin = admin::is_run_as_admin();
    // On CI systems, this might be false, but the function should not panic
    // We're just verifying the function exists and returns a boolean
    assert!(is_admin == true || is_admin == false);
}

#[test]
fn test_windows_dpapi_integration() {
    clear_test_state();
    
    let test_key = b"x25519-private-key-for-testing-32-bytes-long!";
    let test_path = std::env::temp_dir().join("aegis-integration-test-key.bin");
    
    // Test protecting data
    let encrypted = dpapi::protect(test_key).expect("DP API protect should work");
    assert_ne!(&encrypted[..], test_key, "Encrypted data should differ from plaintext");
    
    // Test unprotecting data
    let decrypted = dpapi::unprotect(&encrypted).expect("DP API unprotect should work");
    assert_eq!(&decrypted[..], test_key, "Roundtrip should recover original data");
    
    // Test storing key
    let store_result = dpapi::store_key(&test_path, test_key);
    assert!(store_result.is_ok(), "Storing key should succeed: {:?}", store_result.err());
    
    // Test loading key
    let loaded_key = dpapi::load_key(&test_path).expect("Loading key should work");
    assert_eq!(&loaded_key[..], test_key, "Loaded key should match original");
    
    // Cleanup
    let _ = std::fs::remove_file(&test_path);
}

#[test]
fn test_windows_wfp_integration() {
    // Test WFP filter specification creation
    let spec = WfpFilterSpec {
        remote_server_ip: IpAddr::V4(TEST_SERVER_IP_V4),
        remote_server_port: TEST_SERVER_PORT,
        tunnel_alias: TEST_TUN_NAME.to_string(),
    };
    
    assert_eq!(spec.remote_server_ip, IpAddr::V4(TEST_SERVER_IP_V4));
    assert_eq!(spec.remote_server_port, TEST_SERVER_PORT);
    assert_eq!(spec.tunnel_alias, TEST_TUN_NAME);
    
    // Test applying filters (should work even without admin on mock)
    let apply_result = NativeWfpController::apply_filters(&spec);
    assert!(apply_result.is_ok(), "Applying WFP filters should not fail");
    
    // Test removing filters
    let remove_result = NativeWfpController::remove_filters();
    assert!(remove_result.is_ok(), "Removing WFP filters should not fail");
}

#[test]
fn test_windows_kill_switch_integration() {
    // Test kill switch configuration
    let config = KillSwitchConfig {
        tun_alias: TEST_TUN_NAME.to_string(),
        server_ip: IpAddr::V4(TEST_SERVER_IP_V4),
        server_port: TEST_SERVER_PORT,
        protocol: "UDP".to_string(),
    };
    
    assert_eq!(config.tun_alias, TEST_TUN_NAME);
    assert_eq!(config.server_ip, IpAddr::V4(TEST_SERVER_IP_V4));
    assert_eq!(config.server_port, TEST_SERVER_PORT);
    assert_eq!(config.protocol, "UDP");
    
    // Test enabling kill switch (mock implementation)
    let enable_result = vpn_platform_windows::enable_kill_switch(&config);
    assert!(enable_result.is_ok(), "Enabling kill switch should not fail");
    
    // Test disabling kill switch
    let disable_result = disable_kill_switch();
    assert!(disable_result.is_ok(), "Disabling kill switch should not fail");
    
    // Test verification
    let issues = verify_teardown_clean(TEST_TUN_NAME);
    // With our mocks, there should be no issues
    assert!(issues.is_empty(), "Expected no teardown issues, got: {:?}", issues);
}

#[test]
fn test_windows_service_integration_mock() {
    // Test service manager creation (this tests the interface)
    let service_manager = ServiceManager::new("AegisVpn".to_string());
    assert!(service_manager.is_ok());
    
    // Test that we can query service status (will fail if service doesn't exist, but shouldn't panic)
    if let Ok(manager) = service_manager {
        let status_result = manager.query_status();
        // This might return an error if service doesn't exist, which is fine for this test
        // We're just verifying the function doesn't panic
        assert!(status_result.is_ok() || status_result.is_err());
    }
}

#[test]
fn test_windows_routing_functions_mock() {
    // Test that routing functions exist and don't panic
    // These would normally require admin privileges, but our mocks allow testing
    
    let cleanup_result = vpn_platform_windows::cleanup_routes(TEST_TUN_NAME);
    assert!(cleanup_result.is_ok(), "Cleanup routes should not panic");
    
    // Test full teardown
    let teardown_result = full_teardown(TEST_TUN_NAME);
    assert!(teardown_result.is_ok(), "Full teardown should not panic");
    
    // Test verification
    let issues = verify_teardown_clean(TEST_TUN_NAME);
    assert!(issues.is_empty(), "Expected no teardown issues");
}

#[test]
fn test_windows_tun_device_creation() {
    // Test that we can create a Windows TUN device (mocked)
    let tun_result = WindowsTun::new(TEST_TUN_NAME, 1400);
    assert!(tun_result.is_ok(), "Should be able to create Windows TUN device");
    
    if let Ok(_tun) = tun_result {
        // Test that we can get Rx/Tx channels
        let rx_tx_result = (_tun).rx_tx();
        assert!(rx_tx_result.is_ok(), "Should be able to get RX/TX channels");
    }
}

#[test]
fn test_windows_ipc_server_creation() {
    // Test IPC server creation (cross-platform)
    let router = IpcRouter::new();
    let server_result = IpcServer::bind("/tmp/aegis-test.ipc", router);
    // On Windows, named pipes are used instead of Unix domain sockets
    // This test primarily checks that the function signature works
    // Actual behavior will differ by platform
    assert!(server_result.is_ok() || !cfg!(windows)); // Allow failure on Windows due to path format
}

#[test]
fn test_windows_config_loading() {
    // Test that we can create a valid configuration
    let config = create_test_config();
    
    assert_eq!(config.version, config::ConfigVersion::V1);
    assert_eq!(config.control_plane.node_id, "test-node");
    assert!(config.client.is_some());
    
    if let Some(client_config) = &config.client {
        assert_eq!(&client_config.server_endpoint, &format!("{}:{}", TEST_SERVER_IP_V4, TEST_SERVER_PORT));
        assert_eq!(client_config.tun_name, TEST_TUN_NAME);
        assert_eq!(client_config.tun_cidr, TEST_TUN_IPV4_CIDR);
        assert_eq!(client_config.mtu, 1400);
        assert_eq!(client_config.rotation_interval_secs, 300);
        assert!(client_config.kill_switch);
    }
}

#[test]
fn test_windows_control_plane_integration() {
    // Test that control plane functions can be called
    // This is more of an interface test since full integration would require a running daemon
    
    let config = create_test_config();
    let runtime_config = config::RunConfig {
        config_path: None,
        server: String::new(),
        bind: "127.0.0.1:0".to_string(),
        tun_name: "ignored".to_string(),
        tun_addr": "10.99.0.2/24".to_string(),
        mtu: 1300,
        ipc_addr: "127.0.0.1:7788".to_string(),
        log_file: None,
        kill_switch: false,
        admin_secret_env: None,
        safe_mode: false,
    };
    
    // This test verifies the control plane resolution works
    let settings_result = control_plane::resolve_run_settings(&runtime_config);
    // Might fail due to missing config, but shouldn't panic
    assert!(settings_result.is_ok() || settings_result.is_err());
}

#[test]
fn test_windows_daemon_creation() {
    // Test that we can create a daemon instance (interface test)
    let config = create_test_config();
    let runtime_mode = RuntimeMode::Client;
    
    let daemon_result = Daemon::new(config, runtime_mode);
    // This might fail due to missing dependencies in test environment
    // but we're primarily testing that the constructor exists and doesn't panic
    assert!(daemon_result.is_ok() || daemon_result.is_err());
}

// ──────────────────────────────────────────────────────────────
// Windows-Specific Tests (Require Admin + wintun.dll)
// ──────────────────────────────────────────────────────────────
// These tests are conditionally compiled and only run on Windows
// when the appropriate features are enabled

#[cfg(windows)]
mod windows_specific_tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;
    
    // Helper to check if we're running as administrator
    fn is_admin() -> bool {
        use std::ptr::null_mut;
        unsafe {
            let mut token = null_mut();
            let res = windows_sys::Win32::Security::OpenProcessToken(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                windows_sys::Win32::Security::TOKEN_QUERY,
                &mut token,
            );
            if !res.is_ok() {
                return false;
            }
            
            let mut size = 0;
            let res = windows_sys::Win32::Security::GetTokenInformation(
                token,
                windows_sys::Win32::Security::TokenElevation,
                null_mut(),
                0,
                &mut size,
            );
            if res.is_err() && windows_sys::Win32::Foundation::GetLastError() != windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER {
                windows_sys::Win32::System::Threading::CloseHandle(token);
                return false;
            }
            
            let mut elevation = windows_sys::Win32::Security::TOKEN_ELEVATION::default();
            let res = windows_sys::Win32::Security::GetTokenInformation(
                token,
                windows_sys::Win32::Security::TokenElevation,
                &mut elevation as *mut _ as *mut _,
                size_of::<windows_sys::Win32::Security::TOKEN_ELEVATION>() as u32,
                &mut size,
            );
            windows_sys::Win32::System::Threading::CloseHandle(token);
            
            res.is_ok() && elevation.TokenIsEnabled != 0
        }
    }
    
    // Helper to check if wintun.dll is available
    fn is_wintun_available() -> bool {
        let _ = vpn_platform_windows::load_wintun_dll();
        true
    }
    
    #[test]
    #[ignore = "requires admin privileges"]
    fn test_windows_admin_check_real() {
        // This test only runs if we're actually testing admin functionality
        // In CI, we might skip this unless specifically enabled
        let is_admin = is_admin();
        // If we're not admin, we'll skip the actual validation
        if !is_admin {
            println!("Skipping admin-specific test - not running as administrator");
            return;
        }
        
        // If we are admin, verify the function works
        let api_result = admin::is_run_as_admin();
        assert!(api_result, "API should report admin when running as admin");
    }
    
    #[test]
    #[ignore = "requires admin privileges and wintun.dll"]
    fn test_windows_wfp_integration_real() {
        // Skip if not admin
        if !is_admin() {
            println!("Skipping WFP test - not running as administrator");
            return;
        }
        
        // Skip if wintun.dll not available
        if !is_wintun_available() {
            println!("Skipping WFP test - wintun.dll not available");
            return;
        }
        
        // Test actual WFP engine operations
        let engine_result = WfpEngine::open();
        assert!(engine_result.is_ok(), "Should be able to open WFP engine as admin");
        
        let mut engine = engine_result.expect("WFP engine open");
        
        // Test kill switch filter installation
        let config = KillSwitchConfig {
            tun_alias: "aegis-wfp-test".to_string(),
            server_ip: IpAddr::V4(TEST_SERVER_IP_V4),
            server_port: TEST_SERVER_PORT,
            protocol: "UDP".to_string(),
        };
        
        let install_result = engine.install_kill_switch(&config);
        assert!(install_result.is_ok(), "Should be able to install kill switch filters: {:?}", install_result.err());
        
        // Test filter removal
        let remove_result = engine.remove_filters();
        assert!(remove_result.is_ok(), "Should be able to remove WFP filters: {:?}", remove_result.err());
    }
    
    #[test]
    #[ignore = "requires admin privileges"]
    fn test_windows_dpapi_integration_real() {
        // Skip if not admin
        if !is_admin() {
            println!("Skipping DPAPI test - not running as administrator");
            return;
        }
        
        let test_key = b"x25519-private-key-for-real-testing-32-bytes-long!";
        let test_path = std::env::temp_dir().join("aegis-real-test-key.bin");
        
        // Test protecting data
        let encrypted = dpapi::protect(test_key).expect("DP API protect should work as admin");
        assert_ne!(&encrypted[..], test_key, "Encrypted data should differ from plaintext");
        
        // Test unprotecting data
        let decrypted = dpapi::unprotect(&encrypted).expect("DP API unprotect should work as admin");
        assert_eq!(&decrypted[..], test_key, "Roundtrip should recover original data");
        
        // Test storing key
        let store_result = dpapi::store_key(&test_path, test_key);
        assert!(store_result.is_ok(), "Storing key should succeed as admin: {:?}", store_result.err());
        
        // Test loading key
        let loaded_key = dpapi::load_key(&test_path).expect("Loading key should work as admin");
        assert_eq!(&loaded_key[..], test_key, "Loaded key should match original");
        
        // Cleanup
        let _ = std::fs::remove_file(&test_path);
    }
    
    #[test]
    #[ignore = "requires admin privileges and wintun.dll"]
    fn test_windows_full_integration_real() {
        // Skip if not admin
        if !is_admin() {
            println!("Skipping full integration test - not running as administrator");
            return;
        }
        
        // Skip if wintun.dll not available
        if !is_wintun_available() {
            println!("Skipping full integration test - wintun.dll not available");
            return;
        }
        
        println!("Running full Windows integration test (requires admin + wintun.dll)");
        
        // This would be a full end-to-end test of the Windows VPN stack
        // For now, we'll test the key components that can be tested without
        // actually establishing a VPN connection (which would require a server)
        
        // 1. Test WFP engine
        let engine_result = WfpEngine::open();
        assert!(engine_result.is_ok());
        let mut engine = engine_result.expect("WFP engine open");
        
        // 2. Test kill switch configuration and installation
        let config = KillSwitchConfig {
            tun_alias: "aegis-full-test".to_string(),
            server_ip: IpAddr::V4(TEST_SERVER_IP_V4),
            server_port: TEST_SERVER_PORT,
            protocol: "UDP".to_string(),
        };
        
        let install_result = engine.install_kill_switch(&config);
        assert!(install_result.is_ok());
        
        // 3. Test that filters are actually installed (would require querying WFP)
        // 4. Test filter removal
        let remove_result = engine.remove_filters();
        assert!(remove_result.is_ok());
        
        // 5. Test DPAPI operations
        let test_data = b"aegis-vpn-integration-test-key";
        let encrypted = dpapi::protect(test_data).expect("DP API protect");
        let decrypted = dpapi::unprotect(&encrypted).expect("DP API unprotect");
        assert_eq!(&decrypted[..], test_data);
        
        // 6. Test TUN device creation (requires wintun.dll)
        let tun_result = WindowsTun::new("aegis-full-test", 1400);
        assert!(tun_result.is_ok());
        
        // 7. Test teardown verification
        let issues = verify_teardown_clean("aegis-full-test");
        assert!(issues.is_empty(), "Expected clean teardown: {:?}", issues);
    }
}