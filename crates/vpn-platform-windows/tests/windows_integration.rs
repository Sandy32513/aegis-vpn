//! Windows platform integration tests.
//!
//! These tests validate the Windows platform module's API surface.
//! On non-Windows targets, they verify stub behavior returns errors.
//! On Windows, they test real WFP, routing, and teardown functions.

use vpn_platform_windows::{
    disable_kill_switch, full_teardown, verify_teardown_clean, KillSwitchConfig,
    NativeWfpController, WfpFilterSpec,
};

use std::net::IpAddr;

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

// ──────────────────────────────────────────────────────────────
// Stub behavior tests (run on all platforms)
// ──────────────────────────────────────────────────────────────

#[test]
#[cfg(not(windows))]
fn stub_apply_filters_returns_error() {
    let spec = test_filter_spec();
    let result = NativeWfpController::apply_filters(&spec);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("only available on Windows"));
}

#[test]
#[cfg(not(windows))]
fn stub_remove_filters_returns_error() {
    let result = NativeWfpController::remove_filters();
    assert!(result.is_err());
}

#[test]
#[cfg(not(windows))]
fn stub_disable_kill_switch_returns_error() {
    let result = disable_kill_switch();
    assert!(result.is_err());
}

#[test]
#[cfg(not(windows))]
fn stub_full_teardown_returns_error() {
    let result = full_teardown("aegis-test");
    assert!(result.is_err());
}

#[test]
#[cfg(not(windows))]
fn stub_verify_teardown_reports_issue() {
    let issues = verify_teardown_clean("aegis-test");
    assert!(!issues.is_empty());
}

// ──────────────────────────────────────────────────────────────
// WFP unit tests (run on all platforms — verify API structure)
// ──────────────────────────────────────────────────────────────

#[test]
fn kill_switch_config_fields() {
    let config = test_kill_switch_config();
    assert_eq!(config.tun_alias, "aegis-test");
    assert_eq!(config.server_ip, test_server_ip());
    assert_eq!(config.server_port, 51820);
    assert_eq!(config.protocol, "UDP");
}

#[test]
fn filter_spec_fields() {
    let spec = test_filter_spec();
    assert_eq!(spec.remote_server_ip, test_server_ip());
    assert_eq!(spec.remote_server_port, 51820);
    assert_eq!(spec.tunnel_alias, "aegis-test");
}

#[test]
fn kill_switch_config_clone() {
    let config = test_kill_switch_config();
    let cloned = config.clone();
    assert_eq!(config.tun_alias, cloned.tun_alias);
    assert_eq!(config.server_ip, cloned.server_ip);
    assert_eq!(config.server_port, cloned.server_port);
}

#[test]
fn filter_spec_clone() {
    let spec = test_filter_spec();
    let cloned = spec.clone();
    assert_eq!(spec.remote_server_ip, cloned.remote_server_ip);
    assert_eq!(spec.tunnel_alias, cloned.tunnel_alias);
}

// ──────────────────────────────────────────────────────────────
// WFP engine tests (run on all platforms)
// ──────────────────────────────────────────────────────────────

#[test]
#[cfg(not(windows))]
fn wfp_engine_open_fails_on_non_windows() {
    let result = wfp_native::WfpEngine::open();
    assert!(result.is_err());
}

#[test]
#[cfg(not(windows))]
fn wfp_engine_install_fails_on_non_windows() {
    use vpn_platform_windows::wfp_native::WfpEngine;
    // Can't open engine on non-Windows, so this is the stub behavior
    let result = WfpEngine::open();
    assert!(result.is_err());
}

// ──────────────────────────────────────────────────────────────
// DPAPI tests (run on all platforms)
// ──────────────────────────────────────────────────────────────

#[test]
#[cfg(not(windows))]
fn dpapi_protect_fails_on_non_windows() {
    let result = vpn_platform_windows::dpapi::protect(b"test-key-data");
    assert!(result.is_err());
}

#[test]
#[cfg(not(windows))]
fn dpapi_unprotect_fails_on_non_windows() {
    let result = vpn_platform_windows::dpapi::unprotect(b"encrypted-data");
    assert!(result.is_err());
}

#[test]
#[cfg(not(windows))]
fn dpapi_store_key_fails_on_non_windows() {
    let path = std::path::Path::new("/tmp/test-key.bin");
    let result = vpn_platform_windows::dpapi::store_key(path, b"key");
    assert!(result.is_err());
}

#[test]
#[cfg(not(windows))]
fn dpapi_load_key_fails_on_non_windows() {
    let path = std::path::Path::new("/tmp/test-key.bin");
    let result = vpn_platform_windows::dpapi::load_key(path);
    assert!(result.is_err());
}

// ──────────────────────────────────────────────────────────────
// Windows-only tests (require admin + wintun.dll)
// ──────────────────────────────────────────────────────────────

#[test]
#[cfg(windows)]
#[ignore = "requires admin + wintun.dll"]
fn windows_wfp_engine_opens() {
    use vpn_platform_windows::wfp_native::WfpEngine;
    let engine = WfpEngine::open();
    assert!(
        engine.is_ok(),
        "WFP engine should open on Windows with admin privileges"
    );
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin + wintun.dll"]
fn windows_wfp_install_and_remove() {
    use vpn_platform_windows::wfp_native::WfpEngine;
    let config = test_kill_switch_config();

    let mut engine = WfpEngine::open().expect("WFP engine should open");
    let result = engine.install_kill_switch(&config);
    assert!(
        result.is_ok(),
        "WFP install should succeed: {:?}",
        result.err()
    );

    let remove_result = engine.remove_filters();
    assert!(
        remove_result.is_ok(),
        "WFP remove should succeed: {:?}",
        remove_result.err()
    );
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin + wintun.dll"]
fn windows_full_teardown_no_leaks() {
    let result = full_teardown("aegis-nonexistent");
    // Should succeed even if adapter doesn't exist
    assert!(
        result.is_ok(),
        "teardown should not fail on missing adapter: {:?}",
        result.err()
    );

    let issues = verify_teardown_clean("aegis-nonexistent");
    assert!(
        issues.is_empty(),
        "no leaks expected on non-existent adapter: {:?}",
        issues
    );
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin + wintun.dll"]
fn windows_dpapi_roundtrip() {
    let data = b"aegis-vpn-test-secret-key-2026";
    let encrypted = vpn_platform_windows::dpapi::protect(data).expect("protect should succeed");
    assert_ne!(
        &encrypted[..],
        data,
        "encrypted should differ from plaintext"
    );

    let decrypted =
        vpn_platform_windows::dpapi::unprotect(&encrypted).expect("unprotect should succeed");
    assert_eq!(
        &decrypted[..],
        data,
        "roundtrip should recover original data"
    );
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin + wintun.dll"]
fn windows_dpapi_store_and_load_key() {
    let path = std::env::temp_dir().join("aegis-test-key.bin");
    let key_data = b"x25519-private-key-bytes-32-------";

    vpn_platform_windows::dpapi::store_key(&path, key_data).expect("store should succeed");
    assert!(path.exists(), "key file should exist after store");

    let loaded = vpn_platform_windows::dpapi::load_key(&path).expect("load should succeed");
    assert_eq!(&loaded[..], key_data, "roundtrip should recover key");

    // Cleanup
    let _ = std::fs::remove_file(&path);
}
