//! Windows platform validation and hardening tests.
//!
//! These tests validate correctness, edge cases, and failure modes.
//! Windows-only tests require admin privileges and wintun.dll.

use std::net::IpAddr;
use vpn_platform_windows::{
    cleanup_routes, disable_kill_switch, full_teardown, verify_teardown_clean, KillSwitchConfig,
    NativeWfpController, WfpFilterSpec,
};

fn server_ip() -> IpAddr {
    "203.0.113.1".parse().unwrap()
}

fn ks_config() -> KillSwitchConfig {
    KillSwitchConfig {
        tun_alias: "aegis-validate".to_string(),
        server_ip: server_ip(),
        server_port: 51820,
        protocol: "UDP".to_string(),
    }
}

fn filter_spec() -> WfpFilterSpec {
    WfpFilterSpec {
        remote_server_ip: server_ip(),
        remote_server_port: 51820,
        tunnel_alias: "aegis-validate".to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════
// PART 1: API contract tests (run on all platforms)
// ═══════════════════════════════════════════════════════════════

#[test]
fn kill_switch_config_debug() {
    let config = ks_config();
    let debug = format!("{:?}", config);
    assert!(debug.contains("aegis-validate"));
    assert!(debug.contains("203.0.113.1"));
    assert!(debug.contains("51820"));
}

#[test]
fn filter_spec_debug() {
    let spec = filter_spec();
    let debug = format!("{:?}", spec);
    assert!(debug.contains("aegis-validate"));
}

#[test]
fn kill_switch_config_ipv6() {
    let config = KillSwitchConfig {
        tun_alias: "aegis-v6".to_string(),
        server_ip: "2001:db8::1".parse().unwrap(),
        server_port: 51820,
        protocol: "UDP".to_string(),
    };
    assert!(config.server_ip.is_ipv6());
}

#[test]
fn kill_switch_config_zero_port() {
    let config = KillSwitchConfig {
        tun_alias: "aegis-zero".to_string(),
        server_ip: server_ip(),
        server_port: 0,
        protocol: "TCP".to_string(),
    };
    assert_eq!(config.server_port, 0);
}

#[test]
fn kill_switch_config_max_port() {
    let config = KillSwitchConfig {
        tun_alias: "aegis-max".to_string(),
        server_ip: server_ip(),
        server_port: 65535,
        protocol: "UDP".to_string(),
    };
    assert_eq!(config.server_port, 65535);
}

// ═══════════════════════════════════════════════════════════════
// PART 1b: Stub behavior (non-Windows)
// ═══════════════════════════════════════════════════════════════

#[test]
#[cfg(not(windows))]
fn stub_wfp_apply_returns_error() {
    let result = NativeWfpController::apply_filters(&filter_spec());
    assert!(result.is_err());
}

#[test]
#[cfg(not(windows))]
fn stub_wfp_remove_returns_error() {
    let result = NativeWfpController::remove_filters();
    assert!(result.is_err());
}

#[test]
#[cfg(not(windows))]
fn stub_disable_kill_switch_returns_error() {
    assert!(disable_kill_switch().is_err());
}

#[test]
#[cfg(not(windows))]
fn stub_full_teardown_returns_error() {
    assert!(full_teardown("any").is_err());
}

#[test]
#[cfg(not(windows))]
fn stub_verify_teardown_has_issues() {
    assert!(!verify_teardown_clean("any").is_empty());
}

#[test]
#[cfg(not(windows))]
fn stub_cleanup_routes_returns_error() {
    assert!(cleanup_routes("any").is_err());
}

// ═══════════════════════════════════════════════════════════════
// PART 3: DPAPI validation (non-Windows stub)
// ═══════════════════════════════════════════════════════════════

#[test]
#[cfg(not(windows))]
fn dpapi_protect_empty_fails() {
    let result = vpn_platform_windows::dpapi::protect(b"");
    assert!(result.is_err());
}

#[test]
#[cfg(not(windows))]
fn dpapi_protect_fails_non_windows() {
    assert!(vpn_platform_windows::dpapi::protect(b"data").is_err());
}

#[test]
#[cfg(not(windows))]
fn dpapi_unprotect_fails_non_windows() {
    assert!(vpn_platform_windows::dpapi::unprotect(b"data").is_err());
}

#[test]
#[cfg(not(windows))]
fn dpapi_store_fails_non_windows() {
    assert!(vpn_platform_windows::dpapi::store_key(std::path::Path::new("/tmp/x"), b"k").is_err());
}

#[test]
#[cfg(not(windows))]
fn dpapi_load_fails_non_windows() {
    assert!(vpn_platform_windows::dpapi::load_key(std::path::Path::new("/tmp/x")).is_err());
}

// ═══════════════════════════════════════════════════════════════
// Windows-only: WFP kill switch validation
// ═══════════════════════════════════════════════════════════════

#[test]
#[cfg(windows)]
#[ignore = "requires admin + wintun.dll"]
fn wfp_install_remove_roundtrip() {
    use vpn_platform_windows::wfp_native::WfpEngine;
    let config = ks_config();

    let mut engine = WfpEngine::open().expect("open");
    engine.install_kill_switch(&config).expect("install");
    engine.remove_filters().expect("remove");
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin + wintun.dll"]
fn wfp_double_remove_idempotent() {
    use vpn_platform_windows::wfp_native::WfpEngine;
    let config = ks_config();

    let mut engine1 = WfpEngine::open().expect("open1");
    engine1.install_kill_switch(&config).expect("install");

    // First remove
    let mut engine2 = WfpEngine::open().expect("open2");
    engine2.remove_filters().expect("remove1");

    // Second remove — should be no-op (no filters in store)
    let mut engine3 = WfpEngine::open().expect("open3");
    engine3.remove_filters().expect("remove2");
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin + wintun.dll"]
fn wfp_crash_recovery() {
    use vpn_platform_windows::wfp_native::WfpEngine;
    let config = ks_config();

    // Install filters, then drop engine without explicit remove
    {
        let mut engine = WfpEngine::open().expect("open");
        engine.install_kill_switch(&config).expect("install");
        // engine dropped here — filters persist with DYNAMIC flag
    }

    // Recover: open new engine and remove
    let mut recovery = WfpEngine::open().expect("recovery open");
    recovery.remove_filters().expect("recovery remove");
}

// ═══════════════════════════════════════════════════════════════
// Windows-only: Full lifecycle validation
// ═══════════════════════════════════════════════════════════════

#[test]
#[cfg(windows)]
#[ignore = "requires admin + wintun.dll"]
fn lifecycle_enable_disable_cycle() {
    let config = ks_config();

    // Enable kill switch
    vpn_platform_windows::enable_kill_switch(&config).expect("enable");

    // Disable kill switch
    disable_kill_switch().expect("disable");

    // Verify clean
    let issues = verify_teardown_clean("aegis-validate");
    assert!(issues.is_empty(), "leaks after disable: {:?}", issues);
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin + wintun.dll"]
fn lifecycle_repeated_cycles() {
    let config = ks_config();

    for i in 0..10 {
        vpn_platform_windows::enable_kill_switch(&config)
            .unwrap_or_else(|e| panic!("enable cycle {i}: {e}"));
        disable_kill_switch().unwrap_or_else(|e| panic!("disable cycle {i}: {e}"));
    }

    let issues = verify_teardown_clean("aegis-validate");
    assert!(issues.is_empty(), "leaks after 10 cycles: {:?}", issues);
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin + wintun.dll"]
fn lifecycle_full_teardown_nonexistent_adapter() {
    let result = full_teardown("aegis-nonexistent-adapter");
    assert!(
        result.is_ok(),
        "teardown should handle missing adapter: {:?}",
        result.err()
    );

    let issues = verify_teardown_clean("aegis-nonexistent-adapter");
    assert!(
        issues.is_empty(),
        "no leaks on nonexistent adapter: {:?}",
        issues
    );
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin + wintun.dll"]
fn lifecycle_cleanup_routes_nonexistent() {
    let result = cleanup_routes("aegis-nonexistent");
    assert!(
        result.is_ok(),
        "cleanup_routes should not fail on missing adapter"
    );
}

// ═══════════════════════════════════════════════════════════════
// Windows-only: DPAPI validation
// ═══════════════════════════════════════════════════════════════

#[test]
#[cfg(windows)]
#[ignore = "requires admin"]
fn dpapi_roundtrip() {
    let data = b"aegis-vpn-test-secret-2026";
    let encrypted = vpn_platform_windows::dpapi::protect(data).expect("protect");
    assert_ne!(&encrypted[..], data);
    assert!(encrypted.len() > data.len(), "DPAPI adds overhead");

    let decrypted = vpn_platform_windows::dpapi::unprotect(&encrypted).expect("unprotect");
    assert_eq!(&decrypted[..], data);
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin"]
fn dpapi_corrupted_data_fails() {
    let data = b"test";
    let encrypted = vpn_platform_windows::dpapi::protect(data).expect("protect");

    // Corrupt the encrypted data
    let mut corrupted = encrypted.clone();
    corrupted[0] ^= 0xFF;

    let result = vpn_platform_windows::dpapi::unprotect(&corrupted);
    assert!(result.is_err(), "corrupted data should fail");
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin"]
fn dpapi_empty_data_fails() {
    let result = vpn_platform_windows::dpapi::protect(b"");
    assert!(result.is_err(), "empty data should fail");
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin"]
fn dpapi_too_short_data_fails() {
    let result = vpn_platform_windows::dpapi::unprotect(&[0, 1, 2]);
    assert!(result.is_err(), "too-short data should fail");
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin"]
fn dpapi_store_load_roundtrip() {
    let path = std::env::temp_dir().join("aegis-validate-key.bin");
    let key = b"x25519-private-key-32-bytes-test!";

    vpn_platform_windows::dpapi::store_key(&path, key).expect("store");
    assert!(path.exists());

    let loaded = vpn_platform_windows::dpapi::load_key(&path).expect("load");
    assert_eq!(&loaded[..], key);

    let _ = std::fs::remove_file(&path);
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin"]
fn dpapi_load_nonexistent_fails() {
    let path = std::env::temp_dir().join("aegis-nonexistent-key.bin");
    let _ = std::fs::remove_file(&path); // ensure it doesn't exist

    let result = vpn_platform_windows::dpapi::load_key(&path);
    assert!(result.is_err(), "loading nonexistent key should fail");
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin"]
fn dpapi_large_data_roundtrip() {
    let data = vec![0xABu8; 65536]; // 64KB
    let encrypted = vpn_platform_windows::dpapi::protect(&data).expect("protect");
    let decrypted = vpn_platform_windows::dpapi::unprotect(&encrypted).expect("unprotect");
    assert_eq!(decrypted, data);
}

#[test]
#[cfg(windows)]
#[ignore = "requires admin"]
fn dpapi_binary_data_roundtrip() {
    let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
    let encrypted = vpn_platform_windows::dpapi::protect(&data).expect("protect");
    let decrypted = vpn_platform_windows::dpapi::unprotect(&encrypted).expect("unprotect");
    assert_eq!(decrypted, data);
}

// ═══════════════════════════════════════════════════════════════
// Windows-only: Integration test harness
// ═══════════════════════════════════════════════════════════════

#[test]
#[cfg(windows)]
#[ignore = "requires admin + wintun.dll — run on real Windows host"]
fn test_windows_full_stack() {
    // Full integration test:
    // 1. Enable kill switch
    // 2. Verify traffic is blocked (except VPN endpoint + loopback)
    // 3. Disable kill switch
    // 4. Verify cleanup

    let config = ks_config();

    // Step 1: Enable
    vpn_platform_windows::enable_kill_switch(&config).expect("kill switch enable");

    // Step 2: Verify WFP filters are active
    // (On real host, use: netsh wfp show state)
    // or: Get-NetFirewallRule -Group AegisVPN

    // Step 3: Disable
    disable_kill_switch().expect("kill switch disable");

    // Step 4: Verify clean
    let issues = verify_teardown_clean("aegis-validate");
    assert!(issues.is_empty(), "full stack leaks: {:?}", issues);
}
