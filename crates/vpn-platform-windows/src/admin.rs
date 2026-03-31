// ═══════════════════════════════════════════════════════════════
// PART 2: Centralized Admin Privilege Detection
// ═══════════════════════════════════════════════════════════════

#[cfg(windows)]
mod imp {
    use std::sync::OnceLock;
    use tracing::info;

    static IS_ADMIN: OnceLock<bool> = OnceLock::new();

    /// Check if the current process has administrator privileges.
    /// Result is cached after first call — no repeated syscalls.
    pub fn is_admin() -> bool {
        *IS_ADMIN.get_or_init(|| {
            let result = check_admin_inner();
            info!("admin privilege detection: is_admin={}", result);
            result
        })
    }

    fn check_admin_inner() -> bool {
        use std::ptr::null_mut;
        use windows_sys::Win32::Security::{
            AllocateAndInitializeSid, CheckTokenMembership, FreeSid, SECURITY_NT_AUTHORITY,
        };

        unsafe {
            let mut sid = null_mut();
            let mut authority = SECURITY_NT_AUTHORITY;
            let success = AllocateAndInitializeSid(
                &mut authority as *mut _,
                2,
                0x00000020,
                0x00000220,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut sid,
            );
            if success == 0 {
                return false;
            }

            let mut is_member: i32 = 0;
            CheckTokenMembership(null_mut(), sid, &mut is_member);
            FreeSid(sid);

            is_member != 0
        }
    }

    /// Check if the current process can open an elevated token.
    pub fn has_elevated_token() -> bool {
        use std::ptr::null_mut;
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
        use windows_sys::Win32::Security::TOKEN_QUERY;
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        unsafe {
            let mut token: HANDLE = null_mut();
            let success = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token);
            if success == 0 {
                return false;
            }

            if !token.is_null() {
                CloseHandle(token);
            }

            true
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use tracing::info;

    /// On non-Windows, check if running as root (UID 0).
    pub fn is_admin() -> bool {
        let result = unsafe { libc::geteuid() == 0 };
        info!("admin privilege detection (unix): is_admin={}", result);
        result
    }

    pub fn has_elevated_token() -> bool {
        is_admin()
    }
}

pub use imp::{has_elevated_token, is_admin};
