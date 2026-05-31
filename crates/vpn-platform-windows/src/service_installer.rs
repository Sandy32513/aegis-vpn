// Windows service installation with security validation
#[cfg(windows)]
mod imp {
    use anyhow::{anyhow, Result};
    use std::{
        os::windows::process::CommandExt,
        path::{Path, PathBuf},
        process::Command,
    };

    pub struct ServiceInstaller;

    impl ServiceInstaller {
        /// Install a Windows service with security validation
        ///
        /// # Security Validations
        /// - service_name: alphanumeric, dash, underscore, dot only (max 256 chars)
        /// - daemon_path: must be absolute path, must exist, must be a file
        /// - config_path: if provided, must be absolute path
        /// - All paths quoted to handle spaces
        pub fn install(
            service_name: &str,
            display_name: &str,
            daemon_path: &Path,
            config_path: Option<&Path>,
        ) -> Result<()> {
            validate_service_name(service_name)?;
            validate_display_name(display_name)?;
            let daemon_path = validate_existing_file("daemon_path", daemon_path)?;
            let config_path = config_path
                .map(|config| validate_existing_file("config_path", config))
                .transpose()?;

            // SECURITY: Build binPath carefully to prevent sc.exe command injection
            // sc.exe parses binPath internally, so we quote paths and escape quotes
            let bin_path = if let Some(config) = &config_path {
                format!(
                    "\"{}\" service-run --config-path \"{}\"",
                    scm_quote(&daemon_path),
                    scm_quote(config)
                )
            } else {
                format!("\"{}\" service-run", scm_quote(&daemon_path))
            };

            // Install service using sc.exe
            run(
                "sc.exe",
                &[
                    "create",
                    service_name,
                    "type=",
                    "own",
                    "start=",
                    "auto",
                    "binPath=",
                    &bin_path,
                    "DisplayName=",
                    display_name,
                ],
            )?;

            // Set service description
            run(
                "sc.exe",
                &[
                    "description",
                    service_name,
                    "Aegis VPN privileged tunnel service",
                ],
            )?;

            // Use delayed auto-start so networking services can initialize first.
            run(
                "sc.exe",
                &["config", service_name, "start=", "delayed-auto"],
            )?;

            // Restrict the generated service SID when the OS supports it.
            run("sc.exe", &["sidtype", service_name, "restricted"])?;

            // Configure failure recovery: restart on crash
            run(
                "sc.exe",
                &[
                    "failure",
                    service_name,
                    "reset=",
                    "86400",
                    "actions=",
                    "restart/60000/restart/60000/restart/60000",
                ],
            )?;

            Ok(())
        }

        pub fn uninstall(service_name: &str) -> Result<()> {
            validate_service_name(service_name)?;

            // Stop service (ignore errors if not running)
            let _ = run("sc.exe", &["stop", service_name]);
            // Delete service
            run("sc.exe", &["delete", service_name])
        }
    }

    /// Run a command and check exit status
    fn run(program: &str, args: &[&str]) -> Result<()> {
        let program_path = match program.to_ascii_lowercase().as_str() {
            "sc.exe" => system32_path("sc.exe"),
            _ => PathBuf::from(program),
        };
        let output = Command::new(&program_path)
            .args(args)
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "{} failed (exit {}):\nstdout: {}\nstderr: {}",
                program_path.display(),
                output.status.code().unwrap_or(-1),
                stdout.trim(),
                stderr.trim()
            ));
        }
        Ok(())
    }

    fn validate_service_name(service_name: &str) -> Result<()> {
        if service_name.is_empty() || service_name.len() > 80 {
            return Err(anyhow!("service name must be 1-80 characters"));
        }
        if !service_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(anyhow!(
                "service name must be ASCII alphanumeric, dash, underscore, or dot only"
            ));
        }
        Ok(())
    }

    fn validate_display_name(display_name: &str) -> Result<()> {
        if display_name.is_empty() || display_name.len() > 256 {
            return Err(anyhow!("display name must be 1-256 characters"));
        }
        if display_name.chars().any(|c| c.is_control()) {
            return Err(anyhow!("display name cannot contain control characters"));
        }
        Ok(())
    }

    fn validate_existing_file(label: &str, path: &Path) -> Result<PathBuf> {
        if !path.is_absolute() {
            return Err(anyhow!("{label} must be absolute"));
        }
        if !path.is_file() {
            return Err(anyhow!("{label} is not a file: {}", path.display()));
        }
        path.canonicalize()
            .map_err(|e| anyhow!("failed to canonicalize {label} {}: {e}", path.display()))
    }

    fn scm_quote(path: &Path) -> String {
        path.display().to_string().replace('"', "\\\"")
    }

    fn system32_path(exe: &str) -> PathBuf {
        std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
            .join("System32")
            .join(exe)
    }
}

#[cfg(not(windows))]
mod imp {
    use anyhow::{anyhow, Result};
    use std::path::Path;

    pub struct ServiceInstaller;

    impl ServiceInstaller {
        pub fn install(_: &str, _: &str, _: &Path, _: Option<&Path>) -> Result<()> {
            Err(anyhow!(
                "Windows service installation is only available on Windows"
            ))
        }

        pub fn uninstall(_: &str) -> Result<()> {
            Err(anyhow!(
                "Windows service installation is only available on Windows"
            ))
        }
    }
}

pub use imp::ServiceInstaller;
