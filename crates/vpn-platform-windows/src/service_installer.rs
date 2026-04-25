// Windows service installation with security validation
#[cfg(windows)]
mod imp {
    use anyhow::{anyhow, Result};
    use std::{path::Path, process::Command};

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
            // Validate service name: prevent command injection via sc.exe
            if service_name.is_empty() || service_name.len() > 256 {
                return Err(anyhow!("service name must be 1-256 characters"));
            }
            if !service_name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
            {
                return Err(anyhow!(
                    "service name must be alphanumeric, dash, underscore, or dot only"
                ));
            }

            // Validate display name length
            if display_name.len() > 256 {
                return Err(anyhow!("display name too long (max 256 characters)"));
            }

            // Validate daemon path: must be absolute and exist
            if !daemon_path.is_absolute() {
                return Err(anyhow!("daemon_path must be absolute"));
            }
            if !daemon_path.exists() {
                return Err(anyhow!(
                    "daemon binary not found: {}",
                    daemon_path.display()
                ));
            }
            if !daemon_path.is_file() {
                return Err(anyhow!(
                    "daemon path is not a file: {}",
                    daemon_path.display()
                ));
            }

            // Validate config path if provided
            if let Some(config) = config_path {
                if !config.is_absolute() {
                    return Err(anyhow!("config_path must be absolute if provided"));
                }
            }

            // SECURITY: Build binPath carefully to prevent sc.exe command injection
            // sc.exe parses binPath internally, so we quote paths and escape quotes
            let bin_path = if let Some(config) = config_path {
                format!(
                    "\"{}\" service-run --config-path \"{}\"",
                    daemon_path.display().replace('"', "\\\""),
                    config.display().replace('"', "\\\"")
                )
            } else {
                format!(
                    "\"{}\" service-run",
                    daemon_path.display().replace('"', "\\\"")
                )
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
            // Validate service name
            if service_name.is_empty() || service_name.len() > 256 {
                return Err(anyhow!("service name must be 1-256 characters"));
            }
            if !service_name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
            {
                return Err(anyhow!("invalid service name"));
            }

            // Stop service (ignore errors if not running)
            let _ = run("sc.exe", &["stop", service_name]);
            // Delete service
            run("sc.exe", &["delete", service_name])
        }
    }

    /// Run a command and check exit status
    fn run(program: &str, args: &[&str]) -> Result<()> {
        let output = Command::new(program)
            .args(args)
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(anyhow!(
                "{} failed (exit {}):\nstdout: {}\nstderr: {}",
                program,
                output.status.code().unwrap_or(-1),
                stdout.trim(),
                stderr.trim()
            ));
        }
        Ok(())
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
