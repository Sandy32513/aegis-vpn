#[cfg(windows)]
mod imp {
    use anyhow::{anyhow, Result};
    use std::{path::Path, process::Command};

    pub struct ServiceInstaller;

    impl ServiceInstaller {
        pub fn install(
            service_name: &str,
            display_name: &str,
            daemon_path: &Path,
            config_path: Option<&Path>,
        ) -> Result<()> {
            let mut bin_path = format!("\"{}\" service-run", daemon_path.display());
            if let Some(config_path) = config_path {
                bin_path.push_str(&format!(" --config-path \"{}\"", config_path.display()));
            }

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
            run(
                "sc.exe",
                &[
                    "description",
                    service_name,
                    "Aegis VPN privileged tunnel service",
                ],
            )?;
            Ok(())
        }

        pub fn uninstall(service_name: &str) -> Result<()> {
            let _ = run("sc.exe", &["stop", service_name]);
            run("sc.exe", &["delete", service_name])
        }
    }

    fn run(program: &str, args: &[&str]) -> Result<()> {
        let status = Command::new(program).args(args).status()?;
        if !status.success() {
            return Err(anyhow!("{program} {:?} failed with status {status}", args));
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
