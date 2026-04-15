#[cfg(windows)]
mod imp {
    use crate::{config::RunConfig, run_daemon};
    use anyhow::{anyhow, Result};
    use std::{
        ffi::OsString,
        path::{Path, PathBuf},
        sync::{mpsc, OnceLock},
        time::Duration,
    };
    use vpn_ipc::IpcRequest;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    static SERVICE_ARGS: OnceLock<ServiceArgs> = OnceLock::new();
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
    #[derive(Clone, Debug)]
    struct ServiceArgs {
        config_path: Option<PathBuf>,
        ipc_addr: String,
        service_name: String,
    }

    define_windows_service!(ffi_service_main, service_main);

    pub fn run_service_command(
        config_path: Option<PathBuf>,
        ipc_addr: String,
        service_name: String,
    ) -> Result<()> {
        let _ = SERVICE_ARGS.set(ServiceArgs {
            config_path,
            ipc_addr,
            service_name: service_name.clone(),
        });
        service_dispatcher::start(&service_name, ffi_service_main)?;
        Ok(())
    }

    pub fn install_service_command(
        daemon_path: &Path,
        config_path: Option<&Path>,
        service_name: &str,
        display_name: &str,
    ) -> Result<()> {
        vpn_platform_windows::service_installer::ServiceInstaller::install(
            service_name,
            display_name,
            daemon_path,
            config_path,
        )
    }

    pub fn uninstall_service_command(service_name: &str) -> Result<()> {
        vpn_platform_windows::service_installer::ServiceInstaller::uninstall(service_name)
    }

    fn service_main(_arguments: Vec<OsString>) {
        let _ = run_service_worker();
    }

    fn run_service_worker() -> Result<()> {
        let args = SERVICE_ARGS
            .get()
            .cloned()
            .ok_or_else(|| anyhow!("service arguments were not initialized"))?;
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
        let service_name = args.service_name.clone();

        let status_handle =
            service_control_handler::register(&service_name, move |control_event| {
                match control_event {
                    ServiceControl::Stop => {
                        let _ = shutdown_tx.send(());
                        ServiceControlHandlerResult::NoError
                    }
                    ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                    _ => ServiceControlHandlerResult::NotImplemented,
                }
            })?;

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async move {
            let daemon_config = RunConfig {
                config_path: args.config_path.clone(),
                server: String::new(),
                bind: "0.0.0.0:0".to_string(),
                tun_name: "aegis0".to_string(),
                tun_addr: "10.20.0.2/24".to_string(),
                mtu: 1400,
                ipc_addr: args.ipc_addr.clone(),
                log_file: None,
                kill_switch: true,
                hops: 3,
                admin_secret_env: None,
                safe_mode: false,
            };

            let mut daemon_task = tokio::spawn(run_daemon(daemon_config));
            let mut stop_wait = tokio::task::spawn_blocking(move || shutdown_rx.recv());

            tokio::select! {
                _ = &mut stop_wait => {
                    let _ = vpn_ipc::request(&args.ipc_addr, IpcRequest::Disconnect { admin_secret: None }).await;
                    let _ = daemon_task.await;
                }
                daemon_result = &mut daemon_task => {
                    let _ = daemon_result;
                }
            }
        });

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        Ok(())
    }
}

#[cfg(not(windows))]
mod imp {
    use anyhow::{anyhow, Result};
    use std::path::{Path, PathBuf};

    pub fn run_service_command(_: Option<PathBuf>, _: String, _: String) -> Result<()> {
        Err(anyhow!(
            "Windows service hosting is only available on Windows"
        ))
    }

    pub fn install_service_command(_: &Path, _: Option<&Path>, _: &str, _: &str) -> Result<()> {
        Err(anyhow!(
            "Windows service installation is only available on Windows"
        ))
    }

    pub fn uninstall_service_command(_: &str) -> Result<()> {
        Err(anyhow!(
            "Windows service installation is only available on Windows"
        ))
    }
}

pub use imp::{install_service_command, run_service_command, uninstall_service_command};
