use anyhow::Result;
use clap::Parser;
use vpn_daemon::{
    config::{Cli, Command, IpcAction},
    install_service_command, run_controller, run_daemon, run_service_command,
    uninstall_service_command,
};

#[tokio::main]
async fn main() -> Result<()> {
    vpn_logger::init_tracing();
    let cli = Cli::parse();

    match cli.command {
        None => run_controller().await,
        Some(Command::Run(config)) => run_daemon(config).await,
        Some(Command::ServiceRun {
            config_path,
            ipc_addr,
            service_name,
        }) => run_service_command(config_path, ipc_addr, service_name),
        Some(Command::ServiceInstall {
            daemon_path,
            config_path,
            service_name,
            display_name,
        }) => install_service_command(
            &daemon_path,
            config_path.as_deref(),
            &service_name,
            &display_name,
        ),
        Some(Command::ServiceUninstall { service_name }) => {
            uninstall_service_command(&service_name)
        }
        Some(Command::Ipc { ipc_addr, action }) => {
            let request = match action {
                IpcAction::Connect => vpn_ipc::IpcRequest::Connect,
                IpcAction::Disconnect { admin_secret } => {
                    vpn_ipc::IpcRequest::Disconnect { admin_secret }
                }
                IpcAction::Status => vpn_ipc::IpcRequest::Status,
                IpcAction::Metrics => vpn_ipc::IpcRequest::Metrics,
            };
            let response = vpn_ipc::request(&ipc_addr, request).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(())
        }
    }
}
