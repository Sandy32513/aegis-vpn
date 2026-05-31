use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    Run(RunConfig),
    ServiceRun {
        #[arg(long)]
        config_path: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:7788")]
        ipc_addr: String,
        #[arg(long, default_value = "AegisVpn")]
        service_name: String,
    },
    ServiceInstall {
        #[arg(long)]
        daemon_path: PathBuf,
        #[arg(long)]
        config_path: Option<PathBuf>,
        #[arg(long, default_value = "AegisVpn")]
        service_name: String,
        #[arg(long, default_value = "Aegis VPN")]
        display_name: String,
    },
    ServiceUninstall {
        #[arg(long, default_value = "AegisVpn")]
        service_name: String,
    },
    Ipc {
        #[arg(long, default_value = "127.0.0.1:7788")]
        ipc_addr: String,
        #[command(subcommand)]
        action: IpcAction,
    },
}

#[derive(Args, Debug, Clone)]
pub struct RunConfig {
    #[arg(long)]
    pub config_path: Option<PathBuf>,
    #[arg(long, default_value = "")]
    pub server: String,
    #[arg(long, default_value = "0.0.0.0:0")]
    pub bind: String,
    #[arg(long, default_value = "aegis0")]
    pub tun_name: String,
    #[arg(long, default_value = "10.20.0.2/24")]
    pub tun_addr: String,
    #[arg(long, default_value_t = 1400)]
    pub mtu: u32,
    #[arg(long, default_value = "127.0.0.1:7788")]
    pub ipc_addr: String,
    #[arg(long)]
    pub log_file: Option<PathBuf>,
    #[arg(long, default_value_t = true)]
    pub kill_switch: bool,
    #[arg(long, default_value_t = 3)]
    pub hops: usize,
    #[arg(long)]
    pub admin_secret_env: Option<String>,
    #[arg(long, default_value_t = false)]
    pub safe_mode: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum IpcAction {
    Connect,
    Disconnect {
        #[arg(long)]
        admin_secret: Option<String>,
    },
    Status,
    Metrics,
}
