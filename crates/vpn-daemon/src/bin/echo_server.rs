use anyhow::Result;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    vpn_logger::init_tracing();
    let config_path = std::env::args().nth(1).map(PathBuf::from);
    vpn_daemon::run_vpn_server(config_path.as_ref(), None).await
}
