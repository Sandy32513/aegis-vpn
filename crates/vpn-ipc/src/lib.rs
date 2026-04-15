use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};
use tracing::{error, warn};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub connected: bool,
    pub server: Option<String>,
    pub session_id: Option<u64>,
    pub active_circuit: Option<String>,
    pub rotation_state: Option<String>,
    pub mode: Option<String>,
    pub last_error: Option<String>,
    pub last_transition_at: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DaemonMetrics {
    pub mode: String,
    pub uptime_secs: u64,
    pub last_connect_latency_ms: Option<u64>,
    pub packets_tx: u64,
    pub packets_rx: u64,
    pub request_count: u64,
    pub error_count: u64,
    pub error_rate: f64,
    pub connect_count: u64,
    pub disconnect_count: u64,
    pub last_transition_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IpcRequest {
    Connect,
    Disconnect { admin_secret: Option<String> },
    Status,
    Metrics,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IpcResponse {
    Ok { message: String },
    Status { status: DaemonStatus },
    Metrics { metrics: DaemonMetrics },
    Error { message: String },
}

pub async fn serve(
    bind_addr: &str,
    tx: mpsc::Sender<(IpcRequest, oneshot::Sender<IpcResponse>)>,
) -> Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client(stream, tx).await {
                warn!("ipc client handler error: {err}");
            }
        });
    }
}

pub async fn request(addr: &str, req: IpcRequest) -> Result<IpcResponse> {
    let mut stream = TcpStream::connect(addr).await?;
    let line = serde_json::to_string(&req)?;
    stream.write_all(line.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response).await?;
    Ok(serde_json::from_str(response.trim())?)
}

async fn handle_client(
    stream: TcpStream,
    tx: mpsc::Sender<(IpcRequest, oneshot::Sender<IpcResponse>)>,
) -> Result<()> {
    let (reader_half, mut writer_half) = stream.into_split();
    let mut reader = BufReader::new(reader_half);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let req: IpcRequest = serde_json::from_str(line.trim())?;
        let (resp_tx, resp_rx) = oneshot::channel();
        if tx.send((req, resp_tx)).await.is_err() {
            error!("ipc command channel closed");
            break;
        }

        let resp = match resp_rx.await {
            Ok(resp) => resp,
            Err(_) => IpcResponse::Error {
                message: "daemon did not respond".to_string(),
            },
        };

        let payload = serde_json::to_string(&resp)?;
        writer_half.write_all(payload.as_bytes()).await?;
        writer_half.write_all(b"\n").await?;
        writer_half.flush().await?;
        line.clear();
    }

    Ok(())
}
