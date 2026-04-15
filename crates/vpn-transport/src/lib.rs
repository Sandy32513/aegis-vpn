use anyhow::{anyhow, Result};
use bincode::Options;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{info, warn};
use vpn_crypto::{HandshakeConfirm, HandshakeInit, HandshakeResponse, SealedPayload};

const MAX_FRAME_BYTES: usize = 16 * 1024;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const TCP_RECV_BUF_SIZE: usize = 32 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DataFrame {
    pub session_id: u64,
    pub epoch: u32,
    pub path_id: u32,
    pub packet_type: u8,
    pub counter: u64,
    pub plaintext_len: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum WireFrame {
    HandshakeInit(HandshakeInit),
    HandshakeResponse(HandshakeResponse),
    HandshakeConfirm(HandshakeConfirm),
    HandshakeAck(HandshakeConfirm),
    Data(DataFrame),
    Keepalive { session_id: u64 },
}

impl DataFrame {
    pub fn from_sealed(
        session_id: u64,
        epoch: u32,
        path_id: u32,
        packet_type: u8,
        sealed: SealedPayload,
    ) -> Self {
        Self {
            session_id,
            epoch,
            path_id,
            packet_type,
            counter: sealed.counter,
            plaintext_len: sealed.plaintext_len,
            payload: sealed.ciphertext,
        }
    }
}

#[derive(Clone)]
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
}

impl UdpTransport {
    pub async fn bind(bind_addr: &str) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        Ok(Self {
            socket: Arc::new(socket),
        })
    }

    pub async fn connect(bind_addr: &str, remote: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(remote).await?;
        Ok(Self {
            socket: Arc::new(socket),
        })
    }

    pub fn socket(&self) -> Arc<UdpSocket> {
        Arc::clone(&self.socket)
    }

    pub async fn send_frame(&self, frame: &WireFrame) -> Result<usize> {
        let bytes = wire_options().serialize(frame)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(anyhow!("frame exceeds max size of {MAX_FRAME_BYTES} bytes"));
        }
        Ok(self.socket.send(&bytes).await?)
    }

    pub async fn send_frame_to(&self, frame: &WireFrame, remote: SocketAddr) -> Result<usize> {
        let bytes = wire_options().serialize(frame)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(anyhow!("frame exceeds max size of {MAX_FRAME_BYTES} bytes"));
        }
        Ok(self.socket.send_to(&bytes, remote).await?)
    }

    pub async fn recv_frame(&self) -> Result<(WireFrame, SocketAddr)> {
        let mut buf = vec![0u8; MAX_FRAME_BYTES];
        let (size, peer) = self.socket.recv_from(&mut buf).await?;
        let frame = wire_options()
            .deserialize::<WireFrame>(&buf[..size])
            .map_err(|e| anyhow!("wire decode failed: {e}"))?;
        Ok((frame, peer))
    }
}

#[derive(Clone)]
pub struct TcpTransport {
    stream: Arc<RwLock<TcpStream>>,
    remote: SocketAddr,
    connected: Arc<AtomicBool>,
    reconnect_attempts: Arc<AtomicU32>,
    config: TcpTransportConfig,
}

#[derive(Clone, Debug)]
pub struct TcpTransportConfig {
    pub connect_timeout: Duration,
    pub keepalive_interval: Duration,
    pub max_reconnect_attempts: u32,
    pub base_reconnect_delay: Duration,
    pub max_reconnect_delay: Duration,
}

impl Default for TcpTransportConfig {
    fn default() -> Self {
        Self {
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            max_reconnect_attempts: 3,
            base_reconnect_delay: Duration::from_millis(100),
            max_reconnect_delay: Duration::from_secs(10),
        }
    }
}

impl TcpTransport {
    pub async fn connect(remote: SocketAddr, config: TcpTransportConfig) -> Result<Self> {
        Self::connect_with_retry(remote, &config, 0).await
    }

    async fn connect_with_retry(remote: SocketAddr, config: &TcpTransportConfig, attempt: u32) -> Result<Self> {
        let connect_result = tokio::time::timeout(
            config.connect_timeout,
            TcpStream::connect(remote),
        )
        .await;

        match connect_result {
            Ok(Ok(stream)) => {
                let transport = Self {
                    stream: Arc::new(RwLock::new(stream)),
                    remote,
                    connected: Arc::new(AtomicBool::new(true)),
                    reconnect_attempts: Arc::new(AtomicU32::new(0)),
                    config: config.clone(),
                };
                transport.setup_keepalive().await?;
                info!("tcp: connected to {}", remote);
                Ok(transport)
            }
            Ok(Err(e)) => {
                if attempt < config.max_reconnect_attempts {
                    let delay = Self::calculate_backoff(attempt, config.base_reconnect_delay, config.max_reconnect_delay);
                    warn!("tcp: connection failed (attempt {}/{}), retrying in {:?}: {}", 
                        attempt + 1, config.max_reconnect_attempts, delay, e);
                    tokio::time::sleep(delay).await;
                    return Self::connect_with_retry(remote, config, attempt + 1).await;
                }
                Err(anyhow!("tcp: failed to connect to {} after {} attempts: {}", remote, config.max_reconnect_attempts, e))
            }
            Err(_) => {
                Err(anyhow!("tcp: connection timeout after {:?}", config.connect_timeout))
            }
        }
    }

    fn calculate_backoff(attempt: u32, base: Duration, max: Duration) -> Duration {
        let delay_ms = 100u64 * 2u64.pow(attempt).min(10240);
        let delay = Duration::from_millis(delay_ms.min(max.as_millis() as u64));
        delay.min(max)
    }

    async fn setup_keepalive(&self) -> Result<()> {
        let mut stream = self.stream.write();
        if let Err(e) = stream.set_keepalive(Some(self.config.keepalive_interval)) {
            warn!("tcp: failed to set keepalive: {}", e);
        }
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    pub async fn reconnect(&self) -> Result<()> {
        if self.connected.load(Ordering::SeqCst) {
            return Ok(());
        }

        let attempts = self.reconnect_attempts.fetch_add(1, Ordering::SeqCst);
        if attempts >= self.config.max_reconnect_attempts {
            return Err(anyhow!("tcp: max reconnect attempts exceeded"));
        }

        info!("tcp: attempting reconnect to {}", self.remote);
        
        match tokio::time::timeout(
            self.config.connect_timeout,
            TcpStream::connect(self.remote),
        ).await {
            Ok(Ok(stream)) => {
                let mut current = self.stream.write();
                *current = stream;
                self.connected.store(true, Ordering::SeqCst);
                self.reconnect_attempts.store(0, Ordering::SeqCst);
                self.setup_keepalive().await?;
                info!("tcp: reconnected to {}", self.remote);
                Ok(())
            }
            Ok(Err(e)) => Err(anyhow!("tcp: reconnect failed: {}", e)),
            Err(_) => Err(anyhow!("tcp: reconnect timeout")),
        }
    }

    pub async fn send_frame(&self, frame: &WireFrame) -> Result<usize> {
        if !self.is_connected() {
            self.reconnect().await?;
        }

        let bytes = wire_options().serialize(frame)?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(anyhow!("frame exceeds max size of {MAX_FRAME_BYTES} bytes"));
        }

        let mut stream = self.stream.write();
        
        let len_bytes = (bytes.len() as u32).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        let written = stream.write_all(&bytes).await?;
        
        stream.flush().await?;
        
        Ok(bytes.len())
    }

    pub async fn recv_frame(&self) -> Result<WireFrame> {
        if !self.is_connected() {
            self.reconnect().await?;
        }

        let mut stream = self.stream.write();
        
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        if len > MAX_FRAME_BYTES || len == 0 {
            return Err(anyhow!("tcp: invalid frame size: {}", len));
        }
        
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        
        let frame = wire_options()
            .deserialize::<WireFrame>(&buf)
            .map_err(|e| anyhow!("wire decode failed: {e}"))?;
        
        Ok(frame)
    }

    pub async fn close(&self) -> Result<()> {
        self.connected.store(false, Ordering::SeqCst);
        let mut stream = self.stream.write();
        stream.shutdown().await?;
        Ok(())
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }
}

pub enum Transport {
    Udp(UdpTransport),
    Tcp(TcpTransport),
}

impl Transport {
    pub async fn send_frame(&self, frame: &WireFrame) -> Result<usize> {
        match self {
            Transport::Udp(t) => t.send_frame(frame).await,
            Transport::Tcp(t) => t.send_frame(frame).await,
        }
    }
}

fn wire_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_FRAME_BYTES as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_frame_round_trip() {
        let frame = WireFrame::Keepalive { session_id: 42 };
        let bytes = wire_options()
            .serialize(&frame)
            .expect("serialize keepalive");
        let decoded = wire_options()
            .deserialize::<WireFrame>(&bytes)
            .expect("deserialize keepalive");

        assert!(matches!(decoded, WireFrame::Keepalive { session_id } if session_id == 42));
    }
}
