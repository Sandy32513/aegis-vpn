use anyhow::{anyhow, Result};
use bincode::Options;
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
use vpn_crypto::{HandshakeConfirm, HandshakeInit, HandshakeResponse, SealedPayload};

const MAX_FRAME_BYTES: usize = 16 * 1024;

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
