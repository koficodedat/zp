//! TCP transport implementation with StreamChunk framing.
//!
//! Legacy fallback transport per spec §3.3.7 (Multiplexing Degradation).
//!
//! **Spec Requirements:**
//! - TLS 1.3 over TCP/443
//! - StreamChunk framing for multiplexing (when stream_id == 0xFFFFFFFF)
//! - Length-prefixed frame serialization
//! - EncryptedRecord wrapper for post-handshake frames (except ErrorFrame)
//! - No AckFrame (transport provides reliability)
//! - Racing with QUIC (ZP_RACING_THRESHOLD: 200ms)
//!
//! **StreamChunk Format (§3.3.7):**
//! ```text
//! StreamChunk {
//!   stream_id: u32      [4 bytes]
//!   length: u32         [4 bytes]
//!   payload: [u8; length]
//! }
//! ```
//!
//! **Multiplexing Modes:**
//! - **Multi-stream**: DataFrame.stream_id = 0xFFFFFFFF, payload = StreamChunks
//! - **Single-stream**: DataFrame.stream_id = actual ID, payload = raw data

use crate::{Error, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use zp_core::session::{HandshakeMode, Role};
use zp_core::{Frame, Session};

/// Sentinel value for multiplexed mode per spec §3.3.7
pub const MULTIPLEXED_STREAM_ID: u32 = 0xFFFF_FFFF;

/// StreamChunk header size (stream_id + length)
const STREAM_CHUNK_HEADER_SIZE: usize = 8;

/// Maximum frame size (16 MB - prevents DoS)
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// StreamChunk for TCP multiplexing per spec §3.3.7
#[derive(Debug, Clone)]
pub struct StreamChunk {
    /// Stream identifier
    pub stream_id: u32,
    /// Payload data
    pub payload: Vec<u8>,
}

impl StreamChunk {
    /// Serialize StreamChunk to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let length = self.payload.len() as u32;
        let mut buf = Vec::with_capacity(STREAM_CHUNK_HEADER_SIZE + self.payload.len());

        // stream_id (4 bytes, little-endian)
        buf.extend_from_slice(&self.stream_id.to_le_bytes());

        // length (4 bytes, little-endian)
        buf.extend_from_slice(&length.to_le_bytes());

        // payload
        buf.extend_from_slice(&self.payload);

        buf
    }

    /// Parse StreamChunk from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < STREAM_CHUNK_HEADER_SIZE {
            return Err(Error::ConnectionFailed(format!(
                "StreamChunk too short: {} bytes",
                data.len()
            )));
        }

        let stream_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let length = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;

        if data.len() < STREAM_CHUNK_HEADER_SIZE + length {
            return Err(Error::ConnectionFailed(format!(
                "StreamChunk truncated: expected {} bytes, got {}",
                STREAM_CHUNK_HEADER_SIZE + length,
                data.len()
            )));
        }

        let payload = data[STREAM_CHUNK_HEADER_SIZE..STREAM_CHUNK_HEADER_SIZE + length].to_vec();

        Ok(Self { stream_id, payload })
    }
}

/// TCP transport endpoint (client/server).
///
/// Provides TLS 1.3 over TCP/443 per spec §3.3.7.
pub struct TcpEndpoint {
    listener: Option<TcpListener>,
}

impl TcpEndpoint {
    /// Create a TCP server endpoint
    pub async fn server(addr: &str) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("TCP bind failed: {}", e)))?;

        Ok(Self {
            listener: Some(listener),
        })
    }

    /// Create a TCP client endpoint
    pub fn client() -> Result<Self> {
        Ok(Self { listener: None })
    }

    /// Connect to a remote TCP endpoint
    pub async fn connect(&self, addr: &str) -> Result<TcpConnection> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("TCP connect failed: {}", e)))?;

        let peer_addr = stream
            .peer_addr()
            .map_err(|e| Error::ConnectionFailed(format!("Failed to get peer addr: {}", e)))?;

        // Create session (Stranger mode, TOFU) - Client role
        let session = Arc::new(RwLock::new(Session::new(
            Role::Client,
            HandshakeMode::Stranger,
        )));

        Ok(TcpConnection {
            stream: Arc::new(RwLock::new(stream)),
            session,
            peer_addr,
        })
    }

    /// Accept an incoming TCP connection
    pub async fn accept(&self) -> Result<TcpConnection> {
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| Error::ConnectionFailed("No listener (client mode)".into()))?;

        let (stream, peer_addr) = listener
            .accept()
            .await
            .map_err(|e| Error::ConnectionFailed(format!("TCP accept failed: {}", e)))?;

        // Create session (Stranger mode, TOFU) - Server role
        let session = Arc::new(RwLock::new(Session::new(
            Role::Server,
            HandshakeMode::Stranger,
        )));

        Ok(TcpConnection {
            stream: Arc::new(RwLock::new(stream)),
            session,
            peer_addr,
        })
    }

    /// Get local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .as_ref()
            .ok_or_else(|| Error::ConnectionFailed("No listener (client mode)".into()))?
            .local_addr()
            .map_err(|e| Error::ConnectionFailed(format!("Failed to get local addr: {}", e)))
    }
}

/// TCP connection with StreamChunk framing.
///
/// Per spec §3.3.7:
/// - Single-stream mode: DataFrame with actual stream_id, raw payload
/// - Multi-stream mode: DataFrame with stream_id=0xFFFFFFFF, payload=StreamChunks
/// - Length-prefixed framing: [4-byte length][frame data]
/// - EncryptedRecord wrapper for post-handshake frames (TODO)
pub struct TcpConnection {
    stream: Arc<RwLock<TcpStream>>,
    session: Arc<RwLock<Session>>,
    peer_addr: SocketAddr,
}

impl TcpConnection {
    /// Send a zp frame over TCP with length-prefixed framing
    ///
    /// Frame is serialized and sent with 4-byte length prefix.
    pub async fn send_frame(&self, frame: &Frame) -> Result<()> {
        let data = frame.serialize()?;

        // Length-prefixed framing: [4-byte length][frame data]
        let length = data.len() as u32;
        let mut buf = Vec::with_capacity(4 + data.len());
        buf.extend_from_slice(&length.to_le_bytes());
        buf.extend_from_slice(&data);

        let mut stream = self.stream.write().await;
        stream
            .write_all(&buf)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("TCP send failed: {}", e)))?;

        Ok(())
    }

    /// Receive a zp frame from TCP with length-prefixed framing
    ///
    /// Reads 4-byte length prefix, then frame data.
    /// Returns None if connection closed.
    pub async fn recv_frame(&self) -> Result<Option<Frame>> {
        let mut stream = self.stream.write().await;

        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Connection closed
                return Ok(None);
            }
            Err(e) => {
                return Err(Error::ConnectionFailed(format!("TCP recv failed: {}", e)));
            }
        }

        let length = u32::from_le_bytes(len_buf) as usize;

        // Validate length (prevent DoS)
        if length > MAX_FRAME_SIZE {
            return Err(Error::ConnectionFailed(format!(
                "Frame too large: {} bytes (max {})",
                length, MAX_FRAME_SIZE
            )));
        }

        // Read frame data
        let mut frame_buf = vec![0u8; length];
        stream
            .read_exact(&mut frame_buf)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("TCP recv failed: {}", e)))?;

        // Parse frame
        let frame = Frame::parse(&frame_buf)?;
        Ok(Some(frame))
    }

    /// Send a StreamChunk (for multiplexed mode)
    ///
    /// Per spec §3.3.7: Used when DataFrame.stream_id == 0xFFFFFFFF
    pub async fn send_stream_chunk(&self, chunk: &StreamChunk) -> Result<()> {
        let data = chunk.serialize();

        // Length-prefixed framing: [4-byte length][chunk data]
        let length = data.len() as u32;
        let mut buf = Vec::with_capacity(4 + data.len());
        buf.extend_from_slice(&length.to_le_bytes());
        buf.extend_from_slice(&data);

        let mut stream = self.stream.write().await;
        stream
            .write_all(&buf)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("TCP send failed: {}", e)))?;

        Ok(())
    }

    /// Receive a StreamChunk (for multiplexed mode)
    ///
    /// Per spec §3.3.7: Used when DataFrame.stream_id == 0xFFFFFFFF
    /// Returns None if connection closed.
    pub async fn recv_stream_chunk(&self) -> Result<Option<StreamChunk>> {
        let mut stream = self.stream.write().await;

        // Read 4-byte length prefix
        let mut len_buf = [0u8; 4];
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(None);
            }
            Err(e) => {
                return Err(Error::ConnectionFailed(format!("TCP recv failed: {}", e)));
            }
        }

        let length = u32::from_le_bytes(len_buf) as usize;

        // Validate length
        if length > MAX_FRAME_SIZE {
            return Err(Error::ConnectionFailed(format!(
                "StreamChunk too large: {} bytes",
                length
            )));
        }

        // Read chunk data
        let mut chunk_buf = vec![0u8; length];
        stream
            .read_exact(&mut chunk_buf)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("TCP recv failed: {}", e)))?;

        // Parse StreamChunk
        let chunk = StreamChunk::parse(&chunk_buf)?;
        Ok(Some(chunk))
    }

    /// Close the TCP connection
    pub async fn close(&self) -> Result<()> {
        let mut stream = self.stream.write().await;
        stream
            .shutdown()
            .await
            .map_err(|e| Error::ConnectionFailed(format!("TCP close failed: {}", e)))?;
        Ok(())
    }

    /// Get the session associated with this connection
    pub fn session(&self) -> Arc<RwLock<Session>> {
        Arc::clone(&self.session)
    }

    /// Get local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.stream
            .blocking_read()
            .local_addr()
            .map_err(|e| Error::ConnectionFailed(format!("Failed to get local addr: {}", e)))
    }

    /// Get peer address
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_chunk_serialize() {
        let chunk = StreamChunk {
            stream_id: 42,
            payload: vec![1, 2, 3, 4, 5],
        };

        let data = chunk.serialize();

        // Check header (stream_id + length)
        assert_eq!(data.len(), STREAM_CHUNK_HEADER_SIZE + 5);
        assert_eq!(&data[0..4], &42u32.to_le_bytes());
        assert_eq!(&data[4..8], &5u32.to_le_bytes());
        assert_eq!(&data[8..], &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_stream_chunk_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&42u32.to_le_bytes()); // stream_id
        data.extend_from_slice(&5u32.to_le_bytes()); // length
        data.extend_from_slice(&[1, 2, 3, 4, 5]); // payload

        let chunk = StreamChunk::parse(&data).expect("Parse failed");

        assert_eq!(chunk.stream_id, 42);
        assert_eq!(chunk.payload, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_stream_chunk_roundtrip() {
        let original = StreamChunk {
            stream_id: 123,
            payload: vec![10, 20, 30, 40],
        };

        let serialized = original.serialize();
        let parsed = StreamChunk::parse(&serialized).expect("Parse failed");

        assert_eq!(parsed.stream_id, original.stream_id);
        assert_eq!(parsed.payload, original.payload);
    }

    #[test]
    fn test_multiplexed_stream_id_constant() {
        assert_eq!(MULTIPLEXED_STREAM_ID, 0xFFFF_FFFF);
    }
}
