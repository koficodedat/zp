//! Frame parsing and serialization.
//!
//! Implements all 12 frame types from spec §3.3:
//! - ClientHello, ServerHello
//! - KeyExchange, KeyExchangeResponse
//! - Finished
//! - StreamChunk, StreamClose
//! - PriorityUpdate
//! - WindowUpdate
//! - Ping, Pong
//! - ErrorFrame

use crate::{Error, Result};

/// Protocol frame types per spec §3.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// ClientHello (0x01) - Initiates handshake.
    ClientHello {
        /// Protocol version (e.g., 1.0).
        version: (u8, u8),
        /// Random nonce (32 bytes).
        random: [u8; 32],
        /// Supported cipher suites in preference order.
        cipher_suites: Vec<u16>,
    },

    /// ServerHello (0x02) - Responds to ClientHello.
    ServerHello {
        /// Selected protocol version.
        version: (u8, u8),
        /// Random nonce (32 bytes).
        random: [u8; 32],
        /// Selected cipher suite.
        cipher_suite: u16,
    },

    /// KeyExchange (0x03) - Client's key material.
    KeyExchange {
        /// X25519/ECDH public key.
        classical_public: Vec<u8>,
        /// ML-KEM public key (if post-quantum suite).
        pq_public: Option<Vec<u8>>,
    },

    /// KeyExchangeResponse (0x04) - Server's key material.
    KeyExchangeResponse {
        /// X25519/ECDH public key.
        classical_public: Vec<u8>,
        /// ML-KEM ciphertext (if post-quantum suite).
        pq_ciphertext: Option<Vec<u8>>,
    },

    /// Finished (0x05) - Handshake completion proof.
    Finished {
        /// HMAC over handshake transcript.
        verify_data: [u8; 32],
    },

    /// StreamChunk (0x06) - Application data.
    StreamChunk {
        /// Stream identifier.
        stream_id: u32,
        /// Payload data.
        data: Vec<u8>,
    },

    /// StreamClose (0x07) - Close stream.
    StreamClose {
        /// Stream identifier.
        stream_id: u32,
    },

    /// PriorityUpdate (0x08) - Update stream priority.
    PriorityUpdate {
        /// Stream identifier.
        stream_id: u32,
        /// Priority (1-255, higher is more urgent).
        priority: u8,
    },

    /// WindowUpdate (0x09) - Flow control.
    WindowUpdate {
        /// Stream identifier (0 = connection-level).
        stream_id: u32,
        /// Window increment in bytes.
        increment: u32,
    },

    /// Ping (0x0A) - Keepalive request.
    Ping {
        /// Opaque data to echo.
        data: [u8; 8],
    },

    /// Pong (0x0B) - Keepalive response.
    Pong {
        /// Echoed data from Ping.
        data: [u8; 8],
    },

    /// ErrorFrame (0x0C) - Protocol error.
    ErrorFrame {
        /// Error code (see ErrorCode).
        error_code: u16,
        /// Optional human-readable reason.
        reason: String,
    },
}

impl Frame {
    /// Parse a frame from bytes.
    pub fn parse(_data: &[u8]) -> Result<Self> {
        // TODO: Implement frame parsing per spec §3.3
        Err(Error::InvalidFrame("Not yet implemented".into()))
    }

    /// Serialize frame to bytes.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        // TODO: Implement frame serialization per spec §3.3
        Err(Error::InvalidFrame("Not yet implemented".into()))
    }

    /// Get frame type ID.
    pub fn type_id(&self) -> u8 {
        match self {
            Frame::ClientHello { .. } => 0x01,
            Frame::ServerHello { .. } => 0x02,
            Frame::KeyExchange { .. } => 0x03,
            Frame::KeyExchangeResponse { .. } => 0x04,
            Frame::Finished { .. } => 0x05,
            Frame::StreamChunk { .. } => 0x06,
            Frame::StreamClose { .. } => 0x07,
            Frame::PriorityUpdate { .. } => 0x08,
            Frame::WindowUpdate { .. } => 0x09,
            Frame::Ping { .. } => 0x0A,
            Frame::Pong { .. } => 0x0B,
            Frame::ErrorFrame { .. } => 0x0C,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "not yet implemented"]
    fn test_frame_roundtrip() {
        // Test that parse(serialize(frame)) == frame
        // TODO: Implement for all frame types
    }
}
