//! State Token implementation for ZP protocol session hibernation.
//!
//! Spec: §6.5 (State Token Format)
//!
//! State Tokens enable session hibernation/resumption across network changes and app lifecycle events.
//! Tokens are encrypted with device-bound keys and persisted to secure storage.
//!
//! ## Structure
//!
//! ```text
//! StateToken (≤1024 bytes)
//! ┌─────────────────────────────────────────────────────┐
//! │ Header (16 bytes)                                   │
//! │   magic: 0x5A505354 ("ZPST")          [4 bytes]    │
//! │   version: u8                          [1 byte]    │
//! │   flags: u8                            [1 byte]    │
//! │   stream_count: u8 (max 12)            [1 byte]    │
//! │   reserved: u8                         [1 byte]    │
//! │   created_at: u64                      [8 bytes]   │
//! ├─────────────────────────────────────────────────────┤
//! │ Crypto Context (136 bytes)                          │
//! │   session_id: [u8; 16]                 [16 bytes]  │
//! │   session_secret: [u8; 32]             [32 bytes]  │
//! │   send_key: [u8; 32]                   [32 bytes]  │
//! │   recv_key: [u8; 32]                   [32 bytes]  │
//! │   send_nonce: u64                      [8 bytes]   │
//! │   recv_nonce: u64                      [8 bytes]   │
//! │   key_epoch: u32                       [4 bytes]   │
//! │   reserved: [u8; 4]                    [4 bytes]   │
//! ├─────────────────────────────────────────────────────┤
//! │ Connection Context (50 bytes)                       │
//! │   connection_id: [u8; 20]              [20 bytes]  │
//! │   peer_address: [u8; 18]               [18 bytes]  │
//! │   rtt_estimate: u32                    [4 bytes]   │
//! │   congestion_window: u32               [4 bytes]   │
//! │   bind_ip_hash: [u8; 4]                [4 bytes]   │
//! ├─────────────────────────────────────────────────────┤
//! │ Stream States (≤756 bytes, max 12 × 63 bytes)       │
//! │ Per stream (63 bytes):                              │
//! │   stream_id: u32                       [4 bytes]   │
//! │   global_seq: u64                      [8 bytes]   │
//! │   last_acked: u64                      [8 bytes]   │
//! │   send_offset: u64                     [8 bytes]   │
//! │   recv_offset: u64                     [8 bytes]   │
//! │   flow_window: u32                     [4 bytes]   │
//! │   state_flags: u8                      [1 byte]    │
//! │   priority: u8                         [1 byte]    │
//! │   reserved: [u8; 21]                   [21 bytes]  │
//! └─────────────────────────────────────────────────────┘
//! Total maximum: 16 + 136 + 50 + 756 = 958 bytes
//! ```
//!
//! ## Usage
//!
//! ```no_run
//! use zp_core::token::{StateToken, TokenHeader, CryptoContext, ConnectionContext, StreamState};
//!
//! // Create token from session state
//! let token = StateToken {
//!     header: TokenHeader {
//!         magic: 0x5A505354, // "ZPST"
//!         version: 1,
//!         flags: 0,
//!         stream_count: 2,
//!         reserved: 0,
//!         created_at: 1704067200, // Unix timestamp
//!     },
//!     crypto_context: CryptoContext {
//!         session_id: [0u8; 16],
//!         session_secret: [0u8; 32],
//!         send_key: [0u8; 32],
//!         recv_key: [0u8; 32],
//!         send_nonce: 1000,
//!         recv_nonce: 500,
//!         key_epoch: 0,
//!         reserved: [0u8; 4],
//!     },
//!     connection_context: ConnectionContext {
//!         connection_id: [0u8; 20],
//!         peer_address: [0u8; 18],
//!         rtt_estimate: 50,
//!         congestion_window: 10240,
//!         bind_ip_hash: [0u8; 4],
//!     },
//!     stream_states: vec![],
//! };
//!
//! // Serialize to bytes
//! let bytes = token.serialize();
//!
//! // Parse from bytes
//! let parsed = StateToken::parse(&bytes).unwrap();
//! ```

use crate::Error;

/// State Token magic number: "ZPST" (0x5A505354).
///
/// Spec: §6.5 (State Token Format)
pub const STATE_TOKEN_MAGIC: u32 = 0x5A50_5354;

/// State Token version.
///
/// Current version: 1
pub const STATE_TOKEN_VERSION: u8 = 1;

/// Maximum number of streams that can be hibernated.
///
/// Spec: §6.5 - "Max 12 streams" per State Token
pub const MAX_HIBERNATED_STREAMS: u8 = 12;

/// Nonce skip amount on resume to prevent nonce reuse.
///
/// Spec: §6.5 - "MUST skip ahead by ZP_NONCE_SKIP (default: 1000)"
pub const ZP_NONCE_SKIP: u64 = 1000;

/// State Token header (16 bytes).
///
/// The header is used as Additional Authenticated Data (AAD) during encryption.
///
/// Spec: §6.5 (State Token Format - Header)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenHeader {
    /// Magic number: 0x5A505354 ("ZPST")
    pub magic: u32,
    /// Token format version (currently 1)
    pub version: u8,
    /// Flags (reserved, must be 0)
    pub flags: u8,
    /// Number of streams in this token (1-12)
    pub stream_count: u8,
    /// Reserved (must be 0)
    pub reserved: u8,
    /// Unix timestamp (seconds since 1970-01-01 UTC)
    pub created_at: u64,
}

impl TokenHeader {
    /// Size of serialized header in bytes.
    pub const SIZE: usize = 16;

    /// Serialize header to bytes (little-endian).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZE);
        buf.extend_from_slice(&self.magic.to_le_bytes());
        buf.push(self.version);
        buf.push(self.flags);
        buf.push(self.stream_count);
        buf.push(self.reserved);
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        buf
    }

    /// Parse header from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < Self::SIZE {
            return Err(Error::InvalidFrame("Token header too short".into()));
        }

        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if magic != STATE_TOKEN_MAGIC {
            return Err(Error::InvalidFrame(format!(
                "Invalid token magic: expected 0x{:08X}, got 0x{:08X}",
                STATE_TOKEN_MAGIC, magic
            )));
        }

        let version = data[4];
        if version != STATE_TOKEN_VERSION {
            return Err(Error::InvalidFrame(format!(
                "Unsupported token version: {}",
                version
            )));
        }

        let flags = data[5];
        let stream_count = data[6];
        let reserved = data[7];
        let created_at = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        // Validate stream count per spec §6.5
        if stream_count == 0 || stream_count > MAX_HIBERNATED_STREAMS {
            return Err(Error::InvalidFrame(format!(
                "Invalid stream_count: {} (must be 1-12)",
                stream_count
            )));
        }

        Ok(Self {
            magic,
            version,
            flags,
            stream_count,
            reserved,
            created_at,
        })
    }
}

/// Crypto context (136 bytes) - session keys and nonces.
///
/// Spec: §6.5 (State Token Format - Crypto Context)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoContext {
    /// Session ID (16 bytes)
    pub session_id: [u8; 16],
    /// Session secret (32 bytes)
    pub session_secret: [u8; 32],
    /// Send encryption key (32 bytes)
    pub send_key: [u8; 32],
    /// Receive encryption key (32 bytes)
    pub recv_key: [u8; 32],
    /// Send nonce counter
    pub send_nonce: u64,
    /// Receive nonce counter
    pub recv_nonce: u64,
    /// Key rotation epoch
    pub key_epoch: u32,
    /// Reserved (4 bytes, must be zero)
    pub reserved: [u8; 4],
}

impl CryptoContext {
    /// Size of serialized crypto context in bytes.
    pub const SIZE: usize = 136;

    /// Serialize crypto context to bytes (little-endian).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZE);
        buf.extend_from_slice(&self.session_id);
        buf.extend_from_slice(&self.session_secret);
        buf.extend_from_slice(&self.send_key);
        buf.extend_from_slice(&self.recv_key);
        buf.extend_from_slice(&self.send_nonce.to_le_bytes());
        buf.extend_from_slice(&self.recv_nonce.to_le_bytes());
        buf.extend_from_slice(&self.key_epoch.to_le_bytes());
        buf.extend_from_slice(&self.reserved);
        buf
    }

    /// Parse crypto context from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < Self::SIZE {
            return Err(Error::InvalidFrame("Crypto context too short".into()));
        }

        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&data[0..16]);

        let mut session_secret = [0u8; 32];
        session_secret.copy_from_slice(&data[16..48]);

        let mut send_key = [0u8; 32];
        send_key.copy_from_slice(&data[48..80]);

        let mut recv_key = [0u8; 32];
        recv_key.copy_from_slice(&data[80..112]);

        let send_nonce = u64::from_le_bytes([
            data[112], data[113], data[114], data[115], data[116], data[117], data[118], data[119],
        ]);

        let recv_nonce = u64::from_le_bytes([
            data[120], data[121], data[122], data[123], data[124], data[125], data[126], data[127],
        ]);

        let key_epoch = u32::from_le_bytes([data[128], data[129], data[130], data[131]]);

        let mut reserved = [0u8; 4];
        reserved.copy_from_slice(&data[132..136]);

        Ok(Self {
            session_id,
            session_secret,
            send_key,
            recv_key,
            send_nonce,
            recv_nonce,
            key_epoch,
            reserved,
        })
    }
}

/// Connection context (50 bytes) - transport-level state.
///
/// Spec: §6.5 (State Token Format - Connection Context)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionContext {
    /// Connection ID (20 bytes)
    pub connection_id: [u8; 20],
    /// Peer address (18 bytes) - IPv6 + port
    pub peer_address: [u8; 18],
    /// RTT estimate in milliseconds
    pub rtt_estimate: u32,
    /// Congestion window in bytes
    pub congestion_window: u32,
    /// Bind IP hash for IP binding check (4 bytes)
    pub bind_ip_hash: [u8; 4],
}

impl ConnectionContext {
    /// Size of serialized connection context in bytes.
    pub const SIZE: usize = 50;

    /// Serialize connection context to bytes (little-endian).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZE);
        buf.extend_from_slice(&self.connection_id);
        buf.extend_from_slice(&self.peer_address);
        buf.extend_from_slice(&self.rtt_estimate.to_le_bytes());
        buf.extend_from_slice(&self.congestion_window.to_le_bytes());
        buf.extend_from_slice(&self.bind_ip_hash);
        buf
    }

    /// Parse connection context from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < Self::SIZE {
            return Err(Error::InvalidFrame("Connection context too short".into()));
        }

        let mut connection_id = [0u8; 20];
        connection_id.copy_from_slice(&data[0..20]);

        let mut peer_address = [0u8; 18];
        peer_address.copy_from_slice(&data[20..38]);

        let rtt_estimate = u32::from_le_bytes([data[38], data[39], data[40], data[41]]);

        let congestion_window = u32::from_le_bytes([data[42], data[43], data[44], data[45]]);

        let mut bind_ip_hash = [0u8; 4];
        bind_ip_hash.copy_from_slice(&data[46..50]);

        Ok(Self {
            connection_id,
            peer_address,
            rtt_estimate,
            congestion_window,
            bind_ip_hash,
        })
    }
}

/// Stream state flags.
///
/// Spec: §6.5.2 (Stream State Flags)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamStateFlags(u8);

impl StreamStateFlags {
    /// Stream is open for data.
    pub const OPEN: u8 = 1 << 0;
    /// Local side finished sending.
    pub const HALF_CLOSED_LOCAL: u8 = 1 << 1;
    /// Remote side finished sending.
    pub const HALF_CLOSED_REMOTE: u8 = 1 << 2;
    /// Stream reset requested.
    pub const RESET_PENDING: u8 = 1 << 3;

    /// Create new flags from u8.
    pub fn new(flags: u8) -> Self {
        Self(flags)
    }

    /// Get raw flags value.
    pub fn value(&self) -> u8 {
        self.0
    }

    /// Check if stream is open.
    pub fn is_open(&self) -> bool {
        self.0 & Self::OPEN != 0
    }

    /// Check if local side is half-closed.
    pub fn is_half_closed_local(&self) -> bool {
        self.0 & Self::HALF_CLOSED_LOCAL != 0
    }

    /// Check if remote side is half-closed.
    pub fn is_half_closed_remote(&self) -> bool {
        self.0 & Self::HALF_CLOSED_REMOTE != 0
    }

    /// Check if reset is pending.
    pub fn is_reset_pending(&self) -> bool {
        self.0 & Self::RESET_PENDING != 0
    }
}

/// Per-stream hibernation state (63 bytes).
///
/// Spec: §6.5 (State Token Format - Stream States)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamState {
    /// Stream ID
    pub stream_id: u32,
    /// Global sequence number (wire-level bytes sent)
    pub global_seq: u64,
    /// Last acknowledged sequence number
    pub last_acked: u64,
    /// Application send offset (next byte to generate)
    pub send_offset: u64,
    /// Application receive offset (next byte to deliver)
    pub recv_offset: u64,
    /// Flow control window in bytes
    pub flow_window: u32,
    /// Stream state flags (OPEN, HALF_CLOSED_*, RESET_PENDING)
    pub state_flags: StreamStateFlags,
    /// Stream priority (0-255)
    pub priority: u8,
    /// Reserved (21 bytes, must be zero)
    pub reserved: [u8; 21],
}

impl StreamState {
    /// Size of serialized stream state in bytes.
    pub const SIZE: usize = 63;

    /// Serialize stream state to bytes (little-endian).
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::SIZE);
        buf.extend_from_slice(&self.stream_id.to_le_bytes());
        buf.extend_from_slice(&self.global_seq.to_le_bytes());
        buf.extend_from_slice(&self.last_acked.to_le_bytes());
        buf.extend_from_slice(&self.send_offset.to_le_bytes());
        buf.extend_from_slice(&self.recv_offset.to_le_bytes());
        buf.extend_from_slice(&self.flow_window.to_le_bytes());
        buf.push(self.state_flags.value());
        buf.push(self.priority);
        buf.extend_from_slice(&self.reserved);
        buf
    }

    /// Parse stream state from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < Self::SIZE {
            return Err(Error::InvalidFrame("Stream state too short".into()));
        }

        let stream_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        let global_seq = u64::from_le_bytes([
            data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
        ]);

        let last_acked = u64::from_le_bytes([
            data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
        ]);

        let send_offset = u64::from_le_bytes([
            data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
        ]);

        let recv_offset = u64::from_le_bytes([
            data[28], data[29], data[30], data[31], data[32], data[33], data[34], data[35],
        ]);

        let flow_window = u32::from_le_bytes([data[36], data[37], data[38], data[39]]);

        let state_flags = StreamStateFlags::new(data[40]);
        let priority = data[41];

        let mut reserved = [0u8; 21];
        reserved.copy_from_slice(&data[42..63]);

        Ok(Self {
            stream_id,
            global_seq,
            last_acked,
            send_offset,
            recv_offset,
            flow_window,
            state_flags,
            priority,
            reserved,
        })
    }
}

/// State Token for session hibernation/resumption.
///
/// Spec: §6.5 (State Token Format)
///
/// Maximum size: 16 + 136 + 50 + (12 × 63) = 958 bytes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateToken {
    /// Token header (16 bytes, used as AAD)
    pub header: TokenHeader,
    /// Cryptographic context (136 bytes)
    pub crypto_context: CryptoContext,
    /// Connection context (50 bytes)
    pub connection_context: ConnectionContext,
    /// Per-stream states (max 12 streams, 63 bytes each)
    pub stream_states: Vec<StreamState>,
}

impl StateToken {
    /// Maximum token size in bytes.
    pub const MAX_SIZE: usize = 958;

    /// Create a new State Token.
    ///
    /// # Errors
    ///
    /// Returns error if `stream_states.len() > MAX_HIBERNATED_STREAMS` or is empty.
    pub fn new(
        header: TokenHeader,
        crypto_context: CryptoContext,
        connection_context: ConnectionContext,
        stream_states: Vec<StreamState>,
    ) -> Result<Self, Error> {
        if stream_states.is_empty() {
            return Err(Error::InvalidState);
        }

        if stream_states.len() > MAX_HIBERNATED_STREAMS as usize {
            return Err(Error::InvalidFrame(format!(
                "Too many streams: {} (max {})",
                stream_states.len(),
                MAX_HIBERNATED_STREAMS
            )));
        }

        Ok(Self {
            header,
            crypto_context,
            connection_context,
            stream_states,
        })
    }

    /// Serialize token to bytes (unencrypted).
    ///
    /// Returns: Header (16) + CryptoContext (136) + ConnectionContext (50) + StreamStates (N×63)
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::MAX_SIZE);

        // Header (16 bytes)
        buf.extend_from_slice(&self.header.serialize());

        // Crypto context (136 bytes)
        buf.extend_from_slice(&self.crypto_context.serialize());

        // Connection context (50 bytes)
        buf.extend_from_slice(&self.connection_context.serialize());

        // Stream states (N × 63 bytes)
        for stream in &self.stream_states {
            buf.extend_from_slice(&stream.serialize());
        }

        buf
    }

    /// Parse token from bytes (unencrypted).
    ///
    /// # Errors
    ///
    /// Returns error if data is too short, invalid, or violates spec constraints.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        // Minimum size: header + crypto + connection + 1 stream
        let min_size =
            TokenHeader::SIZE + CryptoContext::SIZE + ConnectionContext::SIZE + StreamState::SIZE;
        if data.len() < min_size {
            return Err(Error::InvalidFrame(format!(
                "Token too short: {} bytes (min {})",
                data.len(),
                min_size
            )));
        }

        let mut offset = 0;

        // Parse header
        let header = TokenHeader::parse(&data[offset..offset + TokenHeader::SIZE])?;
        offset += TokenHeader::SIZE;

        // Parse crypto context
        let crypto_context = CryptoContext::parse(&data[offset..offset + CryptoContext::SIZE])?;
        offset += CryptoContext::SIZE;

        // Parse connection context
        let connection_context =
            ConnectionContext::parse(&data[offset..offset + ConnectionContext::SIZE])?;
        offset += ConnectionContext::SIZE;

        // Parse stream states
        let stream_count = header.stream_count as usize;
        let expected_size = min_size - StreamState::SIZE + (stream_count * StreamState::SIZE);

        if data.len() < expected_size {
            return Err(Error::InvalidFrame(format!(
                "Token too short for {} streams: {} bytes (expected {})",
                stream_count,
                data.len(),
                expected_size
            )));
        }

        let mut stream_states = Vec::with_capacity(stream_count);
        for _ in 0..stream_count {
            let stream = StreamState::parse(&data[offset..offset + StreamState::SIZE])?;
            stream_states.push(stream);
            offset += StreamState::SIZE;
        }

        Self::new(header, crypto_context, connection_context, stream_states)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_header_serialize_parse_roundtrip() {
        let header = TokenHeader {
            magic: STATE_TOKEN_MAGIC,
            version: STATE_TOKEN_VERSION,
            flags: 0,
            stream_count: 2,
            reserved: 0,
            created_at: 1704067200,
        };

        let bytes = header.serialize();
        assert_eq!(bytes.len(), TokenHeader::SIZE);

        let parsed = TokenHeader::parse(&bytes).unwrap();
        assert_eq!(parsed, header);
    }

    #[test]
    fn test_token_header_invalid_magic() {
        let mut bytes = vec![0u8; TokenHeader::SIZE];
        bytes[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        bytes[4] = STATE_TOKEN_VERSION;
        bytes[6] = 1; // stream_count

        let result = TokenHeader::parse(&bytes);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid token magic"));
    }

    #[test]
    fn test_token_header_invalid_version() {
        let mut bytes = vec![0u8; TokenHeader::SIZE];
        bytes[0..4].copy_from_slice(&STATE_TOKEN_MAGIC.to_le_bytes());
        bytes[4] = 99; // Invalid version
        bytes[6] = 1; // stream_count

        let result = TokenHeader::parse(&bytes);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported token version"));
    }

    #[test]
    fn test_token_header_invalid_stream_count_zero() {
        let mut bytes = vec![0u8; TokenHeader::SIZE];
        bytes[0..4].copy_from_slice(&STATE_TOKEN_MAGIC.to_le_bytes());
        bytes[4] = STATE_TOKEN_VERSION;
        bytes[6] = 0; // Invalid: 0 streams

        let result = TokenHeader::parse(&bytes);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid stream_count"));
    }

    #[test]
    fn test_token_header_invalid_stream_count_overflow() {
        let mut bytes = vec![0u8; TokenHeader::SIZE];
        bytes[0..4].copy_from_slice(&STATE_TOKEN_MAGIC.to_le_bytes());
        bytes[4] = STATE_TOKEN_VERSION;
        bytes[6] = 13; // Invalid: >12 streams

        let result = TokenHeader::parse(&bytes);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid stream_count"));
    }

    #[test]
    fn test_crypto_context_serialize_parse_roundtrip() {
        let context = CryptoContext {
            session_id: [1u8; 16],
            session_secret: [2u8; 32],
            send_key: [3u8; 32],
            recv_key: [4u8; 32],
            send_nonce: 1000,
            recv_nonce: 500,
            key_epoch: 0,
            reserved: [0u8; 4],
        };

        let bytes = context.serialize();
        assert_eq!(bytes.len(), CryptoContext::SIZE);

        let parsed = CryptoContext::parse(&bytes).unwrap();
        assert_eq!(parsed, context);
    }

    #[test]
    fn test_connection_context_serialize_parse_roundtrip() {
        let context = ConnectionContext {
            connection_id: [5u8; 20],
            peer_address: [6u8; 18],
            rtt_estimate: 50,
            congestion_window: 10240,
            bind_ip_hash: [7u8; 4],
        };

        let bytes = context.serialize();
        assert_eq!(bytes.len(), ConnectionContext::SIZE);

        let parsed = ConnectionContext::parse(&bytes).unwrap();
        assert_eq!(parsed, context);
    }

    #[test]
    fn test_stream_state_flags() {
        let flags =
            StreamStateFlags::new(StreamStateFlags::OPEN | StreamStateFlags::HALF_CLOSED_LOCAL);

        assert!(flags.is_open());
        assert!(flags.is_half_closed_local());
        assert!(!flags.is_half_closed_remote());
        assert!(!flags.is_reset_pending());
    }

    #[test]
    fn test_stream_state_serialize_parse_roundtrip() {
        let state = StreamState {
            stream_id: 4,
            global_seq: 1024,
            last_acked: 512,
            send_offset: 2048,
            recv_offset: 1536,
            flow_window: 65536,
            state_flags: StreamStateFlags::new(StreamStateFlags::OPEN),
            priority: 128,
            reserved: [0u8; 21],
        };

        let bytes = state.serialize();
        assert_eq!(bytes.len(), StreamState::SIZE);

        let parsed = StreamState::parse(&bytes).unwrap();
        assert_eq!(parsed, state);
    }

    #[test]
    fn test_state_token_serialize_parse_roundtrip() {
        let token = StateToken {
            header: TokenHeader {
                magic: STATE_TOKEN_MAGIC,
                version: STATE_TOKEN_VERSION,
                flags: 0,
                stream_count: 2,
                reserved: 0,
                created_at: 1704067200,
            },
            crypto_context: CryptoContext {
                session_id: [1u8; 16],
                session_secret: [2u8; 32],
                send_key: [3u8; 32],
                recv_key: [4u8; 32],
                send_nonce: 1000,
                recv_nonce: 500,
                key_epoch: 0,
                reserved: [0u8; 4],
            },
            connection_context: ConnectionContext {
                connection_id: [5u8; 20],
                peer_address: [6u8; 18],
                rtt_estimate: 50,
                congestion_window: 10240,
                bind_ip_hash: [7u8; 4],
            },
            stream_states: vec![
                StreamState {
                    stream_id: 4,
                    global_seq: 1024,
                    last_acked: 512,
                    send_offset: 2048,
                    recv_offset: 1536,
                    flow_window: 65536,
                    state_flags: StreamStateFlags::new(StreamStateFlags::OPEN),
                    priority: 128,
                    reserved: [0u8; 21],
                },
                StreamState {
                    stream_id: 8,
                    global_seq: 2048,
                    last_acked: 1024,
                    send_offset: 4096,
                    recv_offset: 3072,
                    flow_window: 65536,
                    state_flags: StreamStateFlags::new(StreamStateFlags::OPEN),
                    priority: 64,
                    reserved: [0u8; 21],
                },
            ],
        };

        let bytes = token.serialize();
        let expected_size = TokenHeader::SIZE
            + CryptoContext::SIZE
            + ConnectionContext::SIZE
            + (2 * StreamState::SIZE);
        assert_eq!(bytes.len(), expected_size);

        let parsed = StateToken::parse(&bytes).unwrap();
        assert_eq!(parsed, token);
    }

    #[test]
    fn test_state_token_empty_streams_rejected() {
        let result = StateToken::new(
            TokenHeader {
                magic: STATE_TOKEN_MAGIC,
                version: STATE_TOKEN_VERSION,
                flags: 0,
                stream_count: 0,
                reserved: 0,
                created_at: 1704067200,
            },
            CryptoContext {
                session_id: [0u8; 16],
                session_secret: [0u8; 32],
                send_key: [0u8; 32],
                recv_key: [0u8; 32],
                send_nonce: 0,
                recv_nonce: 0,
                key_epoch: 0,
                reserved: [0u8; 4],
            },
            ConnectionContext {
                connection_id: [0u8; 20],
                peer_address: [0u8; 18],
                rtt_estimate: 0,
                congestion_window: 0,
                bind_ip_hash: [0u8; 4],
            },
            vec![], // Empty streams
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_state_token_too_many_streams_rejected() {
        let mut streams = Vec::new();
        for i in 0..13 {
            streams.push(StreamState {
                stream_id: i * 4,
                global_seq: 0,
                last_acked: 0,
                send_offset: 0,
                recv_offset: 0,
                flow_window: 65536,
                state_flags: StreamStateFlags::new(StreamStateFlags::OPEN),
                priority: 128,
                reserved: [0u8; 21],
            });
        }

        let result = StateToken::new(
            TokenHeader {
                magic: STATE_TOKEN_MAGIC,
                version: STATE_TOKEN_VERSION,
                flags: 0,
                stream_count: 13,
                reserved: 0,
                created_at: 1704067200,
            },
            CryptoContext {
                session_id: [0u8; 16],
                session_secret: [0u8; 32],
                send_key: [0u8; 32],
                recv_key: [0u8; 32],
                send_nonce: 0,
                recv_nonce: 0,
                key_epoch: 0,
                reserved: [0u8; 4],
            },
            ConnectionContext {
                connection_id: [0u8; 20],
                peer_address: [0u8; 18],
                rtt_estimate: 0,
                congestion_window: 0,
                bind_ip_hash: [0u8; 4],
            },
            streams,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Too many streams"));
    }

    #[test]
    fn test_state_token_max_streams_accepted() {
        let mut streams = Vec::new();
        for i in 0..12 {
            streams.push(StreamState {
                stream_id: i * 4,
                global_seq: 0,
                last_acked: 0,
                send_offset: 0,
                recv_offset: 0,
                flow_window: 65536,
                state_flags: StreamStateFlags::new(StreamStateFlags::OPEN),
                priority: 128,
                reserved: [0u8; 21],
            });
        }

        let token = StateToken::new(
            TokenHeader {
                magic: STATE_TOKEN_MAGIC,
                version: STATE_TOKEN_VERSION,
                flags: 0,
                stream_count: 12,
                reserved: 0,
                created_at: 1704067200,
            },
            CryptoContext {
                session_id: [0u8; 16],
                session_secret: [0u8; 32],
                send_key: [0u8; 32],
                recv_key: [0u8; 32],
                send_nonce: 0,
                recv_nonce: 0,
                key_epoch: 0,
                reserved: [0u8; 4],
            },
            ConnectionContext {
                connection_id: [0u8; 20],
                peer_address: [0u8; 18],
                rtt_estimate: 0,
                congestion_window: 0,
                bind_ip_hash: [0u8; 4],
            },
            streams,
        );

        assert!(token.is_ok());
        let token = token.unwrap();

        // Verify serialization
        let bytes = token.serialize();
        let parsed = StateToken::parse(&bytes).unwrap();
        assert_eq!(parsed.stream_states.len(), 12);
    }
}
