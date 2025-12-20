//! Frame parsing and serialization per spec §3.3.
//!
//! Implements all zp protocol frames with exact wire formats:
//! - Handshake frames (ClientHello, ServerHello, ClientFinish, Known*)
//! - Control frames (Sync, KeyUpdate, Ack, WindowUpdate, Error)
//! - Data frames (DataFrame, EncryptedRecord)
//! - Multiplexing (StreamChunk for TCP fallback)
//!
//! All multi-byte integers use little-endian byte order per spec §3.3.

use crate::{Error, ErrorCode, Result};
use std::hash::Hasher;
use twox_hash::XxHash64;

// Frame magic numbers (4 bytes, ASCII mnemonic)
/// Magic number for ClientHello frame (0x5A504348 = "ZPCH").
pub const MAGIC_CLIENT_HELLO: u32 = 0x5A50_4348;
/// Magic number for ServerHello frame (0x5A505348 = "ZPSH").
pub const MAGIC_SERVER_HELLO: u32 = 0x5A50_5348;
/// Magic number for ClientFinish frame (0x5A504346 = "ZPCF").
pub const MAGIC_CLIENT_FINISH: u32 = 0x5A50_4346;
/// Magic number for KnownHello frame (0x5A504B48 = "ZPKH").
pub const MAGIC_KNOWN_HELLO: u32 = 0x5A50_4B48;
/// Magic number for KnownResponse frame (0x5A504B52 = "ZPKR").
pub const MAGIC_KNOWN_RESPONSE: u32 = 0x5A50_4B52;
/// Magic number for KnownFinish frame (0x5A504B46 = "ZPKF").
pub const MAGIC_KNOWN_FINISH: u32 = 0x5A50_4B46;
/// Magic number for Sync frame (0x5A504D49 = "ZPMI").
pub const MAGIC_SYNC: u32 = 0x5A50_4D49;
/// Magic number for KeyUpdate frame (0x5A504B55 = "ZPKU").
pub const MAGIC_KEY_UPDATE: u32 = 0x5A50_4B55;
/// Magic number for Ack frame (0x5A50414B = "ZPAK").
pub const MAGIC_ACK: u32 = 0x5A50_414B;
/// Magic number for WindowUpdate frame (0x5A505755 = "ZPWU").
pub const MAGIC_WINDOW_UPDATE: u32 = 0x5A50_5755;
/// Magic number for Error frame (0x5A504552 = "ZPER").
pub const MAGIC_ERROR: u32 = 0x5A50_4552;
/// Magic number for Data frame (0x5A504446 = "ZPDF").
pub const MAGIC_DATA: u32 = 0x5A50_4446;

// Frame type identifiers (1 byte)
/// Type identifier for Sync frame (0x01).
pub const TYPE_SYNC: u8 = 0x01;
/// Type identifier for SyncAck frame (0x02).
pub const TYPE_SYNC_ACK: u8 = 0x02;
/// Type identifier for KeyUpdate frame (0x10).
pub const TYPE_KEY_UPDATE: u8 = 0x10;
/// Type identifier for KeyUpdateAck frame (0x11).
pub const TYPE_KEY_UPDATE_ACK: u8 = 0x11;
/// Type identifier for Ack frame (0x20).
pub const TYPE_ACK: u8 = 0x20;
/// Type identifier for WindowUpdate frame (0x30).
pub const TYPE_WINDOW_UPDATE: u8 = 0x30;
/// Type identifier for DataFrame (0x40).
pub const TYPE_DATA: u8 = 0x40;
/// Type identifier for ClientHello frame (0x50).
pub const TYPE_CLIENT_HELLO: u8 = 0x50;
/// Type identifier for ServerHello frame (0x51).
pub const TYPE_SERVER_HELLO: u8 = 0x51;
/// Type identifier for ClientFinish frame (0x52).
pub const TYPE_CLIENT_FINISH: u8 = 0x52;
/// Type identifier for KnownHello frame (0x53).
pub const TYPE_KNOWN_HELLO: u8 = 0x53;
/// Type identifier for KnownResponse frame (0x54).
pub const TYPE_KNOWN_RESPONSE: u8 = 0x54;
/// Type identifier for KnownFinish frame (0x55).
pub const TYPE_KNOWN_FINISH: u8 = 0x55;
/// Type identifier for Error frame (0x60).
pub const TYPE_ERROR: u8 = 0x60;

/// Protocol frame types per spec §3.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    // === Handshake frames (Stranger Mode) ===
    /// ClientHello - Stranger Mode handshake initiation (§4.2.1).
    ClientHello {
        /// Supported protocol versions in descending preference.
        supported_versions: Vec<u16>,
        /// Minimum acceptable version.
        min_version: u16,
        /// Supported cipher suites in descending preference.
        supported_ciphers: Vec<u8>,
        /// Client's X25519 public key (32 bytes).
        x25519_pubkey: [u8; 32],
        /// Client random nonce (32 bytes).
        random: [u8; 32],
    },

    /// ServerHello - Stranger Mode server response (§4.2.2).
    ServerHello {
        /// Selected protocol version.
        selected_version: u16,
        /// Selected cipher suite.
        selected_cipher: u8,
        /// Server's X25519 public key (32 bytes).
        x25519_pubkey: [u8; 32],
        /// Server's ML-KEM public key (1184 bytes for ML-KEM-768, 1568 bytes for ML-KEM-1024).
        mlkem_pubkey: Vec<u8>,
        /// Server random nonce (32 bytes).
        random: [u8; 32],
    },

    /// ClientFinish - Stranger Mode client finish (§4.2.3).
    ClientFinish {
        /// ML-KEM ciphertext (1088 bytes for ML-KEM-768, 1568 bytes for ML-KEM-1024).
        mlkem_ciphertext: Vec<u8>,
    },

    // === Handshake frames (Known Mode) ===
    /// KnownHello - Known Mode handshake initiation (§4.3.1).
    KnownHello {
        /// Supported protocol versions in descending preference.
        supported_versions: Vec<u16>,
        /// Minimum acceptable version.
        min_version: u16,
        /// Supported cipher suites in descending preference.
        supported_ciphers: Vec<u8>,
        /// SPAKE2+ message A (32 bytes).
        spake2_message_a: [u8; 32],
        /// Client random nonce (32 bytes).
        random: [u8; 32],
    },

    /// KnownResponse - Known Mode server response (§4.3.2).
    KnownResponse {
        /// Selected protocol version.
        selected_version: u16,
        /// Selected cipher suite.
        selected_cipher: u8,
        /// SPAKE2+ message B (32 bytes).
        spake2_message_b: [u8; 32],
        /// Server random nonce (32 bytes).
        random: [u8; 32],
        /// Encrypted ML-KEM public key (1200 bytes for ML-KEM-768, 1584 bytes for ML-KEM-1024).
        mlkem_pubkey_encrypted: Vec<u8>,
    },

    /// KnownFinish - Known Mode client finish (§4.3.3).
    KnownFinish {
        /// Encrypted ML-KEM ciphertext (1104 bytes for ML-KEM-768, 1584 bytes for ML-KEM-1024).
        mlkem_ciphertext_encrypted: Vec<u8>,
    },

    // === Control frames ===
    /// SyncFrame - Transport migration state sync (§3.3.5).
    SyncFrame {
        /// Session identifier (16 bytes).
        session_id: [u8; 16],
        /// Stream states to synchronize.
        streams: Vec<StreamState>,
        /// Sync flags (reserved, set to 0).
        flags: u8,
    },

    /// SyncAck - Migration acknowledgment (§3.3.6).
    SyncAck {
        /// Per-stream sync status.
        streams: Vec<StreamSyncStatus>,
        /// Overall sync status code.
        status: u8,
    },

    /// KeyUpdate - Key rotation request (§4.6.2).
    KeyUpdate {
        /// Key epoch number.
        key_epoch: u32,
        /// Key rotation direction (0 = client-to-server, 1 = server-to-client).
        direction: u8,
    },

    /// KeyUpdateAck - Key rotation acknowledgment (§4.6.5).
    KeyUpdateAck {
        /// Acknowledged key epoch.
        acked_epoch: u32,
    },

    /// AckFrame - Reliability layer acknowledgment for unreliable transports (§6.4.4).
    AckFrame {
        /// Stream identifier.
        stream_id: u32,
        /// Acknowledged sequence number ranges.
        ack_ranges: Vec<AckRange>,
    },

    /// WindowUpdate - Flow control window update (§3.3.9).
    WindowUpdate {
        /// Stream identifier (0 for connection-level).
        stream_id: u32,
        /// Window size increment in bytes.
        window_increment: u64,
    },

    /// ErrorFrame - Protocol error (§3.3.12).
    ErrorFrame {
        /// Error code per spec Appendix B.
        error_code: ErrorCode,
    },

    // === Data frames ===
    /// DataFrame - Application data on non-QUIC transports (§3.3.10).
    DataFrame {
        /// Stream identifier.
        stream_id: u32,
        /// Sequence number.
        seq: u64,
        /// Frame flags (FIN bit).
        flags: u8,
        /// Application payload.
        payload: Vec<u8>,
    },

    /// EncryptedRecord - Encryption wrapper for non-QUIC transports (§3.3.13).
    EncryptedRecord {
        /// Key epoch.
        epoch: u8,
        /// Nonce counter.
        counter: u64,
        /// Encrypted payload.
        ciphertext: Vec<u8>,
        /// Authentication tag (16 bytes).
        tag: [u8; 16],
    },

    /// StreamChunk - Multiplexed stream data for TCP fallback (§3.3.7).
    StreamChunk {
        /// Stream identifier.
        stream_id: u32,
        /// Chunk payload.
        payload: Vec<u8>,
    },
}

/// Stream state for Sync-Frame (§3.3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamState {
    /// Stream identifier.
    pub stream_id: u32,
    /// Global sequence number for this stream.
    pub global_seq: u64,
    /// Last acknowledged sequence number.
    pub last_acked: u64,
}

impl StreamState {
    /// Compute XXH64 integrity hash per spec §3.3.5.
    pub fn compute_integrity(&self) -> u64 {
        let mut hasher = XxHash64::with_seed(0);
        hasher.write(&self.stream_id.to_le_bytes());
        hasher.write(&self.global_seq.to_le_bytes());
        hasher.write(&self.last_acked.to_le_bytes());
        hasher.finish()
    }
}

/// Stream sync status for Sync-Ack (§3.3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSyncStatus {
    /// Stream identifier.
    pub stream_id: u32,
    /// Stream status code.
    pub stream_status: u8,
    /// Receiver's last acknowledged sequence number.
    pub receiver_last_acked: u64,
    /// Receiver's current sequence number.
    pub receiver_seq: u64,
}

/// ACK range for AckFrame (§6.4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckRange {
    /// Start sequence number (inclusive).
    pub start_seq: u64,
    /// End sequence number (inclusive).
    pub end_seq: u64,
}

impl Frame {
    /// Parse a frame from bytes.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 5 {
            return Err(Error::InsufficientData(5));
        }

        let magic = read_u32_le(&data[0..4]);
        let frame_type = data[4];

        match (magic, frame_type) {
            (MAGIC_CLIENT_HELLO, TYPE_CLIENT_HELLO) => Self::parse_client_hello(&data[5..]),
            (MAGIC_SERVER_HELLO, TYPE_SERVER_HELLO) => Self::parse_server_hello(&data[5..]),
            (MAGIC_CLIENT_FINISH, TYPE_CLIENT_FINISH) => Self::parse_client_finish(&data[5..]),
            (MAGIC_KNOWN_HELLO, TYPE_KNOWN_HELLO) => Self::parse_known_hello(&data[5..]),
            (MAGIC_KNOWN_RESPONSE, TYPE_KNOWN_RESPONSE) => Self::parse_known_response(&data[5..]),
            (MAGIC_KNOWN_FINISH, TYPE_KNOWN_FINISH) => Self::parse_known_finish(&data[5..]),
            (MAGIC_SYNC, TYPE_SYNC) => Self::parse_sync_frame(&data[5..]),
            (MAGIC_SYNC, TYPE_SYNC_ACK) => Self::parse_sync_ack(&data[5..]),
            (MAGIC_KEY_UPDATE, TYPE_KEY_UPDATE) => Self::parse_key_update(&data[5..]),
            (MAGIC_KEY_UPDATE, TYPE_KEY_UPDATE_ACK) => Self::parse_key_update_ack(&data[5..]),
            (MAGIC_ACK, TYPE_ACK) => Self::parse_ack_frame(&data[5..]),
            (MAGIC_WINDOW_UPDATE, TYPE_WINDOW_UPDATE) => Self::parse_window_update(&data[5..]),
            (MAGIC_ERROR, TYPE_ERROR) => Self::parse_error_frame(&data[5..]),
            (MAGIC_DATA, TYPE_DATA) => Self::parse_data_frame(&data[5..]),
            _ => Err(Error::InvalidFrame(format!(
                "Unknown frame: magic=0x{:08X}, type=0x{:02X}",
                magic, frame_type
            ))),
        }
    }

    /// Serialize frame to bytes.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        match self {
            Frame::ClientHello { .. } => self.serialize_client_hello(),
            Frame::ServerHello { .. } => self.serialize_server_hello(),
            Frame::ClientFinish { .. } => self.serialize_client_finish(),
            Frame::KnownHello { .. } => self.serialize_known_hello(),
            Frame::KnownResponse { .. } => self.serialize_known_response(),
            Frame::KnownFinish { .. } => self.serialize_known_finish(),
            Frame::SyncFrame { .. } => self.serialize_sync_frame(),
            Frame::SyncAck { .. } => self.serialize_sync_ack(),
            Frame::KeyUpdate { .. } => self.serialize_key_update(),
            Frame::KeyUpdateAck { .. } => self.serialize_key_update_ack(),
            Frame::AckFrame { .. } => self.serialize_ack_frame(),
            Frame::WindowUpdate { .. } => self.serialize_window_update(),
            Frame::ErrorFrame { .. } => self.serialize_error_frame(),
            Frame::DataFrame { .. } => self.serialize_data_frame(),
            Frame::EncryptedRecord { .. } => self.serialize_encrypted_record(),
            Frame::StreamChunk { .. } => self.serialize_stream_chunk(),
        }
    }

    // === ClientHello (§4.2.1) ===

    fn parse_client_hello(data: &[u8]) -> Result<Self> {
        let mut offset = 0;

        check_len(data, offset + 1)?;
        let version_count = data[offset] as usize;
        offset += 1;

        check_len(data, offset + version_count * 2)?;
        let mut supported_versions = Vec::new();
        for _ in 0..version_count {
            supported_versions.push(read_u16_le(&data[offset..offset + 2]));
            offset += 2;
        }

        check_len(data, offset + 2)?;
        let min_version = read_u16_le(&data[offset..offset + 2]);
        offset += 2;

        check_len(data, offset + 1)?;
        let cipher_count = data[offset] as usize;
        offset += 1;

        check_len(data, offset + cipher_count)?;
        let mut supported_ciphers = Vec::new();
        for _ in 0..cipher_count {
            supported_ciphers.push(data[offset]);
            offset += 1;
        }

        check_len(data, offset + 32)?;
        let mut x25519_pubkey = [0u8; 32];
        x25519_pubkey.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        check_len(data, offset + 32)?;
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[offset..offset + 32]);

        Ok(Frame::ClientHello {
            supported_versions,
            min_version,
            supported_ciphers,
            x25519_pubkey,
            random,
        })
    }

    fn serialize_client_hello(&self) -> Result<Vec<u8>> {
        if let Frame::ClientHello {
            supported_versions,
            min_version,
            supported_ciphers,
            x25519_pubkey,
            random,
        } = self
        {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC_CLIENT_HELLO.to_le_bytes());
            buf.push(TYPE_CLIENT_HELLO);
            buf.push(supported_versions.len() as u8);
            for &v in supported_versions {
                buf.extend_from_slice(&v.to_le_bytes());
            }
            buf.extend_from_slice(&min_version.to_le_bytes());
            buf.push(supported_ciphers.len() as u8);
            buf.extend_from_slice(supported_ciphers);
            buf.extend_from_slice(x25519_pubkey);
            buf.extend_from_slice(random);
            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }

    // === ServerHello (§4.2.2) ===

    fn parse_server_hello(data: &[u8]) -> Result<Self> {
        let mut offset = 0;

        check_len(data, offset + 2)?;
        let selected_version = read_u16_le(&data[offset..offset + 2]);
        offset += 2;

        check_len(data, offset + 1)?;
        let selected_cipher = data[offset];
        offset += 1;

        check_len(data, offset + 32)?;
        let mut x25519_pubkey = [0u8; 32];
        x25519_pubkey.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        check_len(data, offset + 2)?;
        let mlkem_pubkey_len = read_u16_le(&data[offset..offset + 2]) as usize;
        offset += 2;

        check_len(data, offset + mlkem_pubkey_len)?;
        let mlkem_pubkey = data[offset..offset + mlkem_pubkey_len].to_vec();
        offset += mlkem_pubkey_len;

        check_len(data, offset + 32)?;
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[offset..offset + 32]);

        Ok(Frame::ServerHello {
            selected_version,
            selected_cipher,
            x25519_pubkey,
            mlkem_pubkey,
            random,
        })
    }

    fn serialize_server_hello(&self) -> Result<Vec<u8>> {
        if let Frame::ServerHello {
            selected_version,
            selected_cipher,
            x25519_pubkey,
            mlkem_pubkey,
            random,
        } = self
        {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC_SERVER_HELLO.to_le_bytes());
            buf.push(TYPE_SERVER_HELLO);
            buf.extend_from_slice(&selected_version.to_le_bytes());
            buf.push(*selected_cipher);
            buf.extend_from_slice(x25519_pubkey);
            buf.extend_from_slice(&(mlkem_pubkey.len() as u16).to_le_bytes());
            buf.extend_from_slice(mlkem_pubkey);
            buf.extend_from_slice(random);
            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }

    // === ClientFinish (§4.2.3) ===

    fn parse_client_finish(data: &[u8]) -> Result<Self> {
        check_len(data, 2)?;
        let mlkem_ciphertext_len = read_u16_le(&data[0..2]) as usize;
        check_len(data, 2 + mlkem_ciphertext_len)?;
        let mlkem_ciphertext = data[2..2 + mlkem_ciphertext_len].to_vec();
        Ok(Frame::ClientFinish { mlkem_ciphertext })
    }

    fn serialize_client_finish(&self) -> Result<Vec<u8>> {
        if let Frame::ClientFinish { mlkem_ciphertext } = self {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC_CLIENT_FINISH.to_le_bytes());
            buf.push(TYPE_CLIENT_FINISH);
            buf.extend_from_slice(&(mlkem_ciphertext.len() as u16).to_le_bytes());
            buf.extend_from_slice(mlkem_ciphertext);
            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }

    // === KnownHello (§4.3.1) ===

    fn parse_known_hello(data: &[u8]) -> Result<Self> {
        let mut offset = 0;

        check_len(data, offset + 1)?;
        let version_count = data[offset] as usize;
        offset += 1;

        check_len(data, offset + version_count * 2)?;
        let mut supported_versions = Vec::new();
        for _ in 0..version_count {
            supported_versions.push(read_u16_le(&data[offset..offset + 2]));
            offset += 2;
        }

        check_len(data, offset + 2)?;
        let min_version = read_u16_le(&data[offset..offset + 2]);
        offset += 2;

        check_len(data, offset + 1)?;
        let cipher_count = data[offset] as usize;
        offset += 1;

        check_len(data, offset + cipher_count)?;
        let mut supported_ciphers = Vec::new();
        for _ in 0..cipher_count {
            supported_ciphers.push(data[offset]);
            offset += 1;
        }

        check_len(data, offset + 32)?;
        let mut spake2_message_a = [0u8; 32];
        spake2_message_a.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        check_len(data, offset + 32)?;
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[offset..offset + 32]);

        Ok(Frame::KnownHello {
            supported_versions,
            min_version,
            supported_ciphers,
            spake2_message_a,
            random,
        })
    }

    fn serialize_known_hello(&self) -> Result<Vec<u8>> {
        if let Frame::KnownHello {
            supported_versions,
            min_version,
            supported_ciphers,
            spake2_message_a,
            random,
        } = self
        {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC_KNOWN_HELLO.to_le_bytes());
            buf.push(TYPE_KNOWN_HELLO);
            buf.push(supported_versions.len() as u8);
            for &v in supported_versions {
                buf.extend_from_slice(&v.to_le_bytes());
            }
            buf.extend_from_slice(&min_version.to_le_bytes());
            buf.push(supported_ciphers.len() as u8);
            buf.extend_from_slice(supported_ciphers);
            buf.extend_from_slice(spake2_message_a);
            buf.extend_from_slice(random);
            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }

    // === KnownResponse (§4.3.2) ===

    fn parse_known_response(data: &[u8]) -> Result<Self> {
        let mut offset = 0;

        check_len(data, offset + 2)?;
        let selected_version = read_u16_le(&data[offset..offset + 2]);
        offset += 2;

        check_len(data, offset + 1)?;
        let selected_cipher = data[offset];
        offset += 1;

        check_len(data, offset + 32)?;
        let mut spake2_message_b = [0u8; 32];
        spake2_message_b.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        check_len(data, offset + 32)?;
        let mut random = [0u8; 32];
        random.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        check_len(data, offset + 2)?;
        let mlkem_pubkey_encrypted_len = read_u16_le(&data[offset..offset + 2]) as usize;
        offset += 2;

        check_len(data, offset + mlkem_pubkey_encrypted_len)?;
        let mlkem_pubkey_encrypted = data[offset..offset + mlkem_pubkey_encrypted_len].to_vec();

        Ok(Frame::KnownResponse {
            selected_version,
            selected_cipher,
            spake2_message_b,
            random,
            mlkem_pubkey_encrypted,
        })
    }

    fn serialize_known_response(&self) -> Result<Vec<u8>> {
        if let Frame::KnownResponse {
            selected_version,
            selected_cipher,
            spake2_message_b,
            random,
            mlkem_pubkey_encrypted,
        } = self
        {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC_KNOWN_RESPONSE.to_le_bytes());
            buf.push(TYPE_KNOWN_RESPONSE);
            buf.extend_from_slice(&selected_version.to_le_bytes());
            buf.push(*selected_cipher);
            buf.extend_from_slice(spake2_message_b);
            buf.extend_from_slice(random);
            buf.extend_from_slice(&(mlkem_pubkey_encrypted.len() as u16).to_le_bytes());
            buf.extend_from_slice(mlkem_pubkey_encrypted);
            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }

    // === KnownFinish (§4.3.3) ===

    fn parse_known_finish(data: &[u8]) -> Result<Self> {
        check_len(data, 2)?;
        let mlkem_ciphertext_encrypted_len = read_u16_le(&data[0..2]) as usize;
        check_len(data, 2 + mlkem_ciphertext_encrypted_len)?;
        let mlkem_ciphertext_encrypted = data[2..2 + mlkem_ciphertext_encrypted_len].to_vec();
        Ok(Frame::KnownFinish {
            mlkem_ciphertext_encrypted,
        })
    }

    fn serialize_known_finish(&self) -> Result<Vec<u8>> {
        if let Frame::KnownFinish {
            mlkem_ciphertext_encrypted,
        } = self
        {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC_KNOWN_FINISH.to_le_bytes());
            buf.push(TYPE_KNOWN_FINISH);
            buf.extend_from_slice(&(mlkem_ciphertext_encrypted.len() as u16).to_le_bytes());
            buf.extend_from_slice(mlkem_ciphertext_encrypted);
            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }

    // === SyncFrame (§3.3.5) ===

    fn parse_sync_frame(data: &[u8]) -> Result<Self> {
        let mut offset = 0;

        check_len(data, offset + 16)?;
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;

        check_len(data, offset + 2)?;
        let stream_count = read_u16_le(&data[offset..offset + 2]) as usize;
        offset += 2;

        check_len(data, offset + 1)?;
        let flags = data[offset];
        offset += 1;

        let mut streams = Vec::new();
        for _ in 0..stream_count {
            check_len(data, offset + 28)?;
            let stream_id = read_u32_le(&data[offset..offset + 4]);
            let global_seq = read_u64_le(&data[offset + 4..offset + 12]);
            let last_acked = read_u64_le(&data[offset + 12..offset + 20]);
            let integrity = read_u64_le(&data[offset + 20..offset + 28]);

            let stream_state = StreamState {
                stream_id,
                global_seq,
                last_acked,
            };

            // Verify integrity hash
            if stream_state.compute_integrity() != integrity {
                return Err(Error::InvalidFrame(
                    "Sync-Frame integrity check failed".into(),
                ));
            }

            streams.push(stream_state);
            offset += 28;
        }

        Ok(Frame::SyncFrame {
            session_id,
            streams,
            flags,
        })
    }

    fn serialize_sync_frame(&self) -> Result<Vec<u8>> {
        if let Frame::SyncFrame {
            session_id,
            streams,
            flags,
        } = self
        {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC_SYNC.to_le_bytes());
            buf.push(TYPE_SYNC);
            buf.extend_from_slice(session_id);
            buf.extend_from_slice(&(streams.len() as u16).to_le_bytes());
            buf.push(*flags);

            for stream in streams {
                buf.extend_from_slice(&stream.stream_id.to_le_bytes());
                buf.extend_from_slice(&stream.global_seq.to_le_bytes());
                buf.extend_from_slice(&stream.last_acked.to_le_bytes());
                buf.extend_from_slice(&stream.compute_integrity().to_le_bytes());
            }

            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }

    // === SyncAck (§3.3.6) ===

    fn parse_sync_ack(data: &[u8]) -> Result<Self> {
        let mut offset = 0;

        check_len(data, offset + 2)?;
        let stream_count = read_u16_le(&data[offset..offset + 2]) as usize;
        offset += 2;

        check_len(data, offset + 1)?;
        let status = data[offset];
        offset += 1;

        let mut streams = Vec::new();
        for _ in 0..stream_count {
            check_len(data, offset + 21)?;
            let stream_id = read_u32_le(&data[offset..offset + 4]);
            let stream_status = data[offset + 4];
            let receiver_last_acked = read_u64_le(&data[offset + 5..offset + 13]);
            let receiver_seq = read_u64_le(&data[offset + 13..offset + 21]);

            streams.push(StreamSyncStatus {
                stream_id,
                stream_status,
                receiver_last_acked,
                receiver_seq,
            });
            offset += 21;
        }

        Ok(Frame::SyncAck { streams, status })
    }

    fn serialize_sync_ack(&self) -> Result<Vec<u8>> {
        if let Frame::SyncAck { streams, status } = self {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC_SYNC.to_le_bytes());
            buf.push(TYPE_SYNC_ACK);
            buf.extend_from_slice(&(streams.len() as u16).to_le_bytes());
            buf.push(*status);

            for stream in streams {
                buf.extend_from_slice(&stream.stream_id.to_le_bytes());
                buf.push(stream.stream_status);
                buf.extend_from_slice(&stream.receiver_last_acked.to_le_bytes());
                buf.extend_from_slice(&stream.receiver_seq.to_le_bytes());
            }

            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }

    // === KeyUpdate (§4.6.2) ===

    fn parse_key_update(data: &[u8]) -> Result<Self> {
        check_len(data, 11)?;
        let key_epoch = read_u32_le(&data[0..4]);
        let direction = data[4];
        // reserved: 6 bytes (ignore)
        Ok(Frame::KeyUpdate {
            key_epoch,
            direction,
        })
    }

    fn serialize_key_update(&self) -> Result<Vec<u8>> {
        if let Frame::KeyUpdate {
            key_epoch,
            direction,
        } = self
        {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC_KEY_UPDATE.to_le_bytes());
            buf.push(TYPE_KEY_UPDATE);
            buf.extend_from_slice(&key_epoch.to_le_bytes());
            buf.push(*direction);
            buf.extend_from_slice(&[0u8; 6]); // reserved
            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }

    // === KeyUpdateAck (§4.6.5) ===

    fn parse_key_update_ack(data: &[u8]) -> Result<Self> {
        check_len(data, 4)?;
        let acked_epoch = read_u32_le(&data[0..4]);
        Ok(Frame::KeyUpdateAck { acked_epoch })
    }

    fn serialize_key_update_ack(&self) -> Result<Vec<u8>> {
        if let Frame::KeyUpdateAck { acked_epoch } = self {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC_KEY_UPDATE.to_le_bytes());
            buf.push(TYPE_KEY_UPDATE_ACK);
            buf.extend_from_slice(&acked_epoch.to_le_bytes());
            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }

    // === AckFrame (§6.4.4) ===

    fn parse_ack_frame(data: &[u8]) -> Result<Self> {
        let mut offset = 0;

        check_len(data, offset + 4)?;
        let stream_id = read_u32_le(&data[offset..offset + 4]);
        offset += 4;

        check_len(data, offset + 1)?;
        let ack_range_count = data[offset] as usize;
        offset += 1;

        let mut ack_ranges = Vec::new();
        for _ in 0..ack_range_count {
            check_len(data, offset + 16)?;
            let start_seq = read_u64_le(&data[offset..offset + 8]);
            let end_seq = read_u64_le(&data[offset + 8..offset + 16]);
            ack_ranges.push(AckRange { start_seq, end_seq });
            offset += 16;
        }

        Ok(Frame::AckFrame {
            stream_id,
            ack_ranges,
        })
    }

    fn serialize_ack_frame(&self) -> Result<Vec<u8>> {
        if let Frame::AckFrame {
            stream_id,
            ack_ranges,
        } = self
        {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC_ACK.to_le_bytes());
            buf.push(TYPE_ACK);
            buf.extend_from_slice(&stream_id.to_le_bytes());
            buf.push(ack_ranges.len() as u8);

            for range in ack_ranges {
                buf.extend_from_slice(&range.start_seq.to_le_bytes());
                buf.extend_from_slice(&range.end_seq.to_le_bytes());
            }

            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }

    // === WindowUpdate (§3.3.9) ===

    fn parse_window_update(data: &[u8]) -> Result<Self> {
        check_len(data, 12)?;
        let stream_id = read_u32_le(&data[0..4]);
        let window_increment = read_u64_le(&data[4..12]);
        Ok(Frame::WindowUpdate {
            stream_id,
            window_increment,
        })
    }

    fn serialize_window_update(&self) -> Result<Vec<u8>> {
        if let Frame::WindowUpdate {
            stream_id,
            window_increment,
        } = self
        {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC_WINDOW_UPDATE.to_le_bytes());
            buf.push(TYPE_WINDOW_UPDATE);
            buf.extend_from_slice(&stream_id.to_le_bytes());
            buf.extend_from_slice(&window_increment.to_le_bytes());
            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }

    // === ErrorFrame (§3.3.12) ===

    fn parse_error_frame(data: &[u8]) -> Result<Self> {
        check_len(data, 4)?;
        let error_code = ErrorCode::from_u8(data[0])
            .ok_or_else(|| Error::InvalidFrame(format!("Unknown error code: 0x{:02X}", data[0])))?;
        // reserved: 3 bytes (ignore)
        Ok(Frame::ErrorFrame { error_code })
    }

    fn serialize_error_frame(&self) -> Result<Vec<u8>> {
        if let Frame::ErrorFrame { error_code } = self {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC_ERROR.to_le_bytes());
            buf.push(TYPE_ERROR);
            buf.push(error_code.to_u8());
            buf.extend_from_slice(&[0u8; 3]); // reserved
            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }

    // === DataFrame (§3.3.10) ===

    fn parse_data_frame(data: &[u8]) -> Result<Self> {
        let mut offset = 0;

        check_len(data, offset + 4)?;
        let stream_id = read_u32_le(&data[offset..offset + 4]);
        offset += 4;

        check_len(data, offset + 8)?;
        let seq = read_u64_le(&data[offset..offset + 8]);
        offset += 8;

        check_len(data, offset + 1)?;
        let flags = data[offset];
        offset += 1;

        check_len(data, offset + 4)?;
        let length = read_u32_le(&data[offset..offset + 4]) as usize;
        offset += 4;

        check_len(data, offset + length)?;
        let payload = data[offset..offset + length].to_vec();

        Ok(Frame::DataFrame {
            stream_id,
            seq,
            flags,
            payload,
        })
    }

    fn serialize_data_frame(&self) -> Result<Vec<u8>> {
        if let Frame::DataFrame {
            stream_id,
            seq,
            flags,
            payload,
        } = self
        {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC_DATA.to_le_bytes());
            buf.push(TYPE_DATA);
            buf.extend_from_slice(&stream_id.to_le_bytes());
            buf.extend_from_slice(&seq.to_le_bytes());
            buf.push(*flags);
            buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            buf.extend_from_slice(payload);
            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }

    // === EncryptedRecord (§3.3.13) ===

    #[allow(dead_code)] // Will be used when implementing encrypted frame support
    fn parse_encrypted_record(data: &[u8]) -> Result<Self> {
        check_len(data, 29)?; // 4 (length) + 1 (epoch) + 8 (counter) + 16 (tag)

        let length = read_u32_le(&data[0..4]) as usize;
        if data.len() < length {
            return Err(Error::InsufficientData(length));
        }

        let epoch = data[4];
        let counter = read_u64_le(&data[5..13]);

        let ciphertext_len = length - 29;
        check_len(data, 13 + ciphertext_len + 16)?;
        let ciphertext = data[13..13 + ciphertext_len].to_vec();

        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[13 + ciphertext_len..13 + ciphertext_len + 16]);

        Ok(Frame::EncryptedRecord {
            epoch,
            counter,
            ciphertext,
            tag,
        })
    }

    fn serialize_encrypted_record(&self) -> Result<Vec<u8>> {
        if let Frame::EncryptedRecord {
            epoch,
            counter,
            ciphertext,
            tag,
        } = self
        {
            let length = 4 + 1 + 8 + ciphertext.len() + 16;
            let mut buf = Vec::new();
            buf.extend_from_slice(&(length as u32).to_le_bytes());
            buf.push(*epoch);
            buf.extend_from_slice(&counter.to_le_bytes());
            buf.extend_from_slice(ciphertext);
            buf.extend_from_slice(tag);
            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }

    // === StreamChunk (§3.3.7) ===

    #[allow(dead_code)] // Will be used when implementing stream chunking support
    fn parse_stream_chunk(data: &[u8]) -> Result<Self> {
        check_len(data, 8)?;
        let stream_id = read_u32_le(&data[0..4]);
        let length = read_u32_le(&data[4..8]) as usize;
        check_len(data, 8 + length)?;
        let payload = data[8..8 + length].to_vec();
        Ok(Frame::StreamChunk { stream_id, payload })
    }

    fn serialize_stream_chunk(&self) -> Result<Vec<u8>> {
        if let Frame::StreamChunk { stream_id, payload } = self {
            let mut buf = Vec::new();
            buf.extend_from_slice(&stream_id.to_le_bytes());
            buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            buf.extend_from_slice(payload);
            Ok(buf)
        } else {
            Err(Error::InvalidFrame("Wrong frame type".into()))
        }
    }
}

// === Helper functions ===

#[inline]
fn check_len(data: &[u8], needed: usize) -> Result<()> {
    if data.len() < needed {
        Err(Error::InsufficientData(needed))
    } else {
        Ok(())
    }
}

#[inline]
fn read_u16_le(data: &[u8]) -> u16 {
    u16::from_le_bytes([data[0], data[1]])
}

#[inline]
fn read_u32_le(data: &[u8]) -> u32 {
    u32::from_le_bytes([data[0], data[1], data[2], data[3]])
}

#[inline]
fn read_u64_le(data: &[u8]) -> u64 {
    u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_hello_roundtrip() {
        let frame = Frame::ClientHello {
            supported_versions: vec![0x0100], // version 1.0
            min_version: 0x0100,
            supported_ciphers: vec![0x01, 0x02],
            x25519_pubkey: [0x42; 32],
            random: [0x99; 32],
        };

        let serialized = frame.serialize().expect("serialize failed");
        let parsed = Frame::parse(&serialized).expect("parse failed");
        assert_eq!(frame, parsed);
    }

    #[test]
    fn test_error_frame_roundtrip() {
        let frame = Frame::ErrorFrame {
            error_code: ErrorCode::HandshakeTimeout,
        };

        let serialized = frame.serialize().expect("serialize failed");
        let parsed = Frame::parse(&serialized).expect("parse failed");
        assert_eq!(frame, parsed);
    }

    #[test]
    fn test_sync_frame_integrity() {
        let streams = vec![
            StreamState {
                stream_id: 42,
                global_seq: 1000,
                last_acked: 500,
            },
            StreamState {
                stream_id: 43,
                global_seq: 2000,
                last_acked: 1500,
            },
        ];

        let frame = Frame::SyncFrame {
            session_id: [0x11; 16],
            streams,
            flags: 0,
        };

        let serialized = frame.serialize().expect("serialize failed");
        let parsed = Frame::parse(&serialized).expect("parse failed");
        assert_eq!(frame, parsed);
    }

    #[test]
    fn test_data_frame_roundtrip() {
        let frame = Frame::DataFrame {
            stream_id: 4,
            seq: 0,
            flags: 0,
            payload: b"Hello, zp!".to_vec(),
        };

        let serialized = frame.serialize().expect("serialize failed");
        let parsed = Frame::parse(&serialized).expect("parse failed");
        assert_eq!(frame, parsed);
    }

    #[test]
    fn test_window_update_roundtrip() {
        let frame = Frame::WindowUpdate {
            stream_id: 0,              // connection-level
            window_increment: 1048576, // 1MB
        };

        let serialized = frame.serialize().expect("serialize failed");
        let parsed = Frame::parse(&serialized).expect("parse failed");
        assert_eq!(frame, parsed);
    }

    #[test]
    fn test_stream_state_integrity() {
        let state = StreamState {
            stream_id: 123,
            global_seq: 456789,
            last_acked: 123456,
        };

        let integrity1 = state.compute_integrity();
        let integrity2 = state.compute_integrity();

        // Should be deterministic
        assert_eq!(integrity1, integrity2);

        // Different state should give different hash
        let state2 = StreamState {
            stream_id: 123,
            global_seq: 456789,
            last_acked: 123457, // different
        };
        assert_ne!(integrity1, state2.compute_integrity());
    }
}
