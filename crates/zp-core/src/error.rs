//! Error types for protocol operations.

use thiserror::Error;

/// Result type alias for protocol operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Protocol operation errors.
///
/// Error codes match spec Appendix B.
#[derive(Debug, Error)]
pub enum Error {
    /// Handshake timeout (0x01).
    #[error("Handshake timeout")]
    HandshakeTimeout,

    /// Cipher downgrade attempt (0x02).
    #[error("Cipher downgrade attempt")]
    CipherDowngrade,

    /// Migration failed (0x03).
    #[error("Migration failed")]
    MigrationFailed,

    /// State token expired (0x04).
    #[error("State token expired")]
    TokenExpired,

    /// TEE attestation failed (0x05).
    #[error("TEE attestation failed")]
    TeeAttestation,

    /// Relay unavailable (0x06).
    #[error("Relay unavailable")]
    RelayUnavailable,

    /// Version mismatch (0x07).
    #[error("Version mismatch")]
    VersionMismatch,

    /// Rate limited (0x08).
    #[error("Rate limited")]
    RateLimited,

    /// Token IP mismatch (0x09).
    #[error("Token IP mismatch")]
    TokenIpMismatch,

    /// Stream limit exceeded (0x0A).
    #[error("Stream limit exceeded")]
    StreamLimit,

    /// Key rotation failed (0x0B).
    #[error("Key rotation failed")]
    RekeyFailed,

    /// Sync rejected (0x0C).
    #[error("Sync rejected")]
    SyncRejected,

    /// Flow control stall (0x0D).
    #[error("Flow control stall")]
    FlowStall,

    /// Protocol violation (0x0E).
    #[error("Protocol violation: {0}")]
    ProtocolViolation(String),

    /// Invalid frame format.
    #[error("Invalid frame format: {0}")]
    InvalidFrame(String),

    /// Insufficient data.
    #[error("Insufficient data: need {0} bytes")]
    InsufficientData(usize),

    /// Invalid state transition.
    #[error("Invalid state transition")]
    InvalidState,

    /// Stream closed.
    #[error("Stream closed")]
    StreamClosed,

    /// Cryptographic error.
    #[error("Crypto error: {0}")]
    Crypto(#[from] zp_crypto::Error),

    /// I/O error (not a protocol error).
    #[error("I/O error: {0}")]
    Io(String),
}

/// Protocol error codes per spec Appendix B.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    /// Handshake timeout (0x01).
    HandshakeTimeout = 0x01,
    /// Cipher downgrade (0x02).
    CipherDowngrade = 0x02,
    /// Migration failed (0x03).
    MigrationFailed = 0x03,
    /// Token expired (0x04).
    TokenExpired = 0x04,
    /// TEE attestation (0x05).
    TeeAttestation = 0x05,
    /// Relay unavailable (0x06).
    RelayUnavailable = 0x06,
    /// Version mismatch (0x07).
    VersionMismatch = 0x07,
    /// Rate limited (0x08).
    RateLimited = 0x08,
    /// Token IP mismatch (0x09).
    TokenIpMismatch = 0x09,
    /// Stream limit (0x0A).
    StreamLimit = 0x0A,
    /// Rekey failed (0x0B).
    RekeyFailed = 0x0B,
    /// Sync rejected (0x0C).
    SyncRejected = 0x0C,
    /// Flow stall (0x0D).
    FlowStall = 0x0D,
    /// Protocol violation (0x0E).
    ProtocolViolation = 0x0E,
}

impl ErrorCode {
    /// Convert to wire format.
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Convert from wire format.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::HandshakeTimeout),
            0x02 => Some(Self::CipherDowngrade),
            0x03 => Some(Self::MigrationFailed),
            0x04 => Some(Self::TokenExpired),
            0x05 => Some(Self::TeeAttestation),
            0x06 => Some(Self::RelayUnavailable),
            0x07 => Some(Self::VersionMismatch),
            0x08 => Some(Self::RateLimited),
            0x09 => Some(Self::TokenIpMismatch),
            0x0A => Some(Self::StreamLimit),
            0x0B => Some(Self::RekeyFailed),
            0x0C => Some(Self::SyncRejected),
            0x0D => Some(Self::FlowStall),
            0x0E => Some(Self::ProtocolViolation),
            _ => None,
        }
    }
}
