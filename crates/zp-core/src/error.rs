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

    /// Version mismatch (0x02).
    #[error("Version mismatch")]
    VersionMismatch,

    /// Unsupported cipher suite (0x03).
    #[error("Unsupported cipher suite")]
    UnsupportedCipher,

    /// Invalid frame format (0x04).
    #[error("Invalid frame format: {0}")]
    InvalidFrame(String),

    /// Flow control violation (0x05).
    #[error("Flow control violation")]
    FlowControlViolation,

    /// Stream closed (0x06).
    #[error("Stream closed")]
    StreamClosed,

    /// Cipher downgrade attempt detected (0x07).
    #[error("Cipher downgrade attempt")]
    CipherDowngrade,

    /// Authentication failed (0x08).
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Invalid state transition (0x09).
    #[error("Invalid state transition")]
    InvalidState,

    /// Protocol violation (0x0E).
    #[error("Protocol violation: {0}")]
    ProtocolViolation(String),

    /// Cryptographic error.
    #[error("Crypto error: {0}")]
    Crypto(#[from] zp_crypto::Error),

    /// I/O error (not a protocol error).
    #[error("I/O error: {0}")]
    Io(String),
}

/// Protocol error codes per spec Appendix B.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    /// Handshake timeout (0x01).
    HandshakeTimeout = 0x01,
    /// Version mismatch (0x02).
    VersionMismatch = 0x02,
    /// Unsupported cipher suite (0x03).
    UnsupportedCipher = 0x03,
    /// Invalid frame format (0x04).
    InvalidFrame = 0x04,
    /// Flow control violation (0x05).
    FlowControlViolation = 0x05,
    /// Stream closed (0x06).
    StreamClosed = 0x06,
    /// Cipher downgrade attempt (0x07).
    CipherDowngrade = 0x07,
    /// Authentication failed (0x08).
    AuthenticationFailed = 0x08,
    /// Invalid state transition (0x09).
    InvalidState = 0x09,
    /// Protocol violation (0x0E).
    ProtocolViolation = 0x0E,
}

impl ErrorCode {
    /// Convert to wire format.
    pub fn to_u16(self) -> u16 {
        self as u16
    }

    /// Convert from wire format.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x01 => Some(Self::HandshakeTimeout),
            0x02 => Some(Self::VersionMismatch),
            0x03 => Some(Self::UnsupportedCipher),
            0x04 => Some(Self::InvalidFrame),
            0x05 => Some(Self::FlowControlViolation),
            0x06 => Some(Self::StreamClosed),
            0x07 => Some(Self::CipherDowngrade),
            0x08 => Some(Self::AuthenticationFailed),
            0x09 => Some(Self::InvalidState),
            0x0E => Some(Self::ProtocolViolation),
            _ => None,
        }
    }
}
