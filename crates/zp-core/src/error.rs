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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_to_u8() {
        // Test all 14 error codes
        assert_eq!(ErrorCode::HandshakeTimeout.to_u8(), 0x01);
        assert_eq!(ErrorCode::CipherDowngrade.to_u8(), 0x02);
        assert_eq!(ErrorCode::MigrationFailed.to_u8(), 0x03);
        assert_eq!(ErrorCode::TokenExpired.to_u8(), 0x04);
        assert_eq!(ErrorCode::TeeAttestation.to_u8(), 0x05);
        assert_eq!(ErrorCode::RelayUnavailable.to_u8(), 0x06);
        assert_eq!(ErrorCode::VersionMismatch.to_u8(), 0x07);
        assert_eq!(ErrorCode::RateLimited.to_u8(), 0x08);
        assert_eq!(ErrorCode::TokenIpMismatch.to_u8(), 0x09);
        assert_eq!(ErrorCode::StreamLimit.to_u8(), 0x0A);
        assert_eq!(ErrorCode::RekeyFailed.to_u8(), 0x0B);
        assert_eq!(ErrorCode::SyncRejected.to_u8(), 0x0C);
        assert_eq!(ErrorCode::FlowStall.to_u8(), 0x0D);
        assert_eq!(ErrorCode::ProtocolViolation.to_u8(), 0x0E);
    }

    #[test]
    fn test_error_code_from_u8() {
        // Test all 14 error codes roundtrip
        assert_eq!(ErrorCode::from_u8(0x01), Some(ErrorCode::HandshakeTimeout));
        assert_eq!(ErrorCode::from_u8(0x02), Some(ErrorCode::CipherDowngrade));
        assert_eq!(ErrorCode::from_u8(0x03), Some(ErrorCode::MigrationFailed));
        assert_eq!(ErrorCode::from_u8(0x04), Some(ErrorCode::TokenExpired));
        assert_eq!(ErrorCode::from_u8(0x05), Some(ErrorCode::TeeAttestation));
        assert_eq!(ErrorCode::from_u8(0x06), Some(ErrorCode::RelayUnavailable));
        assert_eq!(ErrorCode::from_u8(0x07), Some(ErrorCode::VersionMismatch));
        assert_eq!(ErrorCode::from_u8(0x08), Some(ErrorCode::RateLimited));
        assert_eq!(ErrorCode::from_u8(0x09), Some(ErrorCode::TokenIpMismatch));
        assert_eq!(ErrorCode::from_u8(0x0A), Some(ErrorCode::StreamLimit));
        assert_eq!(ErrorCode::from_u8(0x0B), Some(ErrorCode::RekeyFailed));
        assert_eq!(ErrorCode::from_u8(0x0C), Some(ErrorCode::SyncRejected));
        assert_eq!(ErrorCode::from_u8(0x0D), Some(ErrorCode::FlowStall));
        assert_eq!(ErrorCode::from_u8(0x0E), Some(ErrorCode::ProtocolViolation));

        // Test invalid codes
        assert_eq!(ErrorCode::from_u8(0x00), None);
        assert_eq!(ErrorCode::from_u8(0x0F), None);
        assert_eq!(ErrorCode::from_u8(0xFF), None);
    }

    #[test]
    fn test_error_code_roundtrip() {
        // All error codes should roundtrip correctly
        let codes = [
            ErrorCode::HandshakeTimeout,
            ErrorCode::CipherDowngrade,
            ErrorCode::MigrationFailed,
            ErrorCode::TokenExpired,
            ErrorCode::TeeAttestation,
            ErrorCode::RelayUnavailable,
            ErrorCode::VersionMismatch,
            ErrorCode::RateLimited,
            ErrorCode::TokenIpMismatch,
            ErrorCode::StreamLimit,
            ErrorCode::RekeyFailed,
            ErrorCode::SyncRejected,
            ErrorCode::FlowStall,
            ErrorCode::ProtocolViolation,
        ];

        for code in &codes {
            let wire = code.to_u8();
            let parsed = ErrorCode::from_u8(wire);
            assert!(
                parsed.is_some(),
                "Failed to parse wire format 0x{:02X}",
                wire
            );
        }
    }
}
