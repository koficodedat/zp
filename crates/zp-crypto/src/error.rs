//! Error types for cryptographic operations.

use thiserror::Error;

/// Result type alias for cryptographic operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Cryptographic operation errors.
#[derive(Debug, Error)]
pub enum Error {
    /// Key exchange failed.
    #[error("Key exchange failed: {0}")]
    KeyExchange(String),

    /// AEAD encryption failed.
    #[error("AEAD encryption failed: {0}")]
    Encryption(String),

    /// AEAD decryption failed.
    #[error("AEAD decryption failed: {0}")]
    Decryption(String),

    /// Key derivation failed.
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    /// Invalid input length.
    #[error("Invalid input length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length received in bytes.
        actual: usize,
    },

    /// Invalid cipher suite.
    #[error("Invalid cipher suite: {0}")]
    InvalidCipherSuite(u16),

    /// Unsupported operation.
    #[error("Unsupported operation: {0}")]
    Unsupported(String),

    /// Key generation failed.
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Invalid key length.
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(String),

    /// Invalid private key.
    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Invalid public key.
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
}
