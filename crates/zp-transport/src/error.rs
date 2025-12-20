//! Transport layer errors.

use thiserror::Error;

/// Result type alias.
pub type Result<T> = core::result::Result<T, Error>;

/// Transport errors.
#[derive(Debug, Error)]
pub enum Error {
    /// Connection failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Transport not available.
    #[error("Transport not available: {0}")]
    TransportUnavailable(String),

    /// Protocol error from core.
    #[error("Protocol error: {0}")]
    Protocol(#[from] zp_core::Error),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
