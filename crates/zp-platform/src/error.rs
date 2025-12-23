//! Platform integration errors.

use thiserror::Error;

/// Result type alias.
pub type Result<T> = core::result::Result<T, Error>;

/// Platform errors.
#[derive(Debug, Error)]
pub enum Error {
    /// Platform feature not available.
    #[error("Platform feature not available: {0}")]
    Unavailable(String),

    /// Keystore error.
    #[error("Keystore error: {0}")]
    Keystore(String),

    /// Background task error.
    #[error("Background task error: {0}")]
    BackgroundTask(String),
}
