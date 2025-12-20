//! Foreign function interface bindings for the zp protocol.
//!
//! Generates C, Swift, and Kotlin bindings via UniFFI for use in:
//! - iOS applications (Swift)
//! - Android applications (Kotlin)
//! - C/C++ applications
//!
//! See UniFFI documentation: https://mozilla.github.io/uniffi-rs/

#![warn(missing_docs)]

// TODO: Define UniFFI interface in zp.udl

/// FFI error type.
#[derive(Debug, thiserror::Error)]
pub enum FfiError {
    /// Protocol error.
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Transport error.
    #[error("Transport error: {0}")]
    Transport(String),

    /// Platform error.
    #[error("Platform error: {0}")]
    Platform(String),
}

impl From<zp_core::Error> for FfiError {
    fn from(err: zp_core::Error) -> Self {
        FfiError::Protocol(err.to_string())
    }
}

/// FFI-safe session handle.
pub struct ZpSession {
    _inner: zp_core::Session,
}

impl ZpSession {
    /// Create a new session.
    pub fn new() -> Self {
        Self {
            _inner: zp_core::Session::new(),
        }
    }

    /// Connect to a remote peer.
    pub fn connect(&mut self, _address: String) -> Result<(), FfiError> {
        // TODO: Implement
        Err(FfiError::Protocol("Not yet implemented".into()))
    }

    /// Send data on the session.
    pub fn send(&self, _data: Vec<u8>) -> Result<(), FfiError> {
        // TODO: Implement
        Err(FfiError::Protocol("Not yet implemented".into()))
    }

    /// Receive data from the session.
    pub fn receive(&self) -> Result<Vec<u8>, FfiError> {
        // TODO: Implement
        Err(FfiError::Protocol("Not yet implemented".into()))
    }

    /// Close the session.
    pub fn close(&mut self) -> Result<(), FfiError> {
        // TODO: Implement
        Err(FfiError::Protocol("Not yet implemented".into()))
    }
}

impl Default for ZpSession {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: Add uniffi::include_scaffolding! macro once .udl is created
