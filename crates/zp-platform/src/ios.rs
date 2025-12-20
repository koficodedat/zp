//! iOS platform integration.
//!
//! Implements:
//! - Secure Enclave key storage
//! - Network.framework HTTP/3 backgrounding
//! - App lifecycle management

use crate::{Error, Result};

/// iOS platform adapter.
pub struct IosPlatform {
    _inner: (),
}

impl IosPlatform {
    /// Create a new iOS platform adapter.
    pub fn new() -> Result<Self> {
        // TODO: Implement iOS-specific initialization
        Err(Error::Unavailable(
            "iOS platform not yet implemented".into(),
        ))
    }

    /// Store key in Secure Enclave.
    pub fn store_key(&self, _key_id: &str, _key_data: &[u8]) -> Result<()> {
        // TODO: Implement Secure Enclave storage
        Err(Error::Keystore("Not implemented".into()))
    }

    /// Retrieve key from Secure Enclave.
    pub fn retrieve_key(&self, _key_id: &str) -> Result<Vec<u8>> {
        // TODO: Implement Secure Enclave retrieval
        Err(Error::Keystore("Not implemented".into()))
    }
}

impl Default for IosPlatform {
    fn default() -> Self {
        Self::new().expect("iOS platform creation should not fail")
    }
}
