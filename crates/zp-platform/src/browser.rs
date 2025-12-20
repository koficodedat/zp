//! Browser/WASM platform integration.
//!
//! Implements:
//! - WebCrypto API integration
//! - IndexedDB storage
//! - WebTransport/WebRTC fallback chain
//!
//! WARNING: Per spec §1.5, browser deployments cannot provide security
//! guarantees equivalent to native platforms. Cipher pinning NOT guaranteed
//! against same-origin XSS.

use crate::{Error, Result};

/// Browser platform adapter.
pub struct BrowserPlatform {
    _inner: (),
}

impl BrowserPlatform {
    /// Create a new browser platform adapter.
    pub fn new() -> Result<Self> {
        // TODO: Implement browser-specific initialization
        Err(Error::Unavailable(
            "Browser platform not yet implemented".into(),
        ))
    }

    /// Store key in IndexedDB.
    pub fn store_key(&self, _key_id: &str, _key_data: &[u8]) -> Result<()> {
        // TODO: Implement IndexedDB storage
        Err(Error::Keystore("Not implemented".into()))
    }

    /// Retrieve key from IndexedDB.
    pub fn retrieve_key(&self, _key_id: &str) -> Result<Vec<u8>> {
        // TODO: Implement IndexedDB retrieval
        Err(Error::Keystore("Not implemented".into()))
    }
}

impl Default for BrowserPlatform {
    fn default() -> Self {
        Self::new().expect("Browser platform creation should not fail")
    }
}
