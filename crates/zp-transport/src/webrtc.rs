//! WebRTC DataChannel transport implementation.
//!
//! Browser P2P transport per spec §5.

use crate::{Error, Result};

/// WebRTC transport endpoint.
pub struct WebRtcTransport {
    _inner: (),
}

impl WebRtcTransport {
    /// Create a new WebRTC transport.
    pub fn new() -> Result<Self> {
        // TODO: Implement
        Err(Error::TransportUnavailable(
            "WebRTC not yet implemented".into(),
        ))
    }
}

impl Default for WebRtcTransport {
    fn default() -> Self {
        Self::new().expect("WebRTC transport creation should not fail")
    }
}
