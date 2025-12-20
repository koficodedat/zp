//! WebSocket transport implementation.
//!
//! Browser fallback transport per spec Appendix D.

use crate::{Error, Result};

/// WebSocket transport endpoint.
pub struct WebSocketTransport {
    _inner: (),
}

impl WebSocketTransport {
    /// Create a new WebSocket transport.
    pub fn new() -> Result<Self> {
        // TODO: Implement
        Err(Error::TransportUnavailable(
            "WebSocket not yet implemented".into(),
        ))
    }
}

impl Default for WebSocketTransport {
    fn default() -> Self {
        Self::new().expect("WebSocket transport creation should not fail")
    }
}
