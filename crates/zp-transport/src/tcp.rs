//! TCP transport implementation with byte-level sync.
//!
//! Fallback transport per spec §3.2.

use crate::{Error, Result};

/// TCP transport endpoint.
pub struct TcpTransport {
    _inner: (),
}

impl TcpTransport {
    /// Create a new TCP transport.
    pub fn new() -> Result<Self> {
        // TODO: Implement using tokio::net::TcpStream
        Err(Error::TransportUnavailable(
            "TCP not yet implemented".into(),
        ))
    }

    /// Connect to a remote endpoint.
    pub async fn connect(&self, _addr: &str) -> Result<()> {
        // TODO: Implement
        Err(Error::ConnectionFailed("Not implemented".into()))
    }

    /// Accept incoming connections.
    pub async fn accept(&self) -> Result<()> {
        // TODO: Implement
        Err(Error::TransportUnavailable("Not implemented".into()))
    }
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::new().expect("TCP transport creation should not fail")
    }
}
