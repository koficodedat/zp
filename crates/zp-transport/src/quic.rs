//! QUIC transport implementation.
//!
//! Primary transport per spec §3.1.
//! Uses BBR v2 congestion control.

use crate::{Error, Result};

/// QUIC transport endpoint.
pub struct QuicTransport {
    _inner: (),
}

impl QuicTransport {
    /// Create a new QUIC transport.
    pub fn new() -> Result<Self> {
        // TODO: Implement using quinn
        Err(Error::TransportUnavailable(
            "QUIC not yet implemented".into(),
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

impl Default for QuicTransport {
    fn default() -> Self {
        Self::new().expect("QUIC transport creation should not fail")
    }
}
