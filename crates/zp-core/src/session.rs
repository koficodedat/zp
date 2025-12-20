//! Session management and state machine.
//!
//! Implements:
//! - Handshake state machine (Stranger/Friend/Family modes per §4)
//! - Cipher pinning validation
//! - Session resumption

use crate::{Error, Result};

/// Session state machine.
pub struct Session {
    _state: SessionState,
}

/// Session states during handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // TODO: Remove once handshake state machine is implemented
enum SessionState {
    /// Initial state, no handshake started.
    Idle,
    /// ClientHello sent/received.
    HelloSent,
    /// ServerHello received.
    HelloReceived,
    /// Key exchange in progress.
    KeyExchange,
    /// Handshake complete, application data allowed.
    Established,
    /// Session closed.
    Closed,
}

impl Session {
    /// Create a new session.
    pub fn new() -> Self {
        Self {
            _state: SessionState::Idle,
        }
    }

    /// Initiate handshake as client.
    pub fn connect(&mut self) -> Result<()> {
        // TODO: Implement handshake initiation
        Err(Error::InvalidState)
    }

    /// Accept handshake as server.
    pub fn accept(&mut self) -> Result<()> {
        // TODO: Implement handshake acceptance
        Err(Error::InvalidState)
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new();
        assert_eq!(session._state, SessionState::Idle);
    }
}
