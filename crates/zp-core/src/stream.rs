//! Stream multiplexing and flow control.
//!
//! Implements:
//! - Stream lifecycle management
//! - Flow control per spec §3.3.9
//! - Priority scheduling per spec §3.3.8

use crate::{Error, Result};

/// A multiplexed stream within a session.
pub struct Stream {
    /// Stream identifier.
    id: u32,
    /// Current state.
    state: StreamState,
    /// Send window (flow control).
    send_window: u32,
    /// Receive window (flow control).
    #[allow(dead_code)] // TODO: Use in recv() implementation
    recv_window: u32,
    /// Priority (1-255, higher is more urgent).
    priority: u8,
}

/// Stream states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    /// Stream is open and can send/receive data.
    Open,
    /// Local side closed (sent StreamClose).
    HalfClosedLocal,
    /// Remote side closed (received StreamClose).
    HalfClosedRemote,
    /// Both sides closed.
    Closed,
}

impl Stream {
    /// Create a new stream with given ID.
    pub fn new(id: u32, initial_window: u32) -> Self {
        Self {
            id,
            state: StreamState::Open,
            send_window: initial_window,
            recv_window: initial_window,
            priority: 128, // Default priority
        }
    }

    /// Get stream ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Send data on this stream.
    pub fn send(&mut self, _data: &[u8]) -> Result<()> {
        if self.state != StreamState::Open && self.state != StreamState::HalfClosedRemote {
            return Err(Error::StreamClosed);
        }
        // TODO: Implement flow control check and data sending
        Err(Error::InvalidState)
    }

    /// Receive data from this stream.
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        if self.state == StreamState::Closed || self.state == StreamState::HalfClosedLocal {
            return Err(Error::StreamClosed);
        }
        // TODO: Implement data receiving
        Err(Error::InvalidState)
    }

    /// Close this stream for sending.
    pub fn close(&mut self) -> Result<()> {
        match self.state {
            StreamState::Open => {
                self.state = StreamState::HalfClosedLocal;
                Ok(())
            }
            StreamState::HalfClosedRemote => {
                self.state = StreamState::Closed;
                Ok(())
            }
            _ => Err(Error::StreamClosed),
        }
    }

    /// Update send window (received WindowUpdate).
    pub fn update_send_window(&mut self, increment: u32) {
        self.send_window = self.send_window.saturating_add(increment);
    }

    /// Update priority.
    pub fn set_priority(&mut self, priority: u8) {
        // Per spec §3.3.8: priority 0 is clamped to 1
        self.priority = priority.max(1);
    }

    /// Get current priority.
    pub fn priority(&self) -> u8 {
        self.priority
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_creation() {
        let stream = Stream::new(1, 65536);
        assert_eq!(stream.id(), 1);
        assert_eq!(stream.priority(), 128);
    }

    #[test]
    fn test_priority_clamping() {
        let mut stream = Stream::new(1, 65536);
        stream.set_priority(0);
        assert_eq!(stream.priority(), 1); // Clamped to 1 per spec
    }
}
