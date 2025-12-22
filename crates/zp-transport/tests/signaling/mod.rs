//! Signaling infrastructure for WebRTC tests.

pub mod client;
pub mod embedded_server;
pub mod server;

// Future: Binary peer for Docker testing
#[allow(dead_code)]
mod test_peer;
