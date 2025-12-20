//! Transport layer implementations for the zp protocol.
//!
//! Implements multiple transport backends with automatic fallback:
//! - QUIC over UDP (primary, spec §3.1)
//! - TCP with byte-level sync (fallback, spec §3.2)
//! - WebSocket (browser fallback, spec Appendix D)
//! - WebRTC DataChannel (browser P2P, spec §5)
//!
//! Transport selection is automatic based on network conditions.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "tcp")]
pub mod tcp;

#[cfg(feature = "websocket")]
pub mod websocket;

#[cfg(feature = "webrtc")]
pub mod webrtc;

pub use error::{Error, Result};
