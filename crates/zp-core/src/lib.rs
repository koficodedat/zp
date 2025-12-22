//! Core protocol engine for the zp transport protocol.
//!
//! This crate implements the zp protocol state machine and framing per spec v1.0:
//! - Frame parsing and serialization (§3.3)
//! - Session management with cipher pinning
//! - Stream multiplexing and flow control (§3.3.9)
//! - Handshake state machines (Stranger/Friend/Family modes, §4)
//!
//! This is a no_std compatible core. Platform-specific I/O is handled by zp-transport.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod frame;
pub mod session;
pub mod stream;
pub mod token;

pub use error::{Error, ErrorCode, Result};
pub use frame::Frame;
pub use session::Session;
pub use stream::Stream;
pub use token::StateToken;
