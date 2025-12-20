//! Platform-specific integrations for the zp protocol.
//!
//! Implements:
//! - iOS: Secure Enclave, Network.framework HTTP/3 backgrounding
//! - Android: Hardware KeyStore, Foreground Services
//! - Browser: WebCrypto, WASM bindings (security-limited per spec §1.5)

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;

#[cfg(feature = "ios")]
pub mod ios;

#[cfg(feature = "android")]
pub mod android;

#[cfg(feature = "browser")]
pub mod browser;

pub use error::{Error, Result};
