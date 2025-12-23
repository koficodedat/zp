//! Platform-specific integrations for the zp protocol.
//!
//! Implements:
//! - iOS: Secure Enclave, Network.framework HTTP/3 backgrounding
//! - Android: Hardware KeyStore, Foreground Services
//! - Browser: WebCrypto, WASM bindings (security-limited per spec §1.5)

// iOS platform code requires unsafe for FFI to Security.framework
#![cfg_attr(not(target_os = "ios"), forbid(unsafe_code))]
#![warn(missing_docs)]

pub mod error;
pub mod mock;
pub mod traits;

#[cfg(target_os = "ios")]
pub mod ios;

#[cfg(target_os = "android")]
pub mod android;

#[cfg(target_arch = "wasm32")]
pub mod browser;

pub use error::{Error, Result};
pub use traits::{InterfaceType, KeyProvider, NetworkMonitor, NetworkPath};
