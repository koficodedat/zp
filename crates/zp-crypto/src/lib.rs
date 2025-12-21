//! Cryptographic primitives for the zp transport protocol.
//!
//! This crate implements the cryptographic foundations required by the zp specification v1.0:
//! - Key exchange (X25519, ML-KEM-768, ML-KEM-1024, ECDH-P256)
//! - AEAD encryption (ChaCha20-Poly1305, AES-256-GCM)
//! - Key derivation (HKDF-based per spec §4.2.4, §4.3.4, §4.6.3)
//! - Password-authenticated key exchange (OPAQUE per RFC 9807, DA-0001)
//!
//! All implementations follow security requirements from CLAUDE.md:
//! - No unsafe code without SAFETY comments
//! - All secrets use Zeroizing wrappers
//! - Constant-time comparisons via subtle crate
//! - No logging of key material

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod aead;
pub mod error;
pub mod kdf;
pub mod kex;
pub mod pake;
pub mod suite;

pub use error::{Error, Result};
pub use suite::CipherSuite;
