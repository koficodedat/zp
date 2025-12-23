//! iOS platform implementation.
//!
//! Provides device-bound key management via Secure Enclave and network monitoring
//! via Network.framework per spec §6.6.
//!
//! # Architecture
//!
//! - **SecureEnclaveKeyProvider**: Production implementation using Security.framework
//!   - Hardware-backed key generation in Secure Enclave
//!   - Persistent storage in iOS Keychain
//!   - One device-bound key per device (Key Singularity)
//!
//! - **InMemoryKeyProvider**: Simulator fallback
//!   - Software-based key generation (Secure Enclave unavailable in simulator)
//!   - Logs warning about non-production use
//!   - Suitable for development/testing only
//!
//! - **NWPathMonitorWrapper**: Network.framework integration
//!   - Monitors WiFi ↔ Cellular transitions
//!   - Detects expensive/constrained network conditions
//!   - Enables connection migration per spec §3.3.5-6

pub mod in_memory;
pub mod network_monitor;
pub mod secure_enclave;

pub use in_memory::InMemoryKeyProvider;
pub use network_monitor::NWPathMonitorWrapper;
pub use secure_enclave::SecureEnclaveKeyProvider;
