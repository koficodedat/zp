//! Platform abstraction traits for device-bound key management and network monitoring.
//!
//! These traits enable platform-specific implementations while maintaining testability through mocks.

use crate::error::Result;
use zeroize::Zeroizing;

/// Provides device-bound cryptographic keys per spec §6.6.
///
/// Platform-specific implementations:
/// - iOS: Secure Enclave via Security.framework (SecureEnclaveKeyProvider)
/// - Android: Hardware KeyStore (future)
/// - Browser: WebCrypto with IndexedDB (future)
/// - Testing: Deterministic mock (MockKeyProvider)
///
/// # Security Requirements
///
/// - Must provide one device-bound key per device (Key Singularity)
/// - Keys should be hardware-backed when available
/// - Keys must persist across app restarts
/// - All operations must use constant-time comparisons where relevant
pub trait KeyProvider: Send + Sync {
    /// Retrieves the device-bound 32-byte key.
    ///
    /// This key is used to encrypt State Tokens per spec §6.5-6.6.
    ///
    /// # Errors
    ///
    /// - `Error::Keystore` if key generation or retrieval fails
    /// - `Error::Unavailable` if platform doesn't support hardware keys
    ///
    /// # Example
    ///
    /// ```no_run
    /// use zp_platform::traits::KeyProvider;
    ///
    /// fn example(provider: &dyn KeyProvider) -> Result<(), zp_platform::Error> {
    ///     let key = provider.get_device_key()?;
    ///     // Use key for AES-256-GCM encryption
    ///     Ok(())
    /// }
    /// ```
    fn get_device_key(&self) -> Result<Zeroizing<[u8; 32]>>;

    /// Encrypts plaintext using the device-bound key.
    ///
    /// Implementation should use AES-256-GCM with a random nonce.
    ///
    /// # Format
    ///
    /// Returns: `nonce[12] || ciphertext || tag[16]`
    ///
    /// # Errors
    ///
    /// - `Error::Keystore` if encryption fails
    ///
    /// # Security Notes
    ///
    /// - MUST generate a fresh nonce for each encryption
    /// - MUST use a cryptographically secure RNG (e.g., OsRng)
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;

    /// Decrypts ciphertext using the device-bound key.
    ///
    /// # Format
    ///
    /// Expects: `nonce[12] || ciphertext || tag[16]`
    ///
    /// # Errors
    ///
    /// - `Error::Keystore` if decryption fails (wrong key, corrupted data, etc.)
    ///
    /// # Security Notes
    ///
    /// - MUST authenticate before decrypting (AEAD property)
    /// - MUST use constant-time comparison for tag verification
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
}

/// Monitors network path changes for connection migration.
///
/// Platform-specific implementations:
/// - iOS: Network.framework NWPathMonitor (NWPathMonitorWrapper)
/// - Android: ConnectivityManager callbacks (future)
/// - Browser: Network Information API (future)
/// - Testing: Simulated transitions (MockNetworkMonitor)
///
/// # Use Case
///
/// Detects when the device switches between:
/// - WiFi ↔ Cellular
/// - Ethernet ↔ WiFi
/// - Interface up ↔ down
///
/// Enables zp to trigger connection migration per spec §3.3.5-6.
pub trait NetworkMonitor: Send + Sync {
    /// Registers a callback for network path changes.
    ///
    /// The callback is invoked whenever the active network interface changes.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use zp_platform::traits::NetworkMonitor;
    ///
    /// fn example(monitor: &dyn NetworkMonitor) {
    ///     monitor.on_path_change(Box::new(|path| {
    ///         println!("Network changed to {:?}", path.interface_type);
    ///         // Trigger connection migration
    ///     }));
    /// }
    /// ```
    fn on_path_change(&self, callback: Box<dyn Fn(NetworkPath) + Send + Sync>);

    /// Returns the current network path.
    ///
    /// Useful for checking network status before initiating a connection.
    fn current_path(&self) -> NetworkPath;
}

/// Describes the current network path.
///
/// Derived from platform-specific network monitoring APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPath {
    /// Type of network interface.
    pub interface_type: InterfaceType,

    /// Whether the connection is expensive (e.g., metered cellular).
    pub is_expensive: bool,

    /// Whether the connection is constrained (e.g., low data mode).
    pub is_constrained: bool,
}

/// Network interface type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceType {
    /// WiFi connection.
    Wifi,

    /// Cellular connection (3G/4G/5G).
    Cellular,

    /// Wired Ethernet connection.
    Wired,

    /// Other or unknown interface type.
    Other,
}

impl Default for NetworkPath {
    fn default() -> Self {
        Self {
            interface_type: InterfaceType::Other,
            is_expensive: false,
            is_constrained: false,
        }
    }
}
