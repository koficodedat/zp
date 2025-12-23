//! Mock implementations for testing.
//!
//! Provides deterministic, reproducible behavior for automated CI testing.

use crate::error::{Error, Result};
use crate::traits::{InterfaceType, KeyProvider, NetworkMonitor, NetworkPath};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use std::sync::{Arc, RwLock};
use zeroize::Zeroizing;

/// Type alias for network path change callback.
type PathChangeCallback = Box<dyn Fn(NetworkPath) + Send + Sync>;

/// Mock key provider for testing.
///
/// Provides deterministic keys and AES-256-GCM encryption for reproducible tests.
///
/// # Example
///
/// ```
/// use zp_platform::mock::MockKeyProvider;
/// use zp_platform::traits::KeyProvider;
///
/// let provider = MockKeyProvider::new_deterministic();
/// let key1 = provider.get_device_key().unwrap();
/// let key2 = provider.get_device_key().unwrap();
/// assert_eq!(*key1, *key2); // Deterministic
/// ```
#[derive(Clone)]
pub struct MockKeyProvider {
    key: Arc<Zeroizing<[u8; 32]>>,
}

impl MockKeyProvider {
    /// Creates a mock provider with a deterministic key.
    ///
    /// The key is fixed for reproducible tests. All instances created with this method
    /// will return the same key.
    pub fn new_deterministic() -> Self {
        let key = [0x42u8; 32]; // Fixed key for testing
        Self {
            key: Arc::new(Zeroizing::new(key)),
        }
    }

    /// Creates a mock provider with a random key.
    ///
    /// Useful for tests that need unique keys per instance.
    pub fn new_random() -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self {
            key: Arc::new(Zeroizing::new(key)),
        }
    }

    /// Creates a mock provider with a specific key.
    ///
    /// Useful for test vectors that specify exact keys.
    pub fn with_key(key: [u8; 32]) -> Self {
        Self {
            key: Arc::new(Zeroizing::new(key)),
        }
    }
}

impl KeyProvider for MockKeyProvider {
    fn get_device_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        Ok(Zeroizing::new(**self.key))
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // AES-256-GCM encryption
        let cipher = Aes256Gcm::new_from_slice(&**self.key)
            .map_err(|e| Error::Keystore(format!("Cipher init failed: {}", e)))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::Keystore(format!("Encryption failed: {}", e)))?;

        // Return nonce || ciphertext (ciphertext already includes tag)
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 + 16 {
            return Err(Error::Keystore(
                "Ciphertext too short (need nonce[12] + tag[16])".into(),
            ));
        }

        // Extract nonce
        let nonce = Nonce::from_slice(&ciphertext[..12]);

        // Extract ciphertext (includes tag)
        let ct_with_tag = &ciphertext[12..];

        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(&**self.key)
            .map_err(|e| Error::Keystore(format!("Cipher init failed: {}", e)))?;

        let plaintext = cipher
            .decrypt(nonce, ct_with_tag)
            .map_err(|e| Error::Keystore(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }
}

/// Mock network monitor for testing.
///
/// Simulates network path changes for testing connection migration logic.
///
/// # Example
///
/// ```
/// use zp_platform::mock::MockNetworkMonitor;
/// use zp_platform::traits::{NetworkMonitor, NetworkPath, InterfaceType};
///
/// let monitor = MockNetworkMonitor::new();
/// monitor.on_path_change(Box::new(|path| {
///     println!("Path changed to {:?}", path.interface_type);
/// }));
///
/// // Simulate WiFi -> Cellular transition
/// monitor.simulate_path_change(NetworkPath {
///     interface_type: InterfaceType::Cellular,
///     is_expensive: true,
///     is_constrained: false,
/// });
/// ```
#[derive(Clone)]
pub struct MockNetworkMonitor {
    path: Arc<RwLock<NetworkPath>>,
    callbacks: Arc<RwLock<Vec<PathChangeCallback>>>,
}

impl MockNetworkMonitor {
    /// Creates a new mock network monitor.
    ///
    /// Initial path is WiFi, not expensive, not constrained.
    pub fn new() -> Self {
        Self {
            path: Arc::new(RwLock::new(NetworkPath {
                interface_type: InterfaceType::Wifi,
                is_expensive: false,
                is_constrained: false,
            })),
            callbacks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Creates a mock monitor with a specific initial path.
    pub fn with_path(path: NetworkPath) -> Self {
        Self {
            path: Arc::new(RwLock::new(path)),
            callbacks: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Simulates a network path change.
    ///
    /// Triggers all registered callbacks with the new path.
    pub fn simulate_path_change(&self, new_path: NetworkPath) {
        // Update current path
        if let Ok(mut path) = self.path.write() {
            *path = new_path.clone();
        }

        // Trigger callbacks
        if let Ok(callbacks) = self.callbacks.read() {
            for callback in callbacks.iter() {
                callback(new_path.clone());
            }
        }
    }
}

impl Default for MockNetworkMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkMonitor for MockNetworkMonitor {
    fn on_path_change(&self, callback: PathChangeCallback) {
        if let Ok(mut callbacks) = self.callbacks.write() {
            callbacks.push(callback);
        }
    }

    fn current_path(&self) -> NetworkPath {
        self.path.read().map(|p| p.clone()).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_key_provider_deterministic() {
        let provider1 = MockKeyProvider::new_deterministic();
        let provider2 = MockKeyProvider::new_deterministic();

        let key1 = provider1.get_device_key().unwrap();
        let key2 = provider2.get_device_key().unwrap();

        assert_eq!(*key1, *key2, "Deterministic keys should match");
    }

    #[test]
    fn test_mock_key_provider_random() {
        let provider1 = MockKeyProvider::new_random();
        let provider2 = MockKeyProvider::new_random();

        let key1 = provider1.get_device_key().unwrap();
        let key2 = provider2.get_device_key().unwrap();

        assert_ne!(*key1, *key2, "Random keys should differ");
    }

    #[test]
    fn test_mock_key_provider_with_key() {
        let custom_key = [0x99u8; 32];
        let provider = MockKeyProvider::with_key(custom_key);

        let key = provider.get_device_key().unwrap();
        assert_eq!(*key, custom_key);
    }

    #[test]
    fn test_mock_key_provider_encrypt_decrypt() {
        let provider = MockKeyProvider::new_deterministic();
        let plaintext = b"Hello, zp!";

        let ciphertext = provider.encrypt(plaintext).unwrap();
        let decrypted = provider.decrypt(&ciphertext).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_mock_key_provider_wrong_key() {
        let provider1 = MockKeyProvider::new_deterministic();
        let provider2 = MockKeyProvider::new_random();

        let plaintext = b"Secret message";
        let ciphertext = provider1.encrypt(plaintext).unwrap();

        // Decryption with wrong key should fail
        assert!(provider2.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_mock_key_provider_corrupted_ciphertext() {
        let provider = MockKeyProvider::new_deterministic();
        let plaintext = b"Test data";

        let mut ciphertext = provider.encrypt(plaintext).unwrap();

        // Corrupt the ciphertext
        if let Some(byte) = ciphertext.last_mut() {
            *byte = byte.wrapping_add(1);
        }

        // Decryption should fail
        assert!(provider.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_mock_network_monitor_initial_path() {
        let monitor = MockNetworkMonitor::new();
        let path = monitor.current_path();

        assert_eq!(path.interface_type, InterfaceType::Wifi);
        assert!(!path.is_expensive);
        assert!(!path.is_constrained);
    }

    #[test]
    fn test_mock_network_monitor_with_path() {
        let custom_path = NetworkPath {
            interface_type: InterfaceType::Cellular,
            is_expensive: true,
            is_constrained: true,
        };

        let monitor = MockNetworkMonitor::with_path(custom_path.clone());
        let path = monitor.current_path();

        assert_eq!(path, custom_path);
    }

    #[test]
    fn test_mock_network_monitor_path_change() {
        let monitor = MockNetworkMonitor::new();
        let new_path = NetworkPath {
            interface_type: InterfaceType::Cellular,
            is_expensive: true,
            is_constrained: false,
        };

        monitor.simulate_path_change(new_path.clone());
        let current = monitor.current_path();

        assert_eq!(current, new_path);
    }

    #[test]
    fn test_mock_network_monitor_callback() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let monitor = MockNetworkMonitor::new();
        let triggered = Arc::new(AtomicBool::new(false));
        let triggered_clone = triggered.clone();

        monitor.on_path_change(Box::new(move |path| {
            assert_eq!(path.interface_type, InterfaceType::Cellular);
            triggered_clone.store(true, Ordering::SeqCst);
        }));

        monitor.simulate_path_change(NetworkPath {
            interface_type: InterfaceType::Cellular,
            is_expensive: true,
            is_constrained: false,
        });

        assert!(
            triggered.load(Ordering::SeqCst),
            "Callback should be triggered"
        );
    }
}
