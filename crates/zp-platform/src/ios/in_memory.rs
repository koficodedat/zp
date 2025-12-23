//! In-memory key provider for iOS Simulator.
//!
//! Provides a software-based key provider for development and testing on iOS Simulator,
//! where Secure Enclave is unavailable.
//!
//! # Security Notice
//!
//! This implementation is NOT suitable for production use. Keys are stored in memory
//! and will be lost when the app terminates. Use `SecureEnclaveKeyProvider` for
//! production iOS apps on physical devices.

use crate::error::{Error, Result};
use crate::traits::KeyProvider;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use std::sync::Arc;
use zeroize::Zeroizing;

/// In-memory key provider for iOS Simulator.
///
/// This provider generates a random key on initialization and stores it in memory.
/// It logs a warning on creation to alert developers that this is not production-ready.
///
/// # Example
///
/// ```no_run
/// use zp_platform::ios::InMemoryKeyProvider;
/// use zp_platform::traits::KeyProvider;
///
/// let provider = InMemoryKeyProvider::new();
/// let key = provider.get_device_key().unwrap();
/// // Key is valid only for this process lifetime
/// ```
pub struct InMemoryKeyProvider {
    key: Arc<Zeroizing<[u8; 32]>>,
}

impl InMemoryKeyProvider {
    /// Creates a new in-memory key provider.
    ///
    /// Generates a random 32-byte key using `OsRng` and logs a warning about
    /// non-production use.
    ///
    /// # Security Warning
    ///
    /// This logs a warning message indicating that the key is not hardware-backed
    /// and will not persist across app restarts.
    pub fn new() -> Self {
        tracing::warn!(
            "Using InMemoryKeyProvider - keys are not hardware-backed and will not persist. \
             This is only suitable for iOS Simulator development. \
             Use SecureEnclaveKeyProvider on physical devices."
        );

        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);

        Self {
            key: Arc::new(Zeroizing::new(key)),
        }
    }

    /// Creates a provider with a specific key.
    ///
    /// Useful for testing with predetermined keys.
    ///
    /// # Arguments
    ///
    /// * `key` - The 32-byte key to use
    pub fn with_key(key: [u8; 32]) -> Self {
        tracing::warn!("Using InMemoryKeyProvider with custom key - not suitable for production");

        Self {
            key: Arc::new(Zeroizing::new(key)),
        }
    }
}

impl Default for InMemoryKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProvider for InMemoryKeyProvider {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_provider_creates_random_key() {
        let provider1 = InMemoryKeyProvider::new();
        let provider2 = InMemoryKeyProvider::new();

        let key1 = provider1.get_device_key().unwrap();
        let key2 = provider2.get_device_key().unwrap();

        // Different instances should have different keys
        assert_ne!(*key1, *key2);
    }

    #[test]
    fn test_in_memory_provider_with_key() {
        let custom_key = [0x42u8; 32];
        let provider = InMemoryKeyProvider::with_key(custom_key);

        let key = provider.get_device_key().unwrap();
        assert_eq!(*key, custom_key);
    }

    #[test]
    fn test_in_memory_provider_encrypt_decrypt() {
        let provider = InMemoryKeyProvider::new();
        let plaintext = b"Test data for iOS Simulator";

        let ciphertext = provider.encrypt(plaintext).unwrap();
        let decrypted = provider.decrypt(&ciphertext).unwrap();

        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_in_memory_provider_different_nonces() {
        let provider = InMemoryKeyProvider::new();
        let plaintext = b"Same plaintext";

        let ciphertext1 = provider.encrypt(plaintext).unwrap();
        let ciphertext2 = provider.encrypt(plaintext).unwrap();

        // Different nonces should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_in_memory_provider_wrong_key_fails() {
        let provider1 = InMemoryKeyProvider::new();
        let provider2 = InMemoryKeyProvider::new();

        let plaintext = b"Secret message";
        let ciphertext = provider1.encrypt(plaintext).unwrap();

        // Decryption with different key should fail
        assert!(provider2.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_in_memory_provider_corrupted_data_fails() {
        let provider = InMemoryKeyProvider::new();
        let plaintext = b"Test data";

        let mut ciphertext = provider.encrypt(plaintext).unwrap();

        // Corrupt the authentication tag
        if let Some(byte) = ciphertext.last_mut() {
            *byte = byte.wrapping_add(1);
        }

        // Decryption should fail
        assert!(provider.decrypt(&ciphertext).is_err());
    }
}
