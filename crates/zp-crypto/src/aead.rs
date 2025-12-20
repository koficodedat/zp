//! AEAD (Authenticated Encryption with Associated Data) implementations.
//!
//! Implements:
//! - ChaCha20-Poly1305 (RFC 8439) for ZP_PQC_1, ZP_CLASSICAL_1
//! - AES-256-GCM (NIST SP 800-38D) for ZP_PQC_2, ZP_CLASSICAL_2
//!
//! All operations are verified against TEST_VECTORS.md §4.

use crate::{Error, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroizing;

/// Construct AEAD nonce from counter per spec §6.5.1.
///
/// Both ChaCha20-Poly1305 and AES-256-GCM require 12-byte nonces.
/// The spec mandates:
/// - `nonce[0:4] = 0x00000000` (4 bytes of zeros, fixed)
/// - `nonce[4:12] = counter` (8 bytes, little-endian)
///
/// # Arguments
/// * `counter` - 8-byte counter value
///
/// # Returns
/// 12-byte nonce suitable for AEAD encryption.
///
/// # Example
/// ```
/// use zp_crypto::aead::construct_nonce;
///
/// let nonce = construct_nonce(0x4746454443424140);
/// assert_eq!(&nonce[0..4], &[0, 0, 0, 0]);
/// assert_eq!(&nonce[4..12], &[0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]);
/// ```
pub fn construct_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    // nonce[0:4] already zero
    nonce[4..12].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// Encrypt with ChaCha20-Poly1305 per RFC 8439.
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce (must be unique per key)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (not encrypted, but authenticated)
///
/// # Returns
/// Ciphertext with appended 16-byte authentication tag.
///
/// # Security
/// Callers MUST ensure `key` parameter is stored in `Zeroizing` wrapper
/// to prevent key material from remaining in memory after use.
///
/// # Example
/// ```
/// use zp_crypto::aead::chacha20poly1305_encrypt;
///
/// let key = [0x42; 32];
/// let nonce = [0x01; 12];
/// let plaintext = b"Hello, world!";
/// let aad = b"metadata";
///
/// let ciphertext_with_tag = chacha20poly1305_encrypt(&key, &nonce, plaintext, aad).unwrap();
/// assert!(ciphertext_with_tag.len() >= plaintext.len() + 16);
/// ```
pub fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    // Create cipher from key
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    // Create payload with plaintext and AAD
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    // Encrypt and return ciphertext || tag
    cipher
        .encrypt(Nonce::from_slice(nonce), payload)
        .map_err(|_| Error::Encryption("ChaCha20-Poly1305 encryption failed".into()))
}

/// Decrypt with ChaCha20-Poly1305 per RFC 8439.
///
/// # Arguments
/// * `key` - 32-byte decryption key
/// * `nonce` - 12-byte nonce (same as used for encryption)
/// * `ciphertext_and_tag` - Ciphertext with appended 16-byte tag
/// * `aad` - Additional authenticated data (must match encryption)
///
/// # Returns
/// Plaintext if authentication succeeds, wrapped in `Zeroizing`.
///
/// # Security
/// Callers MUST ensure `key` parameter is stored in `Zeroizing` wrapper
/// to prevent key material from remaining in memory after use.
///
/// # Errors
/// Returns `Error::Decryption` if tag verification fails.
pub fn chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    // Create cipher from key
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    // Create payload with ciphertext+tag and AAD
    let payload = Payload {
        msg: ciphertext_and_tag,
        aad,
    };

    // Decrypt and verify tag
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), payload)
        .map_err(|_| Error::Decryption("ChaCha20-Poly1305 authentication failed".into()))?;

    // Wrap in Zeroizing for automatic secret cleanup
    Ok(Zeroizing::new(plaintext))
}

/// Encrypt with AES-256-GCM per NIST SP 800-38D.
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 12-byte nonce (must be unique per key)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (not encrypted, but authenticated)
///
/// # Returns
/// Ciphertext with appended 16-byte authentication tag.
///
/// # Security
/// Callers MUST ensure `key` parameter is stored in `Zeroizing` wrapper
/// to prevent key material from remaining in memory after use.
///
/// # Example
/// ```
/// use zp_crypto::aead::aes256gcm_encrypt;
///
/// let key = [0x42; 32];
/// let nonce = [0x01; 12];
/// let plaintext = b"Hello, world!";
/// let aad = b"metadata";
///
/// let ciphertext_with_tag = aes256gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
/// assert!(ciphertext_with_tag.len() >= plaintext.len() + 16);
/// ```
pub fn aes256gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};

    // Create cipher from key
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::Encryption("Invalid AES-256-GCM key length".into()))?;

    // Create payload with plaintext and AAD
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    // Encrypt and return ciphertext || tag
    cipher
        .encrypt(Nonce::from_slice(nonce), payload)
        .map_err(|_| Error::Encryption("AES-256-GCM encryption failed".into()))
}

/// Decrypt with AES-256-GCM per NIST SP 800-38D.
///
/// # Arguments
/// * `key` - 32-byte decryption key
/// * `nonce` - 12-byte nonce (same as used for encryption)
/// * `ciphertext_and_tag` - Ciphertext with appended 16-byte tag
/// * `aad` - Additional authenticated data (must match encryption)
///
/// # Returns
/// Plaintext if authentication succeeds, wrapped in `Zeroizing`.
///
/// # Security
/// Callers MUST ensure `key` parameter is stored in `Zeroizing` wrapper
/// to prevent key material from remaining in memory after use.
///
/// # Errors
/// Returns `Error::Decryption` if tag verification fails.
pub fn aes256gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};

    // Create cipher from key
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::Decryption("Invalid AES-256-GCM key length".into()))?;

    // Create payload with ciphertext+tag and AAD
    let payload = Payload {
        msg: ciphertext_and_tag,
        aad,
    };

    // Decrypt and verify tag
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), payload)
        .map_err(|_| Error::Decryption("AES-256-GCM authentication failed".into()))?;

    // Wrap in Zeroizing for automatic secret cleanup
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test nonce construction per spec §6.5.1
    #[test]
    fn test_construct_nonce() {
        // Counter from RFC 8439 test vector
        let counter = 0x4746454443424140u64;
        let nonce = construct_nonce(counter);

        // First 4 bytes must be zeros
        assert_eq!(&nonce[0..4], &[0, 0, 0, 0]);

        // Last 8 bytes are counter in little-endian
        assert_eq!(
            &nonce[4..12],
            &[0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]
        );
    }

    /// Test nonce construction with zero counter
    #[test]
    fn test_construct_nonce_zero() {
        let nonce = construct_nonce(0);
        assert_eq!(nonce, [0u8; 12]);
    }

    /// Test nonce construction with max counter
    #[test]
    fn test_construct_nonce_max() {
        let nonce = construct_nonce(u64::MAX);
        assert_eq!(&nonce[0..4], &[0, 0, 0, 0]);
        assert_eq!(&nonce[4..12], &[0xFF; 8]);
    }

    /// Test RFC 8439 §2.8.2 test vector from TEST_VECTORS.md §4.1
    #[test]
    fn test_chacha20poly1305_rfc8439() {
        let key: [u8; 32] =
            hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap()
                .try_into()
                .unwrap();

        let nonce: [u8; 12] = hex::decode("070000004041424344454647")
            .unwrap()
            .try_into()
            .unwrap();

        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();

        let plaintext = hex::decode(
            "4c616469657320616e642047656e746c656d656e206f662074686520636c6173\
             73206f66202739393a204966204920636f756c64206f6666657220796f75206f\
             6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73\
             637265656e20776f756c642062652069742e",
        )
        .unwrap();

        let expected_ciphertext = hex::decode(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
        )
        .unwrap();

        let expected_tag = hex::decode("1ae10b594f09e26a7e902ecbd0600691").unwrap();

        // Encrypt
        let ciphertext_with_tag = chacha20poly1305_encrypt(&key, &nonce, &plaintext, &aad).unwrap();

        // Verify ciphertext
        assert_eq!(
            &ciphertext_with_tag[..expected_ciphertext.len()],
            &expected_ciphertext[..]
        );

        // Verify tag
        assert_eq!(
            &ciphertext_with_tag[expected_ciphertext.len()..],
            &expected_tag[..]
        );

        // Decrypt
        let decrypted = chacha20poly1305_decrypt(&key, &nonce, &ciphertext_with_tag, &aad).unwrap();

        // Verify plaintext
        assert_eq!(&*decrypted, &plaintext);
    }

    /// Test encryption/decryption roundtrip
    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"The quick brown fox jumps over the lazy dog";
        let aad = b"packet_metadata";

        let ciphertext = chacha20poly1305_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = chacha20poly1305_decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(&*decrypted, plaintext);
    }

    /// Test decryption with wrong key fails
    #[test]
    fn test_chacha20poly1305_wrong_key() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret message";
        let aad = b"";

        let ciphertext = chacha20poly1305_encrypt(&key1, &nonce, plaintext, aad).unwrap();
        let result = chacha20poly1305_decrypt(&key2, &nonce, &ciphertext, aad);

        assert!(result.is_err());
    }

    /// Test decryption with wrong nonce fails
    #[test]
    fn test_chacha20poly1305_wrong_nonce() {
        let key = [0x42u8; 32];
        let nonce1 = [0x01u8; 12];
        let nonce2 = [0x02u8; 12];
        let plaintext = b"secret message";
        let aad = b"";

        let ciphertext = chacha20poly1305_encrypt(&key, &nonce1, plaintext, aad).unwrap();
        let result = chacha20poly1305_decrypt(&key, &nonce2, &ciphertext, aad);

        assert!(result.is_err());
    }

    /// Test decryption with wrong AAD fails
    #[test]
    fn test_chacha20poly1305_wrong_aad() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret message";
        let aad1 = b"correct_metadata";
        let aad2 = b"wrong_metadata";

        let ciphertext = chacha20poly1305_encrypt(&key, &nonce, plaintext, aad1).unwrap();
        let result = chacha20poly1305_decrypt(&key, &nonce, &ciphertext, aad2);

        assert!(result.is_err());
    }

    /// Test decryption with corrupted ciphertext fails
    #[test]
    fn test_chacha20poly1305_corrupted_ciphertext() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret message";
        let aad = b"";

        let mut ciphertext = chacha20poly1305_encrypt(&key, &nonce, plaintext, aad).unwrap();

        // Corrupt one byte
        ciphertext[5] ^= 0xFF;

        let result = chacha20poly1305_decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    /// Test empty plaintext
    #[test]
    fn test_chacha20poly1305_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"";
        let aad = b"metadata";

        let ciphertext = chacha20poly1305_encrypt(&key, &nonce, plaintext, aad).unwrap();

        // Should only contain tag (16 bytes)
        assert_eq!(ciphertext.len(), 16);

        let decrypted = chacha20poly1305_decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    /// Test AES-256-GCM encryption/decryption roundtrip
    #[test]
    fn test_aes256gcm_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"The quick brown fox jumps over the lazy dog";
        let aad = b"packet_metadata";

        let ciphertext = aes256gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = aes256gcm_decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(&*decrypted, plaintext);
    }

    /// Test AES-256-GCM decryption with wrong key fails
    #[test]
    fn test_aes256gcm_wrong_key() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret message";
        let aad = b"";

        let ciphertext = aes256gcm_encrypt(&key1, &nonce, plaintext, aad).unwrap();
        let result = aes256gcm_decrypt(&key2, &nonce, &ciphertext, aad);

        assert!(result.is_err());
    }

    /// Test AES-256-GCM decryption with wrong nonce fails
    #[test]
    fn test_aes256gcm_wrong_nonce() {
        let key = [0x42u8; 32];
        let nonce1 = [0x01u8; 12];
        let nonce2 = [0x02u8; 12];
        let plaintext = b"secret message";
        let aad = b"";

        let ciphertext = aes256gcm_encrypt(&key, &nonce1, plaintext, aad).unwrap();
        let result = aes256gcm_decrypt(&key, &nonce2, &ciphertext, aad);

        assert!(result.is_err());
    }

    /// Test AES-256-GCM decryption with wrong AAD fails
    #[test]
    fn test_aes256gcm_wrong_aad() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret message";
        let aad1 = b"correct_metadata";
        let aad2 = b"wrong_metadata";

        let ciphertext = aes256gcm_encrypt(&key, &nonce, plaintext, aad1).unwrap();
        let result = aes256gcm_decrypt(&key, &nonce, &ciphertext, aad2);

        assert!(result.is_err());
    }

    /// Test AES-256-GCM decryption with corrupted ciphertext fails
    #[test]
    fn test_aes256gcm_corrupted_ciphertext() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"secret message";
        let aad = b"";

        let mut ciphertext = aes256gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();

        // Corrupt one byte
        ciphertext[5] ^= 0xFF;

        let result = aes256gcm_decrypt(&key, &nonce, &ciphertext, aad);
        assert!(result.is_err());
    }

    /// Test AES-256-GCM with empty plaintext
    #[test]
    fn test_aes256gcm_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let plaintext = b"";
        let aad = b"metadata";

        let ciphertext = aes256gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();

        // Should only contain tag (16 bytes)
        assert_eq!(ciphertext.len(), 16);

        let decrypted = aes256gcm_decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }
}
