//! ML-KEM (Kyber) key encapsulation mechanism (FIPS 203).
//!
//! Implements ML-KEM-768 and ML-KEM-1024 as specified in NIST FIPS 203.
//! ML-KEM provides post-quantum secure key encapsulation, used in the zp protocol
//! in conjunction with X25519 for hybrid classical/post-quantum security.
//!
//! # Security
//!
//! - All shared secrets are wrapped in `Zeroizing<>` to ensure they are securely
//!   cleared from memory when dropped.
//! - Uses `ml-kem` crate (RustCrypto) which provides a FIPS 203 compliant implementation.
//! - Designed to be resistant to attacks using quantum computers.
//!
//! # Example
//!
//! ```
//! use zp_crypto::kex::MlKem768KeyPair;
//! use ::kem::{Encapsulate, Decapsulate};
//!
//! # fn example() -> Result<(), zp_crypto::Error> {
//! // Recipient generates a keypair
//! let recipient = MlKem768KeyPair::generate()?;
//!
//! // Sender encapsulates a shared secret using recipient's public key
//! let (ciphertext, sender_shared) = MlKem768KeyPair::encapsulate(recipient.public_key())?;
//!
//! // Recipient decapsulates to recover the same shared secret
//! let recipient_shared = recipient.decapsulate(&ciphertext)?;
//!
//! // Both parties now have the same 32-byte shared secret
//! assert_eq!(&*sender_shared, &*recipient_shared);
//! # Ok(())
//! # }
//! ```

use crate::{Error, Result};
use kem::{Decapsulate, Encapsulate};
use ml_kem::kem::{DecapsulationKey, EncapsulationKey};
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024, MlKem768};
use zeroize::Zeroizing;

/// ML-KEM-768 key pair (NIST security level 3).
///
/// ML-KEM-768 provides post-quantum security equivalent to AES-192.
/// Used in zp cipher suite ZP_PQC_1 (the default suite).
///
/// Key sizes:
/// - Public key: 1184 bytes
/// - Private key: 2400 bytes
/// - Ciphertext: 1088 bytes
/// - Shared secret: 32 bytes
pub struct MlKem768KeyPair {
    /// Decapsulation key bytes (private key, 2400 bytes), zeroed on drop.
    decapsulation_key_bytes: Zeroizing<[u8; 2400]>,
    /// Encapsulation key bytes (public key, 1184 bytes).
    encapsulation_key_bytes: [u8; 1184],
}

impl MlKem768KeyPair {
    /// Generate a new random ML-KEM-768 keypair using a cryptographically secure RNG.
    ///
    /// # Errors
    ///
    /// This function should not fail under normal circumstances. It returns a `Result`
    /// for consistency with other key generation functions.
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::MlKem768KeyPair;
    ///
    /// let keypair = MlKem768KeyPair::generate().unwrap();
    /// assert_eq!(keypair.public_key().len(), 1184);
    /// ```
    pub fn generate() -> Result<Self> {
        let mut rng = rand::rngs::OsRng;
        let (decapsulation_key, encapsulation_key) = MlKem768::generate(&mut rng);

        // Extract bytes for secure storage
        let dk_bytes_slice = decapsulation_key.as_bytes();
        let ek_bytes_slice = encapsulation_key.as_bytes();

        // Convert hybrid-arrays to regular arrays by copying
        let mut dk_bytes = [0u8; 2400];
        let mut ek_bytes = [0u8; 1184];
        dk_bytes.copy_from_slice(&dk_bytes_slice[..]);
        ek_bytes.copy_from_slice(&ek_bytes_slice[..]);

        Ok(Self {
            decapsulation_key_bytes: Zeroizing::new(dk_bytes),
            encapsulation_key_bytes: ek_bytes,
        })
    }

    /// Get the public key (encapsulation key) as bytes.
    ///
    /// The public key is 1184 bytes and can be safely shared with peers.
    /// It is used by senders to encapsulate shared secrets.
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::MlKem768KeyPair;
    ///
    /// let keypair = MlKem768KeyPair::generate().unwrap();
    /// let public_bytes = keypair.public_key();
    /// assert_eq!(public_bytes.len(), 1184);
    /// ```
    pub fn public_key(&self) -> &[u8] {
        &self.encapsulation_key_bytes
    }

    /// Encapsulate: Generate a shared secret and ciphertext for the recipient.
    ///
    /// This is a static method that doesn't require a private key. Anyone with the
    /// recipient's public key can encapsulate a shared secret to them.
    ///
    /// # Arguments
    ///
    /// * `recipient_public` - The recipient's ML-KEM-768 public key (1184 bytes)
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - `ciphertext` (1088 bytes) - Send this to the recipient
    /// - `shared_secret` (32 bytes, Zeroizing-wrapped) - Your copy of the shared secret
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidLength` if `recipient_public` is not exactly 1184 bytes.
    /// Returns `Error::KeyExchange` if encapsulation fails (malformed public key).
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::MlKem768KeyPair;
    ///
    /// let recipient = MlKem768KeyPair::generate().unwrap();
    /// let (ct, secret) = MlKem768KeyPair::encapsulate(recipient.public_key()).unwrap();
    /// assert_eq!(ct.len(), 1088);
    /// assert_eq!(secret.len(), 32);
    /// ```
    pub fn encapsulate(recipient_public: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
        // Validate public key length
        if recipient_public.len() != 1184 {
            return Err(Error::InvalidLength {
                expected: 1184,
                actual: recipient_public.len(),
            });
        }

        // Parse the public key (encapsulation key)
        let ek_bytes: &[u8; 1184] = recipient_public
            .try_into()
            .map_err(|_| Error::KeyExchange("Failed to parse public key".into()))?;

        // Reconstruct encapsulation key from bytes
        let encapsulation_key =
            EncapsulationKey::<ml_kem::MlKem768Params>::from_bytes(&(*ek_bytes).into());

        // Encapsulate a shared secret
        let mut rng = rand::rngs::OsRng;
        let (ciphertext, shared_secret) = encapsulation_key
            .encapsulate(&mut rng)
            .map_err(|e| Error::KeyExchange(format!("Encapsulation failed: {:?}", e)))?;

        // Convert to owned types with Zeroizing wrapper for secret
        let mut ct_vec = vec![0u8; 1088];
        ct_vec.copy_from_slice(&ciphertext[..]);

        let mut ss_array = [0u8; 32];
        ss_array.copy_from_slice(&shared_secret[..]);

        Ok((ct_vec, Zeroizing::new(ss_array)))
    }

    /// Decapsulate: Recover the shared secret from a ciphertext.
    ///
    /// Uses this keypair's private key (decapsulation key) to extract the shared secret
    /// that was encapsulated in the ciphertext.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ML-KEM-768 ciphertext (1088 bytes)
    ///
    /// # Returns
    ///
    /// The 32-byte shared secret wrapped in `Zeroizing`.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidLength` if `ciphertext` is not exactly 1088 bytes.
    /// Returns `Error::KeyExchange` if decapsulation fails (malformed ciphertext).
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::MlKem768KeyPair;
    ///
    /// let recipient = MlKem768KeyPair::generate().unwrap();
    /// let (ct, sender_secret) = MlKem768KeyPair::encapsulate(recipient.public_key()).unwrap();
    ///
    /// let recipient_secret = recipient.decapsulate(&ct).unwrap();
    /// assert_eq!(&*sender_secret, &*recipient_secret);
    /// ```
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        // Validate ciphertext length
        if ciphertext.len() != 1088 {
            return Err(Error::InvalidLength {
                expected: 1088,
                actual: ciphertext.len(),
            });
        }

        // Parse the ciphertext
        let ct_bytes: &[u8; 1088] = ciphertext
            .try_into()
            .map_err(|_| Error::KeyExchange("Failed to parse ciphertext".into()))?;

        // Reconstruct decapsulation key from stored bytes
        let decapsulation_key = DecapsulationKey::<ml_kem::MlKem768Params>::from_bytes(
            &(*self.decapsulation_key_bytes).into(),
        );

        // Decapsulate to recover shared secret
        let shared_secret = decapsulation_key
            .decapsulate(&(*ct_bytes).into())
            .map_err(|e| Error::KeyExchange(format!("Decapsulation failed: {:?}", e)))?;

        let mut ss_array = [0u8; 32];
        ss_array.copy_from_slice(&shared_secret[..]);
        Ok(Zeroizing::new(ss_array))
    }
}

/// ML-KEM-1024 key pair (NIST security level 5).
///
/// ML-KEM-1024 provides post-quantum security equivalent to AES-256.
/// Used in zp cipher suite ZP_PQC_2 (ZP_HYBRID_2).
///
/// Key sizes:
/// - Public key: 1568 bytes
/// - Private key: 3168 bytes
/// - Ciphertext: 1568 bytes
/// - Shared secret: 32 bytes
pub struct MlKem1024KeyPair {
    /// Decapsulation key bytes (private key, 3168 bytes), zeroed on drop.
    decapsulation_key_bytes: Zeroizing<[u8; 3168]>,
    /// Encapsulation key bytes (public key, 1568 bytes).
    encapsulation_key_bytes: [u8; 1568],
}

impl MlKem1024KeyPair {
    /// Generate a new random ML-KEM-1024 keypair using a cryptographically secure RNG.
    ///
    /// # Errors
    ///
    /// This function should not fail under normal circumstances. It returns a `Result`
    /// for consistency with other key generation functions.
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::MlKem1024KeyPair;
    ///
    /// let keypair = MlKem1024KeyPair::generate().unwrap();
    /// assert_eq!(keypair.public_key().len(), 1568);
    /// ```
    pub fn generate() -> Result<Self> {
        let mut rng = rand::rngs::OsRng;
        let (decapsulation_key, encapsulation_key) = MlKem1024::generate(&mut rng);

        // Extract bytes for secure storage
        let dk_bytes_slice = decapsulation_key.as_bytes();
        let ek_bytes_slice = encapsulation_key.as_bytes();

        // Convert hybrid-arrays to regular arrays by copying
        let mut dk_bytes = [0u8; 3168];
        let mut ek_bytes = [0u8; 1568];
        dk_bytes.copy_from_slice(&dk_bytes_slice[..]);
        ek_bytes.copy_from_slice(&ek_bytes_slice[..]);

        Ok(Self {
            decapsulation_key_bytes: Zeroizing::new(dk_bytes),
            encapsulation_key_bytes: ek_bytes,
        })
    }

    /// Get the public key (encapsulation key) as bytes.
    ///
    /// The public key is 1568 bytes and can be safely shared with peers.
    /// It is used by senders to encapsulate shared secrets.
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::MlKem1024KeyPair;
    ///
    /// let keypair = MlKem1024KeyPair::generate().unwrap();
    /// let public_bytes = keypair.public_key();
    /// assert_eq!(public_bytes.len(), 1568);
    /// ```
    pub fn public_key(&self) -> &[u8] {
        &self.encapsulation_key_bytes
    }

    /// Encapsulate: Generate a shared secret and ciphertext for the recipient.
    ///
    /// This is a static method that doesn't require a private key. Anyone with the
    /// recipient's public key can encapsulate a shared secret to them.
    ///
    /// # Arguments
    ///
    /// * `recipient_public` - The recipient's ML-KEM-1024 public key (1568 bytes)
    ///
    /// # Returns
    ///
    /// A tuple of:
    /// - `ciphertext` (1568 bytes) - Send this to the recipient
    /// - `shared_secret` (32 bytes, Zeroizing-wrapped) - Your copy of the shared secret
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidLength` if `recipient_public` is not exactly 1568 bytes.
    /// Returns `Error::KeyExchange` if encapsulation fails (malformed public key).
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::MlKem1024KeyPair;
    ///
    /// let recipient = MlKem1024KeyPair::generate().unwrap();
    /// let (ct, secret) = MlKem1024KeyPair::encapsulate(recipient.public_key()).unwrap();
    /// assert_eq!(ct.len(), 1568);
    /// assert_eq!(secret.len(), 32);
    /// ```
    pub fn encapsulate(recipient_public: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
        // Validate public key length
        if recipient_public.len() != 1568 {
            return Err(Error::InvalidLength {
                expected: 1568,
                actual: recipient_public.len(),
            });
        }

        // Parse the public key (encapsulation key)
        let ek_bytes: &[u8; 1568] = recipient_public
            .try_into()
            .map_err(|_| Error::KeyExchange("Failed to parse public key".into()))?;

        // Reconstruct encapsulation key from bytes
        let encapsulation_key =
            EncapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(&(*ek_bytes).into());

        // Encapsulate a shared secret
        let mut rng = rand::rngs::OsRng;
        let (ciphertext, shared_secret) = encapsulation_key
            .encapsulate(&mut rng)
            .map_err(|e| Error::KeyExchange(format!("Encapsulation failed: {:?}", e)))?;

        // Convert to owned types with Zeroizing wrapper for secret
        let mut ct_vec = vec![0u8; 1568];
        ct_vec.copy_from_slice(&ciphertext[..]);

        let mut ss_array = [0u8; 32];
        ss_array.copy_from_slice(&shared_secret[..]);

        Ok((ct_vec, Zeroizing::new(ss_array)))
    }

    /// Decapsulate: Recover the shared secret from a ciphertext.
    ///
    /// Uses this keypair's private key (decapsulation key) to extract the shared secret
    /// that was encapsulated in the ciphertext.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ML-KEM-1024 ciphertext (1568 bytes)
    ///
    /// # Returns
    ///
    /// The 32-byte shared secret wrapped in `Zeroizing`.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidLength` if `ciphertext` is not exactly 1568 bytes.
    /// Returns `Error::KeyExchange` if decapsulation fails (malformed ciphertext).
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::MlKem1024KeyPair;
    ///
    /// let recipient = MlKem1024KeyPair::generate().unwrap();
    /// let (ct, sender_secret) = MlKem1024KeyPair::encapsulate(recipient.public_key()).unwrap();
    ///
    /// let recipient_secret = recipient.decapsulate(&ct).unwrap();
    /// assert_eq!(&*sender_secret, &*recipient_secret);
    /// ```
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        // Validate ciphertext length
        if ciphertext.len() != 1568 {
            return Err(Error::InvalidLength {
                expected: 1568,
                actual: ciphertext.len(),
            });
        }

        // Parse the ciphertext
        let ct_bytes: &[u8; 1568] = ciphertext
            .try_into()
            .map_err(|_| Error::KeyExchange("Failed to parse ciphertext".into()))?;

        // Reconstruct decapsulation key from stored bytes
        let decapsulation_key = DecapsulationKey::<ml_kem::MlKem1024Params>::from_bytes(
            &(*self.decapsulation_key_bytes).into(),
        );

        // Decapsulate to recover shared secret
        let shared_secret = decapsulation_key
            .decapsulate(&(*ct_bytes).into())
            .map_err(|e| Error::KeyExchange(format!("Decapsulation failed: {:?}", e)))?;

        let mut ss_array = [0u8; 32];
        ss_array.copy_from_slice(&shared_secret[..]);
        Ok(Zeroizing::new(ss_array))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that ML-KEM-768 produces correct key/ciphertext sizes.
    ///
    /// Per TEST_VECTORS.md §1.2 verification points.
    #[test]
    fn test_ml_kem_768_sizes() {
        let keypair = MlKem768KeyPair::generate().unwrap();

        // Public key must be exactly 1184 bytes
        assert_eq!(keypair.public_key().len(), 1184);

        // Encapsulate and check ciphertext/shared secret sizes
        let (ciphertext, shared_secret) =
            MlKem768KeyPair::encapsulate(keypair.public_key()).unwrap();

        // Ciphertext must be exactly 1088 bytes
        assert_eq!(ciphertext.len(), 1088);

        // Shared secret must be exactly 32 bytes
        assert_eq!(shared_secret.len(), 32);
    }

    /// Test ML-KEM-768 encapsulate/decapsulate roundtrip.
    ///
    /// Verifies that decapsulation recovers the same shared secret that was
    /// generated during encapsulation.
    #[test]
    fn test_ml_kem_768_roundtrip() {
        // Recipient generates a keypair
        let recipient = MlKem768KeyPair::generate().unwrap();

        // Sender encapsulates a shared secret
        let (ciphertext, sender_secret) =
            MlKem768KeyPair::encapsulate(recipient.public_key()).unwrap();

        // Recipient decapsulates to recover the shared secret
        let recipient_secret = recipient.decapsulate(&ciphertext).unwrap();

        // Both should have the same 32-byte shared secret
        assert_eq!(&*sender_secret, &*recipient_secret);
        assert_eq!(sender_secret.len(), 32);
    }

    /// Test that ML-KEM-768 generates unique shared secrets.
    #[test]
    fn test_ml_kem_768_unique_secrets() {
        let recipient = MlKem768KeyPair::generate().unwrap();

        // Encapsulate twice with the same public key
        let (ct1, secret1) = MlKem768KeyPair::encapsulate(recipient.public_key()).unwrap();
        let (ct2, secret2) = MlKem768KeyPair::encapsulate(recipient.public_key()).unwrap();

        // Ciphertexts should be different (randomized encapsulation)
        assert_ne!(ct1, ct2);

        // Shared secrets should be different (independent random values)
        assert_ne!(&*secret1, &*secret2);
    }

    /// Test that ML-KEM-768 generates unique keypairs.
    #[test]
    fn test_ml_kem_768_unique_keypairs() {
        let kp1 = MlKem768KeyPair::generate().unwrap();
        let kp2 = MlKem768KeyPair::generate().unwrap();

        // Public keys should be different
        assert_ne!(kp1.public_key(), kp2.public_key());
    }

    /// Test that ML-KEM-768 rejects invalid public key lengths.
    #[test]
    fn test_ml_kem_768_invalid_public_key_length() {
        // Too short
        let short_key = vec![0u8; 1183];
        let result = MlKem768KeyPair::encapsulate(&short_key);
        assert!(result.is_err());
        if let Err(Error::InvalidLength { expected, actual }) = result {
            assert_eq!(expected, 1184);
            assert_eq!(actual, 1183);
        } else {
            panic!("Expected InvalidLength error");
        }

        // Too long
        let long_key = vec![0u8; 1185];
        let result = MlKem768KeyPair::encapsulate(&long_key);
        assert!(result.is_err());
    }

    /// Test that ML-KEM-768 rejects invalid ciphertext lengths.
    #[test]
    fn test_ml_kem_768_invalid_ciphertext_length() {
        let keypair = MlKem768KeyPair::generate().unwrap();

        // Too short
        let short_ct = vec![0u8; 1087];
        let result = keypair.decapsulate(&short_ct);
        assert!(result.is_err());
        if let Err(Error::InvalidLength { expected, actual }) = result {
            assert_eq!(expected, 1088);
            assert_eq!(actual, 1087);
        } else {
            panic!("Expected InvalidLength error");
        }

        // Too long
        let long_ct = vec![0u8; 1089];
        let result = keypair.decapsulate(&long_ct);
        assert!(result.is_err());
    }

    /// Test that shared secrets are not all zeros.
    #[test]
    fn test_ml_kem_768_secret_not_zero() {
        let recipient = MlKem768KeyPair::generate().unwrap();
        let (_ct, secret) = MlKem768KeyPair::encapsulate(recipient.public_key()).unwrap();

        // Shared secret should not be all zeros (astronomically unlikely)
        assert_ne!(&*secret, &[0u8; 32]);
    }

    /// Test that public keys are not all zeros.
    #[test]
    fn test_ml_kem_768_pubkey_not_zero() {
        let keypair = MlKem768KeyPair::generate().unwrap();

        // Public key should not be all zeros (astronomically unlikely)
        assert_ne!(keypair.public_key(), &[0u8; 1184]);
    }

    /// Test that ML-KEM-1024 produces correct key/ciphertext sizes.
    ///
    /// Per TEST_VECTORS.md §1.3 verification points.
    #[test]
    fn test_ml_kem_1024_sizes() {
        let keypair = MlKem1024KeyPair::generate().unwrap();

        // Public key must be exactly 1568 bytes
        assert_eq!(keypair.public_key().len(), 1568);

        // Encapsulate and check ciphertext/shared secret sizes
        let (ciphertext, shared_secret) =
            MlKem1024KeyPair::encapsulate(keypair.public_key()).unwrap();

        // Ciphertext must be exactly 1568 bytes
        assert_eq!(ciphertext.len(), 1568);

        // Shared secret must be exactly 32 bytes
        assert_eq!(shared_secret.len(), 32);
    }

    /// Test ML-KEM-1024 encapsulate/decapsulate roundtrip.
    ///
    /// Verifies that decapsulation recovers the same shared secret that was
    /// generated during encapsulation.
    #[test]
    fn test_ml_kem_1024_roundtrip() {
        // Recipient generates a keypair
        let recipient = MlKem1024KeyPair::generate().unwrap();

        // Sender encapsulates a shared secret
        let (ciphertext, sender_secret) =
            MlKem1024KeyPair::encapsulate(recipient.public_key()).unwrap();

        // Recipient decapsulates to recover the shared secret
        let recipient_secret = recipient.decapsulate(&ciphertext).unwrap();

        // Both should have the same 32-byte shared secret
        assert_eq!(&*sender_secret, &*recipient_secret);
        assert_eq!(sender_secret.len(), 32);
    }

    /// Test that ML-KEM-1024 generates unique shared secrets.
    #[test]
    fn test_ml_kem_1024_unique_secrets() {
        let recipient = MlKem1024KeyPair::generate().unwrap();

        // Encapsulate twice with the same public key
        let (ct1, secret1) = MlKem1024KeyPair::encapsulate(recipient.public_key()).unwrap();
        let (ct2, secret2) = MlKem1024KeyPair::encapsulate(recipient.public_key()).unwrap();

        // Ciphertexts should be different (randomized encapsulation)
        assert_ne!(ct1, ct2);

        // Shared secrets should be different (independent random values)
        assert_ne!(&*secret1, &*secret2);
    }

    /// Test that ML-KEM-1024 generates unique keypairs.
    #[test]
    fn test_ml_kem_1024_unique_keypairs() {
        let kp1 = MlKem1024KeyPair::generate().unwrap();
        let kp2 = MlKem1024KeyPair::generate().unwrap();

        // Public keys should be different
        assert_ne!(kp1.public_key(), kp2.public_key());
    }

    /// Test that ML-KEM-1024 rejects invalid public key lengths.
    #[test]
    fn test_ml_kem_1024_invalid_public_key_length() {
        // Too short
        let short_key = vec![0u8; 1567];
        let result = MlKem1024KeyPair::encapsulate(&short_key);
        assert!(result.is_err());
        if let Err(Error::InvalidLength { expected, actual }) = result {
            assert_eq!(expected, 1568);
            assert_eq!(actual, 1567);
        } else {
            panic!("Expected InvalidLength error");
        }

        // Too long
        let long_key = vec![0u8; 1569];
        let result = MlKem1024KeyPair::encapsulate(&long_key);
        assert!(result.is_err());
    }

    /// Test that ML-KEM-1024 rejects invalid ciphertext lengths.
    #[test]
    fn test_ml_kem_1024_invalid_ciphertext_length() {
        let keypair = MlKem1024KeyPair::generate().unwrap();

        // Too short
        let short_ct = vec![0u8; 1567];
        let result = keypair.decapsulate(&short_ct);
        assert!(result.is_err());
        if let Err(Error::InvalidLength { expected, actual }) = result {
            assert_eq!(expected, 1568);
            assert_eq!(actual, 1567);
        } else {
            panic!("Expected InvalidLength error");
        }

        // Too long
        let long_ct = vec![0u8; 1569];
        let result = keypair.decapsulate(&long_ct);
        assert!(result.is_err());
    }

    /// Test that shared secrets are not all zeros.
    #[test]
    fn test_ml_kem_1024_secret_not_zero() {
        let recipient = MlKem1024KeyPair::generate().unwrap();
        let (_ct, secret) = MlKem1024KeyPair::encapsulate(recipient.public_key()).unwrap();

        // Shared secret should not be all zeros (astronomically unlikely)
        assert_ne!(&*secret, &[0u8; 32]);
    }

    /// Test that public keys are not all zeros.
    #[test]
    fn test_ml_kem_1024_pubkey_not_zero() {
        let keypair = MlKem1024KeyPair::generate().unwrap();

        // Public key should not be all zeros (astronomically unlikely)
        assert_ne!(keypair.public_key(), &[0u8; 1568]);
    }
}
