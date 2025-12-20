//! ECDH-P256 key exchange (for ZP_CLASSICAL_2 cipher suite).
//!
//! Implements ECDH using the NIST P-256 (secp256r1) elliptic curve as specified
//! in NIST SP 800-56A. P-256 is used in the zp protocol only for ZP_CLASSICAL_2
//! cipher suite to provide FIPS 140-3 compliance.
//!
//! # Security
//!
//! - All private keys and shared secrets are wrapped in `Zeroizing<>` to ensure
//!   they are securely cleared from memory when dropped.
//! - Uses `p256` crate from RustCrypto which provides NIST SP 800-56A compliant
//!   implementation with public key validation.
//! - Public keys are encoded in uncompressed form (0x04 || x || y) per SEC 1.
//!
//! # Example
//!
//! ```
//! use zp_crypto::kex::EcdhP256KeyPair;
//!
//! # fn example() -> Result<(), zp_crypto::Error> {
//! // Alice generates a keypair
//! let alice = EcdhP256KeyPair::generate()?;
//!
//! // Bob generates a keypair
//! let bob = EcdhP256KeyPair::generate()?;
//!
//! // Both perform key exchange
//! let alice_shared = alice.exchange(bob.public_key())?;
//! let bob_shared = bob.exchange(alice.public_key())?;
//!
//! // They arrive at the same shared secret
//! assert_eq!(*alice_shared, *bob_shared);
//! # Ok(())
//! # }
//! ```

use crate::{Error, Result};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey, SecretKey};
use zeroize::Zeroizing;

/// ECDH-P256 key pair for elliptic curve Diffie-Hellman key exchange.
///
/// This structure holds a private key and its corresponding public key.
/// The private key is automatically zeroed when dropped.
///
/// Public keys are encoded in uncompressed form: 0x04 || x || y (65 bytes total).
pub struct EcdhP256KeyPair {
    /// Secret key (32 bytes), zeroed on drop.
    secret_key: SecretKey,
    /// Public key in uncompressed form (65 bytes: 0x04 || x || y), cached.
    public_key_bytes: Vec<u8>,
}

impl EcdhP256KeyPair {
    /// Generate a new random P-256 keypair using a cryptographically secure RNG.
    ///
    /// # Errors
    ///
    /// This function should not fail under normal circumstances. It returns a `Result`
    /// for consistency with other key generation functions.
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::EcdhP256KeyPair;
    ///
    /// let keypair = EcdhP256KeyPair::generate().unwrap();
    /// assert_eq!(keypair.public_key().len(), 65); // uncompressed format
    /// assert_eq!(keypair.public_key()[0], 0x04); // uncompressed marker
    /// ```
    pub fn generate() -> Result<Self> {
        let secret_key = SecretKey::random(&mut rand::rngs::OsRng);
        let public_key = secret_key.public_key();
        let public_key_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();

        Ok(Self {
            secret_key,
            public_key_bytes,
        })
    }

    /// Create a keypair from an existing 32-byte private key.
    ///
    /// This is useful for testing with known test vectors or for key restoration.
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is invalid or not on the P-256 curve.
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::EcdhP256KeyPair;
    ///
    /// let private_key = [0x42; 32];
    /// let keypair = EcdhP256KeyPair::from_private(&private_key).unwrap();
    /// assert_eq!(keypair.public_key().len(), 65);
    /// ```
    pub fn from_private(private_key: &[u8]) -> Result<Self> {
        if private_key.len() != 32 {
            return Err(Error::InvalidKeyLength(format!(
                "P-256 private key must be 32 bytes, got {}",
                private_key.len()
            )));
        }

        let secret_key = SecretKey::from_be_bytes(private_key)
            .map_err(|_| Error::InvalidPrivateKey("Invalid P-256 private key".into()))?;

        let public_key = secret_key.public_key();
        let public_key_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();

        Ok(Self {
            secret_key,
            public_key_bytes,
        })
    }

    /// Get the public key in uncompressed form (65 bytes: 0x04 || x || y).
    ///
    /// The public key can be safely shared with peers and is used to compute
    /// the shared secret during key exchange.
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::EcdhP256KeyPair;
    ///
    /// let keypair = EcdhP256KeyPair::generate().unwrap();
    /// let public_bytes = keypair.public_key();
    /// assert_eq!(public_bytes.len(), 65);
    /// assert_eq!(public_bytes[0], 0x04); // uncompressed format marker
    /// ```
    pub fn public_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    /// Perform P-256 ECDH key exchange with a peer's public key.
    ///
    /// Computes the shared secret using this keypair's private key and the peer's
    /// public key. The shared secret is 32 bytes (the x-coordinate of the result point)
    /// and is wrapped in `Zeroizing` to ensure it is securely cleared from memory.
    ///
    /// The peer's public key must be in uncompressed form (65 bytes: 0x04 || x || y).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The peer's public key has invalid length
    /// - The peer's public key is not on the P-256 curve
    /// - The ECDH operation fails
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::EcdhP256KeyPair;
    ///
    /// let alice = EcdhP256KeyPair::generate().unwrap();
    /// let bob = EcdhP256KeyPair::generate().unwrap();
    ///
    /// let shared_secret = alice.exchange(bob.public_key()).unwrap();
    /// assert_eq!(shared_secret.len(), 32);
    /// ```
    pub fn exchange(&self, peer_public: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        // Validate peer public key length
        if peer_public.len() != 65 {
            return Err(Error::InvalidKeyLength(format!(
                "P-256 public key must be 65 bytes (uncompressed), got {}",
                peer_public.len()
            )));
        }

        if peer_public[0] != 0x04 {
            return Err(Error::InvalidPublicKey(
                "P-256 public key must use uncompressed format (0x04 prefix)".into(),
            ));
        }

        // Parse peer's public key from uncompressed encoding
        let peer_encoded_point = EncodedPoint::from_bytes(peer_public)
            .map_err(|_| Error::InvalidPublicKey("Failed to parse P-256 public key".into()))?;

        let peer_public_key = PublicKey::from_encoded_point(&peer_encoded_point)
            .into_option()
            .ok_or_else(|| Error::InvalidPublicKey("Invalid P-256 public key point".into()))?;

        // Perform ECDH using the diffie_hellman function
        let shared_secret = diffie_hellman(
            self.secret_key.to_nonzero_scalar(),
            peer_public_key.as_affine(),
        );

        // Extract the shared secret bytes (x-coordinate)
        let shared_bytes = shared_secret.raw_secret_bytes();

        // Convert to fixed-size array
        let mut result = [0u8; 32];
        result.copy_from_slice(shared_bytes.as_slice());

        Ok(Zeroizing::new(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test ECDH-P256 key exchange commutativity: Alice->Bob == Bob->Alice
    #[test]
    fn test_key_exchange_commutativity() {
        let alice = EcdhP256KeyPair::generate().unwrap();
        let bob = EcdhP256KeyPair::generate().unwrap();

        let alice_shared = alice.exchange(bob.public_key()).unwrap();
        let bob_shared = bob.exchange(alice.public_key()).unwrap();

        assert_eq!(&*alice_shared, &*bob_shared);
    }

    /// Test key generation produces valid keypairs
    #[test]
    fn test_generate() {
        let keypair = EcdhP256KeyPair::generate().unwrap();

        // Public key should be 65 bytes in uncompressed format
        assert_eq!(keypair.public_key().len(), 65);
        // Should start with 0x04 (uncompressed point indicator)
        assert_eq!(keypair.public_key()[0], 0x04);
    }

    /// Test deterministic key derivation from private key
    #[test]
    fn test_deterministic() {
        let private_key = [0x42u8; 32];

        let keypair1 = EcdhP256KeyPair::from_private(&private_key).unwrap();
        let keypair2 = EcdhP256KeyPair::from_private(&private_key).unwrap();

        assert_eq!(keypair1.public_key(), keypair2.public_key());
    }

    /// Test roundtrip key exchange
    #[test]
    fn test_key_exchange_roundtrip() {
        let alice = EcdhP256KeyPair::generate().unwrap();
        let bob = EcdhP256KeyPair::generate().unwrap();

        let shared_secret = alice.exchange(bob.public_key()).unwrap();

        // Shared secret should be 32 bytes
        assert_eq!(shared_secret.len(), 32);
        // Shared secret should not be all zeros
        assert_ne!(&*shared_secret, &[0u8; 32]);
    }

    /// Test rejection of invalid public key length
    #[test]
    fn test_reject_invalid_public_key_length() {
        let keypair = EcdhP256KeyPair::generate().unwrap();

        // Try with wrong length
        let invalid_public = vec![0x04; 64]; // Should be 65 bytes
        let result = keypair.exchange(&invalid_public);

        assert!(result.is_err());
    }

    /// Test rejection of compressed public key format
    #[test]
    fn test_reject_compressed_format() {
        let keypair = EcdhP256KeyPair::generate().unwrap();

        // Compressed format starts with 0x02 or 0x03, not 0x04
        let mut invalid_public = vec![0x02; 65];
        invalid_public[0] = 0x02;
        let result = keypair.exchange(&invalid_public);

        assert!(result.is_err());
    }

    /// Test different keypairs produce different public keys
    #[test]
    fn test_unique_keypairs() {
        let keypair1 = EcdhP256KeyPair::generate().unwrap();
        let keypair2 = EcdhP256KeyPair::generate().unwrap();

        assert_ne!(keypair1.public_key(), keypair2.public_key());
    }

    /// Test different keypair pairs produce different shared secrets
    #[test]
    fn test_unique_shared_secrets() {
        let alice1 = EcdhP256KeyPair::generate().unwrap();
        let bob1 = EcdhP256KeyPair::generate().unwrap();

        let alice2 = EcdhP256KeyPair::generate().unwrap();
        let bob2 = EcdhP256KeyPair::generate().unwrap();

        let shared1 = alice1.exchange(bob1.public_key()).unwrap();
        let shared2 = alice2.exchange(bob2.public_key()).unwrap();

        assert_ne!(&*shared1, &*shared2);
    }
}
