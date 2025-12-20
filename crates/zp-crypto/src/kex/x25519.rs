//! X25519 key exchange (RFC 7748).
//!
//! Implements the X25519 Elliptic Curve Diffie-Hellman (ECDH) function as specified
//! in RFC 7748. X25519 is used in the zp protocol for all cipher suites except
//! ZP_CLASSICAL_2 (which uses ECDH-P256 for FIPS compliance).
//!
//! # Security
//!
//! - All private keys and shared secrets are wrapped in `Zeroizing<>` to ensure
//!   they are securely cleared from memory when dropped.
//! - Uses `x25519-dalek` crate which provides a well-tested implementation.
//! - Constant-time operations prevent timing side-channel attacks.
//!
//! # Example
//!
//! ```
//! use zp_crypto::kex::X25519KeyPair;
//!
//! # fn example() -> Result<(), zp_crypto::Error> {
//! // Alice generates a keypair
//! let alice = X25519KeyPair::generate()?;
//!
//! // Bob generates a keypair
//! let bob = X25519KeyPair::generate()?;
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
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// X25519 key pair for Elliptic Curve Diffie-Hellman key exchange.
///
/// This structure holds both a private key and its corresponding public key.
/// The private key is automatically zeroed when dropped.
pub struct X25519KeyPair {
    /// Private scalar (32 bytes), zeroed on drop.
    private_key: Zeroizing<StaticSecret>,
    /// Public key point (32 bytes).
    public_key: PublicKey,
}

impl X25519KeyPair {
    /// Generate a new random X25519 keypair using a cryptographically secure RNG.
    ///
    /// # Errors
    ///
    /// This function should not fail under normal circumstances. It returns a `Result`
    /// for consistency with other key generation functions.
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// assert_eq!(keypair.public_key().len(), 32);
    /// ```
    pub fn generate() -> Result<Self> {
        let private_key = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let public_key = PublicKey::from(&private_key);

        Ok(Self {
            private_key: Zeroizing::new(private_key),
            public_key,
        })
    }

    /// Get the public key as a 32-byte array.
    ///
    /// The public key can be safely shared with peers and is used to compute
    /// the shared secret during key exchange.
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// let public_bytes = keypair.public_key();
    /// assert_eq!(public_bytes.len(), 32);
    /// ```
    pub fn public_key(&self) -> &[u8; 32] {
        self.public_key.as_bytes()
    }

    /// Perform X25519 key exchange with a peer's public key.
    ///
    /// Computes the shared secret using this keypair's private key and the peer's
    /// public key. The shared secret is 32 bytes and is wrapped in `Zeroizing` to
    /// ensure it is securely cleared from memory when no longer needed.
    ///
    /// # Arguments
    ///
    /// * `peer_public` - The peer's X25519 public key (32 bytes)
    ///
    /// # Returns
    ///
    /// A `Zeroizing`-wrapped 32-byte shared secret.
    ///
    /// # Errors
    ///
    /// Returns `Error::KeyExchange` if the peer's public key is invalid (e.g., all zeros).
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::X25519KeyPair;
    ///
    /// let alice = X25519KeyPair::generate().unwrap();
    /// let bob = X25519KeyPair::generate().unwrap();
    ///
    /// let shared_secret = alice.exchange(bob.public_key()).unwrap();
    /// assert_eq!(shared_secret.len(), 32);
    /// ```
    pub fn exchange(&self, peer_public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        let peer_key = PublicKey::from(*peer_public);
        let shared = self.private_key.diffie_hellman(&peer_key);

        // Check for low-order points (all zeros shared secret indicates failure)
        if shared.as_bytes() == &[0u8; 32] {
            return Err(Error::KeyExchange(
                "Invalid peer public key (low-order point)".into(),
            ));
        }

        Ok(Zeroizing::new(*shared.as_bytes()))
    }

    /// Create an X25519 keypair from a raw private key.
    ///
    /// This is primarily used for testing with known test vectors.
    /// In production, use `generate()` instead.
    ///
    /// # Arguments
    ///
    /// * `private` - The 32-byte private scalar
    ///
    /// # Example
    ///
    /// ```
    /// use zp_crypto::kex::X25519KeyPair;
    ///
    /// let private = [42u8; 32];
    /// let keypair = X25519KeyPair::from_private(private).unwrap();
    /// ```
    #[doc(hidden)]
    pub fn from_private(private: [u8; 32]) -> Result<Self> {
        let private_key = StaticSecret::from(private);
        let public_key = PublicKey::from(&private_key);

        Ok(Self {
            private_key: Zeroizing::new(private_key),
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test X25519 key exchange against RFC 7748 §6.1 canonical test vectors.
    ///
    /// These vectors are from TEST_VECTORS.md §1.1 and verify that our implementation
    /// produces the correct shared secret given known private and public keys.
    #[test]
    fn test_x25519_rfc7748_vectors() {
        // Test vectors from TEST_VECTORS.md §1.1 (RFC 7748 §6.1)
        let alice_private_bytes =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap();
        let alice_public_expected =
            hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .unwrap();
        let bob_private_bytes =
            hex::decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
                .unwrap();
        let bob_public_expected =
            hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .unwrap();
        let expected_shared =
            hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
                .unwrap();

        // Create Alice's keypair from known private key
        let alice_private: [u8; 32] = alice_private_bytes.try_into().unwrap();
        let alice = X25519KeyPair::from_private(alice_private).unwrap();

        // Verify Alice's public key matches expected
        assert_eq!(
            alice.public_key(),
            alice_public_expected.as_slice(),
            "Alice's public key doesn't match RFC 7748 test vector"
        );

        // Create Bob's keypair from known private key
        let bob_private: [u8; 32] = bob_private_bytes.try_into().unwrap();
        let bob = X25519KeyPair::from_private(bob_private).unwrap();

        // Verify Bob's public key matches expected
        assert_eq!(
            bob.public_key(),
            bob_public_expected.as_slice(),
            "Bob's public key doesn't match RFC 7748 test vector"
        );

        // Alice computes shared secret with Bob's public key
        let alice_shared = alice.exchange(bob.public_key()).unwrap();

        // Bob computes shared secret with Alice's public key
        let bob_shared = bob.exchange(alice.public_key()).unwrap();

        // Both should produce the same shared secret
        assert_eq!(
            &*alice_shared,
            expected_shared.as_slice(),
            "Alice's shared secret doesn't match RFC 7748 test vector"
        );

        assert_eq!(
            &*bob_shared,
            expected_shared.as_slice(),
            "Bob's shared secret doesn't match RFC 7748 test vector"
        );

        // Verify Alice and Bob computed the same secret
        assert_eq!(
            &*alice_shared, &*bob_shared,
            "Alice and Bob computed different shared secrets"
        );
    }

    /// Test that key generation produces valid keypairs.
    #[test]
    fn test_generate() {
        let keypair = X25519KeyPair::generate().unwrap();

        // Public key should be 32 bytes
        assert_eq!(keypair.public_key().len(), 32);

        // Public key should not be all zeros (extremely unlikely)
        assert_ne!(keypair.public_key(), &[0u8; 32]);
    }

    /// Test that two different keypairs can perform key exchange.
    #[test]
    fn test_key_exchange_random() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let alice_shared = alice.exchange(bob.public_key()).unwrap();
        let bob_shared = bob.exchange(alice.public_key()).unwrap();

        // Both should compute the same shared secret
        assert_eq!(&*alice_shared, &*bob_shared);

        // Shared secret should be 32 bytes
        assert_eq!(alice_shared.len(), 32);

        // Shared secret should not be all zeros
        assert_ne!(&*alice_shared, &[0u8; 32]);
    }

    /// Test that exchange rejects low-order points (all-zero public keys).
    #[test]
    fn test_reject_low_order_point() {
        let alice = X25519KeyPair::generate().unwrap();
        let bad_public_key = [0u8; 32];

        let result = alice.exchange(&bad_public_key);
        assert!(
            result.is_err(),
            "Should reject all-zero public key (low-order point)"
        );

        if let Err(Error::KeyExchange(msg)) = result {
            assert!(msg.contains("low-order"));
        } else {
            panic!("Expected KeyExchange error");
        }
    }

    /// Test that multiple key exchanges with the same keys produce the same result.
    #[test]
    fn test_deterministic() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let shared1 = alice.exchange(bob.public_key()).unwrap();
        let shared2 = alice.exchange(bob.public_key()).unwrap();

        assert_eq!(&*shared1, &*shared2);
    }
}
