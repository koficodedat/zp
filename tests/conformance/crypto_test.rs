//! Cryptographic conformance tests.
//!
//! Verifies implementation against TEST_VECTORS.md §1-3.

#[cfg(test)]
mod x25519_tests {
    use zp_crypto::kex::X25519KeyPair;

    /// X25519 conformance test using RFC 7748 §6.1 test vectors.
    ///
    /// This test is duplicated from zp-crypto/src/kex/x25519.rs to ensure
    /// conformance tests are tracked separately.
    #[test]
    fn test_rfc7748_vectors() {
        // Test vectors from TEST_VECTORS.md §1.1 (RFC 7748 §6.1)
        let alice_private_bytes =
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap();
        let bob_public =
            hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .unwrap();
        let expected_shared =
            hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
                .unwrap();

        // Create Alice's keypair from known private key
        let alice_private: [u8; 32] = alice_private_bytes.try_into().unwrap();
        let alice = X25519KeyPair::from_private(alice_private).unwrap();

        // Perform key exchange with Bob's public key
        let bob_pub_array: &[u8; 32] = bob_public.as_slice().try_into().unwrap();
        let shared = alice.exchange(bob_pub_array).unwrap();

        // Verify shared secret matches expected value
        assert_eq!(&*shared, expected_shared.as_slice());
    }
}

#[cfg(test)]
mod ml_kem_1024_tests {
    use zp_crypto::kex::MlKem1024KeyPair;

    /// ML-KEM-1024 conformance test per TEST_VECTORS.md §1.3.
    ///
    /// Verifies key sizes and encapsulation/decapsulation correctness.
    #[test]
    fn test_ml_kem_1024_sizes_and_roundtrip() {
        // Generate keypair
        let keypair = MlKem1024KeyPair::generate().unwrap();

        // Verify public key size (1568 bytes per FIPS 203)
        assert_eq!(
            keypair.public_key().len(),
            1568,
            "ML-KEM-1024 public key must be 1568 bytes"
        );

        // Encapsulate a shared secret
        let (ciphertext, sender_secret) =
            MlKem1024KeyPair::encapsulate(keypair.public_key()).unwrap();

        // Verify ciphertext size (1568 bytes per FIPS 203)
        assert_eq!(
            ciphertext.len(),
            1568,
            "ML-KEM-1024 ciphertext must be 1568 bytes"
        );

        // Verify shared secret size (32 bytes per FIPS 203)
        assert_eq!(
            sender_secret.len(),
            32,
            "ML-KEM-1024 shared secret must be 32 bytes"
        );

        // Decapsulate to recover shared secret
        let recipient_secret = keypair.decapsulate(&ciphertext).unwrap();

        // Verify decapsulation produces same shared secret
        assert_eq!(
            &*sender_secret, &*recipient_secret,
            "Encapsulated and decapsulated secrets must match"
        );
    }
}

#[cfg(test)]
mod ecdh_p256_tests {
    use zp_crypto::kex::EcdhP256KeyPair;

    /// ECDH-P256 conformance test using RFC 5903 §8.1 test vectors.
    ///
    /// Test vectors from TEST_VECTORS.md §1.4 (RFC 5903 §8.1).
    /// Verifies P-256 ECDH implementation produces correct shared secret.
    #[test]
    fn test_rfc5903_vectors() {
        // Alice's private key from RFC 5903 §8.1
        let alice_private_bytes =
            hex::decode("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433")
                .unwrap();

        // Bob's public key (uncompressed: 0x04 || x || y)
        let bob_public_x =
            hex::decode("D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63")
                .unwrap();
        let bob_public_y =
            hex::decode("56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB")
                .unwrap();

        // Construct uncompressed public key: 0x04 || x || y
        let mut bob_public = vec![0x04];
        bob_public.extend_from_slice(&bob_public_x);
        bob_public.extend_from_slice(&bob_public_y);

        // Expected shared secret from RFC 5903 §8.1
        let expected_shared =
            hex::decode("D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE")
                .unwrap();

        // Create Alice's keypair from known private key
        let alice = EcdhP256KeyPair::from_private(&alice_private_bytes).unwrap();

        // Perform key exchange with Bob's public key
        let shared = alice.exchange(&bob_public).unwrap();

        // Verify shared secret matches expected value
        assert_eq!(
            &*shared,
            expected_shared.as_slice(),
            "ECDH-P256 shared secret must match RFC 5903 §8.1 test vector"
        );
    }
}

#[cfg(test)]
mod ml_kem_tests {
    use zp_crypto::kex::MlKem768KeyPair;

    /// ML-KEM-768 size conformance test per TEST_VECTORS.md §1.2
    ///
    /// Verifies that ML-KEM-768 produces the correct sizes per FIPS 203:
    /// - Public key: 1184 bytes
    /// - Ciphertext: 1088 bytes
    /// - Shared secret: 32 bytes
    #[test]
    fn test_ml_kem_768_sizes() {
        // Generate a keypair
        let keypair = MlKem768KeyPair::generate().unwrap();

        // Verify public key size (1184 bytes per FIPS 203)
        assert_eq!(
            keypair.public_key().len(),
            1184,
            "ML-KEM-768 public key must be 1184 bytes"
        );

        // Encapsulate to get ciphertext and shared secret
        let (ciphertext, shared_secret) =
            MlKem768KeyPair::encapsulate(keypair.public_key()).unwrap();

        // Verify ciphertext size (1088 bytes per FIPS 203)
        assert_eq!(
            ciphertext.len(),
            1088,
            "ML-KEM-768 ciphertext must be 1088 bytes"
        );

        // Verify shared secret size (32 bytes per FIPS 203)
        assert_eq!(
            shared_secret.len(),
            32,
            "ML-KEM-768 shared secret must be 32 bytes"
        );

        // Verify decapsulation produces same-size shared secret
        let decapsulated_secret = keypair.decapsulate(&ciphertext).unwrap();
        assert_eq!(
            decapsulated_secret.len(),
            32,
            "Decapsulated shared secret must be 32 bytes"
        );

        // Verify both parties derive the same shared secret
        assert_eq!(
            &*shared_secret, &*decapsulated_secret,
            "Encapsulated and decapsulated secrets must match"
        );
    }

    #[test]
    #[ignore = "not yet implemented"]
    fn test_ml_kem_1024_sizes() {
        // Per TEST_VECTORS.md §1.3
        // Public key: 1568 bytes
        // Ciphertext: 1568 bytes
        // Shared secret: 32 bytes
    }
}

#[cfg(test)]
mod aead_tests {
    use zp_crypto::aead::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};

    /// ChaCha20-Poly1305 conformance test using RFC 8439 §2.8.2 test vectors.
    ///
    /// Test vectors from TEST_VECTORS.md §4.1 (RFC 8439 §2.8.2)
    #[test]
    fn test_chacha20poly1305_rfc8439() {
        // Test vector from RFC 8439 §2.8.2
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

        // Verify ciphertext matches expected value
        assert_eq!(
            &ciphertext_with_tag[..expected_ciphertext.len()],
            &expected_ciphertext[..],
            "Ciphertext must match RFC 8439 test vector"
        );

        // Verify tag matches expected value
        assert_eq!(
            &ciphertext_with_tag[expected_ciphertext.len()..],
            &expected_tag[..],
            "Authentication tag must match RFC 8439 test vector"
        );

        // Decrypt and verify roundtrip
        let decrypted = chacha20poly1305_decrypt(&key, &nonce, &ciphertext_with_tag, &aad).unwrap();
        assert_eq!(
            &*decrypted, &plaintext,
            "Decrypted plaintext must match original"
        );
    }

    /// AES-256-GCM conformance test using NIST SP 800-38D test vectors.
    ///
    /// Test vectors from TEST_VECTORS.md §4.2 (NIST SP 800-38D)
    #[test]
    fn test_aes256gcm_nist() {
        use zp_crypto::aead::{aes256gcm_decrypt, aes256gcm_encrypt};

        // NIST SP 800-38D test vector
        let key: [u8; 32] =
            hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
                .unwrap()
                .try_into()
                .unwrap();

        let nonce: [u8; 12] = hex::decode("cafebabefacedbaddecaf888")
            .unwrap()
            .try_into()
            .unwrap();

        let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();

        let plaintext = hex::decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        )
        .unwrap();

        let expected_ciphertext = hex::decode(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        )
        .unwrap();

        let expected_tag = hex::decode("76fc6ece0f4e1768cddf8853bb2d551b").unwrap();

        // Encrypt
        let ciphertext_with_tag = aes256gcm_encrypt(&key, &nonce, &plaintext, &aad).unwrap();

        // Verify ciphertext matches NIST test vector
        assert_eq!(
            &ciphertext_with_tag[..expected_ciphertext.len()],
            &expected_ciphertext[..],
            "Ciphertext must match NIST SP 800-38D test vector"
        );

        // Verify tag matches NIST test vector
        assert_eq!(
            &ciphertext_with_tag[expected_ciphertext.len()..],
            &expected_tag[..],
            "Authentication tag must match NIST SP 800-38D test vector"
        );

        // Decrypt and verify roundtrip
        let decrypted = aes256gcm_decrypt(&key, &nonce, &ciphertext_with_tag, &aad).unwrap();
        assert_eq!(
            &*decrypted, &plaintext,
            "Decrypted plaintext must match original"
        );
    }
}

#[cfg(test)]
mod kdf_tests {
    use zp_crypto::kdf::{
        derive_session_keys_stranger, derive_session_secret_stranger, hkdf_sha256,
    };

    /// HKDF-SHA256 conformance test using RFC 5869 Test Case 1.
    ///
    /// Test vectors from TEST_VECTORS.md §2.1 (RFC 5869 Appendix A.1)
    #[test]
    fn test_hkdf_rfc5869() {
        // RFC 5869 Test Case 1
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let okm = hkdf_sha256(&ikm, &salt, &info, 42).unwrap();

        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

        assert_eq!(
            &*okm, &expected,
            "HKDF output must match RFC 5869 test vector"
        );
    }

    /// Session secret and keys derivation conformance test for Stranger Mode.
    ///
    /// Test vectors from TEST_VECTORS.md §2.2-2.3
    #[test]
    fn test_session_derivation_stranger() {
        // Test data from TEST_VECTORS.md
        let shared_secret =
            hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
                .unwrap();
        let client_random: [u8; 32] =
            hex::decode("0001020304050607080910111213141516171819202122232425262728293031")
                .unwrap()
                .try_into()
                .unwrap();
        let server_random: [u8; 32] =
            hex::decode("3130292827262524232221201918171615141312111009080706050403020100")
                .unwrap()
                .try_into()
                .unwrap();

        // Derive session secret
        let session_secret =
            derive_session_secret_stranger(&shared_secret, &client_random, &server_random).unwrap();

        // Verify it's 32 bytes and not all zeros
        assert_eq!(session_secret.len(), 32, "Session secret must be 32 bytes");
        assert_ne!(
            &*session_secret, &[0u8; 32],
            "Session secret must not be all zeros"
        );

        // Derive session keys
        let (c2s_key, s2c_key) =
            derive_session_keys_stranger(&shared_secret, &client_random, &server_random).unwrap();

        // Verify key sizes
        assert_eq!(c2s_key.len(), 32, "Client-to-server key must be 32 bytes");
        assert_eq!(s2c_key.len(), 32, "Server-to-client key must be 32 bytes");

        // Verify keys are different
        assert_ne!(
            &*c2s_key, &*s2c_key,
            "Client and server keys must be different"
        );

        // Verify keys are not all zeros
        assert_ne!(
            &*c2s_key, &[0u8; 32],
            "Client-to-server key must not be all zeros"
        );
        assert_ne!(
            &*s2c_key, &[0u8; 32],
            "Server-to-client key must not be all zeros"
        );
    }

    /// Session secret and keys derivation conformance test for Known Mode.
    ///
    /// Test vectors from TEST_VECTORS.md §2.4-2.5
    #[test]
    fn test_session_derivation_known() {
        use zp_crypto::kdf::{derive_session_keys_known, derive_session_secret_known};

        // Test data
        let spake2_key = [0x11u8; 32];
        let shared_secret =
            hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
                .unwrap();
        let client_random: [u8; 32] =
            hex::decode("0001020304050607080910111213141516171819202122232425262728293031")
                .unwrap()
                .try_into()
                .unwrap();
        let server_random: [u8; 32] =
            hex::decode("3130292827262524232221201918171615141312111009080706050403020100")
                .unwrap()
                .try_into()
                .unwrap();

        // Derive session secret
        let session_secret = derive_session_secret_known(
            &spake2_key,
            &shared_secret,
            &client_random,
            &server_random,
        )
        .unwrap();

        // Verify it's 32 bytes and not all zeros
        assert_eq!(session_secret.len(), 32, "Session secret must be 32 bytes");
        assert_ne!(
            &*session_secret, &[0u8; 32],
            "Session secret must not be all zeros"
        );

        // Derive session keys
        let (c2s_key, s2c_key) =
            derive_session_keys_known(&spake2_key, &shared_secret, &client_random, &server_random)
                .unwrap();

        // Verify key sizes
        assert_eq!(c2s_key.len(), 32, "Client-to-server key must be 32 bytes");
        assert_eq!(s2c_key.len(), 32, "Server-to-client key must be 32 bytes");

        // Verify keys are different
        assert_ne!(
            &*c2s_key, &*s2c_key,
            "Client and server keys must be different"
        );

        // Verify keys are not all zeros
        assert_ne!(
            &*c2s_key, &[0u8; 32],
            "Client-to-server key must not be all zeros"
        );
        assert_ne!(
            &*s2c_key, &[0u8; 32],
            "Server-to-client key must not be all zeros"
        );
    }

    /// Key rotation derivation conformance test per spec §4.6.3
    #[test]
    fn test_key_rotation_derivation() {
        use zp_crypto::kdf::{derive_traffic_key, update_current_secret, KeyDirection};

        let current_secret = [0x42u8; 32];
        let session_id = [0x01u8; 16];
        let key_epoch = 1u32;

        // Derive traffic keys for both directions
        let c2s_key = derive_traffic_key(
            &current_secret,
            &session_id,
            key_epoch,
            KeyDirection::ClientToServer,
        )
        .unwrap();
        let s2c_key = derive_traffic_key(
            &current_secret,
            &session_id,
            key_epoch,
            KeyDirection::ServerToClient,
        )
        .unwrap();

        // Verify key sizes
        assert_eq!(c2s_key.len(), 32, "Traffic key must be 32 bytes");
        assert_eq!(s2c_key.len(), 32, "Traffic key must be 32 bytes");

        // Verify keys are different for different directions
        assert_ne!(&*c2s_key, &*s2c_key, "Directional keys must be different");

        // Update current secret for forward secrecy
        let new_secret = update_current_secret(&current_secret, &session_id, key_epoch).unwrap();

        // Verify new secret is different
        assert_ne!(
            &*new_secret, &current_secret,
            "Updated secret must be different"
        );
        assert_eq!(new_secret.len(), 32, "New secret must be 32 bytes");
    }
}

#[cfg(test)]
mod suite_tests {
    use zp_crypto::suite::{AeadAlgorithm, CipherSuite, MlKemVariant};

    /// Cipher suite ID conversion test.
    #[test]
    fn test_cipher_suite_ids() {
        assert_eq!(CipherSuite::ZpHybrid1.to_u16(), 0x0001);
        assert_eq!(CipherSuite::ZpHybrid2.to_u16(), 0x0002);
        assert_eq!(CipherSuite::ZpHybrid3.to_u16(), 0x0003);
        assert_eq!(CipherSuite::ZpClassical2.to_u16(), 0x0005);
    }

    /// Cipher suite from_u16() validation.
    #[test]
    fn test_cipher_suite_from_u16() {
        assert_eq!(
            CipherSuite::from_u16(0x0001).unwrap(),
            CipherSuite::ZpHybrid1
        );
        assert_eq!(
            CipherSuite::from_u16(0x0002).unwrap(),
            CipherSuite::ZpHybrid2
        );
        assert_eq!(
            CipherSuite::from_u16(0x0003).unwrap(),
            CipherSuite::ZpHybrid3
        );
        assert_eq!(
            CipherSuite::from_u16(0x0005).unwrap(),
            CipherSuite::ZpClassical2
        );

        // Invalid ID
        assert!(CipherSuite::from_u16(0x9999).is_none());
    }

    /// ML-KEM variant mapping test.
    #[test]
    fn test_ml_kem_variant_mapping() {
        assert_eq!(
            CipherSuite::ZpHybrid1.ml_kem_variant(),
            Some(MlKemVariant::MlKem768)
        );
        assert_eq!(
            CipherSuite::ZpHybrid2.ml_kem_variant(),
            Some(MlKemVariant::MlKem1024)
        );
        assert_eq!(
            CipherSuite::ZpHybrid3.ml_kem_variant(),
            Some(MlKemVariant::MlKem768)
        );
        assert_eq!(CipherSuite::ZpClassical2.ml_kem_variant(), None);
    }

    /// AEAD algorithm mapping test.
    #[test]
    fn test_aead_algorithm_mapping() {
        assert_eq!(
            CipherSuite::ZpHybrid1.aead_algorithm(),
            AeadAlgorithm::ChaCha20Poly1305
        );
        assert_eq!(
            CipherSuite::ZpHybrid2.aead_algorithm(),
            AeadAlgorithm::ChaCha20Poly1305
        );
        assert_eq!(
            CipherSuite::ZpHybrid3.aead_algorithm(),
            AeadAlgorithm::Aes256Gcm
        );
        assert_eq!(
            CipherSuite::ZpClassical2.aead_algorithm(),
            AeadAlgorithm::Aes256Gcm
        );
    }
}

#[cfg(test)]
mod property_tests {
    use zp_crypto::aead::{chacha20poly1305_decrypt, chacha20poly1305_encrypt, construct_nonce};
    use zp_crypto::kdf::hkdf_sha256;
    use zp_crypto::kex::{MlKem768KeyPair, X25519KeyPair};

    /// Property: X25519 key exchange is commutative.
    ///
    /// For any two keypairs (A, B):
    /// A.exchange(B.public) == B.exchange(A.public)
    #[test]
    fn test_x25519_commutativity() {
        // Generate two random keypairs
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        // Each party performs key exchange
        let alice_shared = alice.exchange(bob.public_key()).unwrap();
        let bob_shared = bob.exchange(alice.public_key()).unwrap();

        // Both must derive the same shared secret
        assert_eq!(
            &*alice_shared, &*bob_shared,
            "X25519 key exchange must be commutative"
        );
    }

    /// Property: ML-KEM-768 encapsulate/decapsulate roundtrip always succeeds.
    ///
    /// For any keypair and encapsulation:
    /// decapsulate(encapsulate(public_key).ciphertext) == encapsulate().shared_secret
    #[test]
    fn test_ml_kem_768_roundtrip() {
        // Generate a keypair
        let keypair = MlKem768KeyPair::generate().unwrap();

        // Encapsulate a shared secret
        let (ciphertext, sender_secret) =
            MlKem768KeyPair::encapsulate(keypair.public_key()).unwrap();

        // Decapsulate to recover the shared secret
        let recipient_secret = keypair.decapsulate(&ciphertext).unwrap();

        // Both parties must have the same shared secret
        assert_eq!(
            &*sender_secret, &*recipient_secret,
            "ML-KEM-768 encapsulate/decapsulate must be a valid roundtrip"
        );
    }

    /// Property: ChaCha20-Poly1305 encrypt/decrypt roundtrip preserves plaintext.
    ///
    /// For any key, nonce, plaintext, AAD:
    /// decrypt(encrypt(plaintext)) == plaintext
    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = construct_nonce(12345);
        let plaintext = b"The quick brown fox jumps over the lazy dog";
        let aad = b"additional authenticated data";

        // Encrypt
        let ciphertext = chacha20poly1305_encrypt(&key, &nonce, plaintext, aad).unwrap();

        // Decrypt
        let decrypted = chacha20poly1305_decrypt(&key, &nonce, &ciphertext, aad).unwrap();

        // Plaintext must be preserved
        assert_eq!(
            &*decrypted, plaintext,
            "ChaCha20-Poly1305 encrypt/decrypt must preserve plaintext"
        );
    }

    /// Property: ChaCha20-Poly1305 is deterministic.
    ///
    /// Encrypting the same plaintext with the same key/nonce/AAD always produces
    /// the same ciphertext.
    #[test]
    fn test_chacha20poly1305_deterministic() {
        let key = [0x42u8; 32];
        let nonce = construct_nonce(12345);
        let plaintext = b"deterministic test";
        let aad = b"metadata";

        // Encrypt twice with same inputs
        let ciphertext1 = chacha20poly1305_encrypt(&key, &nonce, plaintext, aad).unwrap();
        let ciphertext2 = chacha20poly1305_encrypt(&key, &nonce, plaintext, aad).unwrap();

        // Must produce identical ciphertext
        assert_eq!(
            ciphertext1, ciphertext2,
            "ChaCha20-Poly1305 must be deterministic"
        );
    }

    /// Property: HKDF is deterministic.
    ///
    /// The same IKM, salt, and info always produce the same output.
    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"input key material";
        let salt = b"salt value";
        let info = b"application context";

        // Derive twice with same inputs
        let okm1 = hkdf_sha256(ikm, salt, info, 32).unwrap();
        let okm2 = hkdf_sha256(ikm, salt, info, 32).unwrap();

        // Must produce identical output
        assert_eq!(&*okm1, &*okm2, "HKDF must be deterministic");
    }

    /// Property: Different nonces produce different ciphertexts.
    ///
    /// Encrypting the same plaintext with different nonces must produce
    /// different ciphertexts (with overwhelming probability).
    #[test]
    fn test_chacha20poly1305_nonce_independence() {
        let key = [0x42u8; 32];
        let nonce1 = construct_nonce(1);
        let nonce2 = construct_nonce(2);
        let plaintext = b"same plaintext";
        let aad = b"";

        let ciphertext1 = chacha20poly1305_encrypt(&key, &nonce1, plaintext, aad).unwrap();
        let ciphertext2 = chacha20poly1305_encrypt(&key, &nonce2, plaintext, aad).unwrap();

        // Different nonces must produce different ciphertexts
        assert_ne!(
            ciphertext1, ciphertext2,
            "Different nonces must produce different ciphertexts"
        );
    }

    /// Property: ML-KEM-768 produces unique shared secrets.
    ///
    /// Multiple encapsulations to the same public key produce different
    /// shared secrets (randomized encapsulation).
    #[test]
    fn test_ml_kem_768_randomized_encapsulation() {
        let keypair = MlKem768KeyPair::generate().unwrap();

        // Encapsulate twice to the same public key
        let (ct1, secret1) = MlKem768KeyPair::encapsulate(keypair.public_key()).unwrap();
        let (ct2, secret2) = MlKem768KeyPair::encapsulate(keypair.public_key()).unwrap();

        // Ciphertexts should be different (randomized)
        assert_ne!(ct1, ct2, "ML-KEM-768 encapsulation must be randomized");

        // Shared secrets should be different
        assert_ne!(
            &*secret1, &*secret2,
            "Multiple encapsulations must produce different shared secrets"
        );
    }
}
