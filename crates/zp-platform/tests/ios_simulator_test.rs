//! iOS Simulator integration tests.
//!
//! These tests are marked `#[ignore]` and must be run manually on iOS Simulator:
//!
//! ```bash
//! # Build for iOS Simulator
//! cargo test --target aarch64-apple-ios-sim --package zp-platform --test ios_simulator_test -- --ignored
//! ```
//!
//! Note: These tests verify basic functionality but cannot test Secure Enclave
//! (which is unavailable in simulator). For full Secure Enclave testing, use
//! the diagnostic runner on a physical device.

#[cfg(target_os = "ios")]
mod ios_tests {
    use zp_platform::ios::{InMemoryKeyProvider, SecureEnclaveKeyProvider};
    use zp_platform::traits::KeyProvider;

    #[test]
    #[ignore] // Run manually: cargo test --target aarch64-apple-ios-sim -- --ignored
    fn test_in_memory_provider_basic_operations() {
        let provider = InMemoryKeyProvider::new();

        // Get device key
        let key = provider.get_device_key().expect("Should get device key");
        assert_eq!(key.len(), 32, "Key should be 32 bytes");

        // Encrypt/decrypt roundtrip
        let plaintext = b"Test data for iOS Simulator";
        let ciphertext = provider.encrypt(plaintext).expect("Should encrypt");
        let decrypted = provider.decrypt(&ciphertext).expect("Should decrypt");

        assert_eq!(&decrypted[..], plaintext, "Roundtrip should work");
    }

    #[test]
    #[ignore]
    fn test_in_memory_provider_multiple_instances() {
        let provider1 = InMemoryKeyProvider::new();
        let provider2 = InMemoryKeyProvider::new();

        let key1 = provider1.get_device_key().unwrap();
        let key2 = provider2.get_device_key().unwrap();

        // Different instances should have different keys
        assert_ne!(*key1, *key2, "Random keys should differ");
    }

    #[test]
    #[ignore]
    fn test_in_memory_provider_custom_key() {
        let custom_key = [0x42u8; 32];
        let provider = InMemoryKeyProvider::with_key(custom_key);

        let key = provider.get_device_key().unwrap();
        assert_eq!(*key, custom_key, "Custom key should be returned");
    }

    #[test]
    #[ignore]
    fn test_in_memory_provider_wrong_key_fails() {
        let provider1 = InMemoryKeyProvider::new();
        let provider2 = InMemoryKeyProvider::new();

        let plaintext = b"Secret message";
        let ciphertext = provider1.encrypt(plaintext).unwrap();

        // Decryption with different key should fail
        let result = provider2.decrypt(&ciphertext);
        assert!(result.is_err(), "Wrong key should fail decryption");
    }

    #[test]
    #[ignore]
    fn test_in_memory_provider_corrupted_ciphertext() {
        let provider = InMemoryKeyProvider::new();
        let plaintext = b"Test data";

        let mut ciphertext = provider.encrypt(plaintext).unwrap();

        // Corrupt the authentication tag
        if let Some(byte) = ciphertext.last_mut() {
            *byte = byte.wrapping_add(1);
        }

        // Decryption should fail
        let result = provider.decrypt(&ciphertext);
        assert!(result.is_err(), "Corrupted data should fail decryption");
    }

    #[test]
    #[ignore]
    fn test_in_memory_provider_empty_plaintext() {
        let provider = InMemoryKeyProvider::new();
        let plaintext = b"";

        let ciphertext = provider.encrypt(plaintext).unwrap();
        let decrypted = provider.decrypt(&ciphertext).unwrap();

        assert_eq!(
            &decrypted[..],
            plaintext,
            "Empty plaintext should roundtrip"
        );
    }

    #[test]
    #[ignore]
    fn test_in_memory_provider_large_plaintext() {
        let provider = InMemoryKeyProvider::new();
        let plaintext = vec![0x42u8; 10_000]; // 10KB

        let ciphertext = provider.encrypt(&plaintext).unwrap();
        let decrypted = provider.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext, "Large plaintext should roundtrip");
    }

    /// Diagnostic test for Secure Enclave key persistence.
    ///
    /// **REQUIRES PHYSICAL DEVICE** - Secure Enclave unavailable in simulator.
    ///
    /// This test verifies that a Secure Enclave key:
    /// 1. Can be generated and stored in Keychain
    /// 2. Can be retrieved using the same key tag
    /// 3. Produces identical derived keys across multiple provider instances
    /// 4. Persists across app restarts (manual verification required)
    ///
    /// # Manual Testing Procedure
    ///
    /// 1. Run this test on a physical iOS device:
    ///    ```bash
    ///    cargo test --target aarch64-apple-ios --package zp-platform \
    ///      --test ios_simulator_test test_secure_enclave_key_persistence -- --ignored
    ///    ```
    ///
    /// 2. Note the ciphertext hex output in console
    ///
    /// 3. Terminate and restart the test app
    ///
    /// 4. Run the test again - it should:
    ///    - Retrieve the same key (not generate new)
    ///    - Decrypt the previous ciphertext successfully
    ///    - Produce identical ciphertext for same plaintext
    ///
    /// 5. To reset: Delete and reinstall app (clears Keychain)
    ///
    /// # Expected Results
    ///
    /// - ✓ First run: Generates new key, stores in Keychain
    /// - ✓ Subsequent runs: Retrieves existing key
    /// - ✓ Derived AES key remains stable across instances
    /// - ✓ Encryption/decryption produces consistent results
    /// - ✓ Key survives app restarts
    ///
    /// # Failure Modes
    ///
    /// - Simulator: Returns Error::Unavailable (expected)
    /// - Device without Secure Enclave: Returns Error::Unavailable
    /// - Different ciphertext each run: Key not persisting (BUG)
    /// - Cannot decrypt previous ciphertext: Key changed (BUG)
    #[test]
    #[ignore] // Requires physical device - cannot run in simulator
    fn test_secure_enclave_key_persistence() {
        // Use a test-specific key tag
        let key_tag = "com.zp.test.persistence";
        let test_plaintext = b"Persistence test data";

        // First provider instance
        let provider1 = match SecureEnclaveKeyProvider::new(key_tag) {
            Ok(p) => p,
            Err(e) => {
                // Expected on simulator or devices without Secure Enclave
                println!("Secure Enclave unavailable (expected on simulator): {}", e);
                return;
            }
        };

        // Encrypt with first provider
        let ciphertext1 = provider1
            .encrypt(test_plaintext)
            .expect("Encryption should succeed");

        println!(
            "Ciphertext (hex): {}",
            hex::encode(&ciphertext1[..std::cmp::min(ciphertext1.len(), 64)])
        );

        // Drop first provider
        drop(provider1);

        // Second provider instance - should retrieve same key
        let provider2 =
            SecureEnclaveKeyProvider::new(key_tag).expect("Should retrieve existing key");

        // Decrypt with second provider
        let decrypted = provider2
            .decrypt(&ciphertext1)
            .expect("Decryption should succeed with same key");

        assert_eq!(
            &decrypted[..],
            test_plaintext,
            "Decryption should succeed with persisted key"
        );

        // Encrypt same plaintext again
        let ciphertext2 = provider2.encrypt(test_plaintext).unwrap();

        // Decrypt second ciphertext
        let decrypted2 = provider2.decrypt(&ciphertext2).unwrap();

        assert_eq!(
            &decrypted2[..],
            test_plaintext,
            "Second roundtrip should work"
        );

        // Note: ciphertext1 != ciphertext2 due to random nonces (expected)
        // But both should decrypt to same plaintext (verified above)

        println!("✓ Key persistence verified:");
        println!("  - Key retrieved across provider instances");
        println!("  - Encryption/decryption consistent");
        println!("  - HKDF derivation stable");
        println!("");
        println!("Manual verification:");
        println!("  1. Note the ciphertext hex above");
        println!("  2. Restart this test");
        println!("  3. Key should be retrieved (not regenerated)");
        println!("  4. Previous ciphertext should still decrypt");
    }
}

#[cfg(target_os = "ios")]
mod network_monitor_tests {
    use zp_platform::ios::NWPathMonitorWrapper;
    use zp_platform::traits::{InterfaceType, NetworkMonitor};

    #[test]
    #[ignore]
    fn test_network_monitor_creation() {
        let monitor = NWPathMonitorWrapper::new();
        assert!(monitor.is_ok(), "Monitor creation should succeed");
    }

    #[test]
    #[ignore]
    fn test_network_monitor_current_path() {
        let monitor = NWPathMonitorWrapper::new().unwrap();
        let path = monitor.current_path();

        // Should have a valid interface type
        assert!(matches!(
            path.interface_type,
            InterfaceType::Wifi
                | InterfaceType::Cellular
                | InterfaceType::Wired
                | InterfaceType::Other
        ));
    }

    #[test]
    #[ignore]
    fn test_network_monitor_callback_registration() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let monitor = NWPathMonitorWrapper::new().unwrap();
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        monitor.on_path_change(Box::new(move |_path| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
        }));

        // Callback registration should succeed
        // (actual triggering depends on network changes)
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            0,
            "Callback not yet triggered"
        );
    }
}

// Placeholder tests for non-iOS platforms
#[cfg(not(target_os = "ios"))]
mod placeholder_tests {
    #[test]
    fn ios_tests_require_ios_target() {
        // This test exists to prevent cargo test from failing when not on iOS
        println!("iOS tests require --target aarch64-apple-ios-sim");
    }
}
