//! Trait contract tests for KeyProvider and NetworkMonitor.
//!
//! These tests verify that mock implementations satisfy the trait contracts.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use zp_platform::mock::{MockKeyProvider, MockNetworkMonitor};
use zp_platform::traits::{InterfaceType, KeyProvider, NetworkMonitor, NetworkPath};

// ============================================================================
// KeyProvider Contract Tests
// ============================================================================

#[test]
fn test_key_provider_get_device_key_succeeds() {
    let provider = MockKeyProvider::new_deterministic();
    let result = provider.get_device_key();
    assert!(result.is_ok(), "get_device_key should succeed");
    assert_eq!(result.unwrap().len(), 32, "Key should be 32 bytes");
}

#[test]
fn test_key_provider_get_device_key_deterministic() {
    let provider = MockKeyProvider::new_deterministic();
    let key1 = provider.get_device_key().unwrap();
    let key2 = provider.get_device_key().unwrap();
    assert_eq!(*key1, *key2, "Keys should be deterministic");
}

#[test]
fn test_key_provider_encrypt_produces_valid_output() {
    let provider = MockKeyProvider::new_deterministic();
    let plaintext = b"Test data";

    let ciphertext = provider.encrypt(plaintext).unwrap();

    // Format: nonce[12] || ciphertext || tag[16]
    assert!(
        ciphertext.len() >= 12 + 16,
        "Ciphertext should be at least nonce(12) + tag(16) bytes"
    );
    assert_eq!(
        ciphertext.len(),
        12 + plaintext.len() + 16,
        "Ciphertext length should be nonce + plaintext + tag"
    );
}

#[test]
fn test_key_provider_encrypt_decrypt_roundtrip() {
    let provider = MockKeyProvider::new_deterministic();
    let plaintext = b"Hello, zp protocol!";

    let ciphertext = provider.encrypt(plaintext).unwrap();
    let decrypted = provider.decrypt(&ciphertext).unwrap();

    assert_eq!(
        &decrypted[..],
        plaintext,
        "Decrypted plaintext should match original"
    );
}

#[test]
fn test_key_provider_encrypt_produces_different_ciphertexts() {
    let provider = MockKeyProvider::new_deterministic();
    let plaintext = b"Same plaintext";

    let ciphertext1 = provider.encrypt(plaintext).unwrap();
    let ciphertext2 = provider.encrypt(plaintext).unwrap();

    // Nonces should differ, so ciphertexts should differ
    assert_ne!(
        ciphertext1, ciphertext2,
        "Encrypting same plaintext twice should produce different ciphertexts (different nonces)"
    );
}

#[test]
fn test_key_provider_decrypt_fails_with_wrong_key() {
    let provider1 = MockKeyProvider::new_deterministic();
    let provider2 = MockKeyProvider::new_random();

    let plaintext = b"Secret message";
    let ciphertext = provider1.encrypt(plaintext).unwrap();

    let result = provider2.decrypt(&ciphertext);
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

#[test]
fn test_key_provider_decrypt_fails_with_corrupted_ciphertext() {
    let provider = MockKeyProvider::new_deterministic();
    let plaintext = b"Test data";

    let mut ciphertext = provider.encrypt(plaintext).unwrap();

    // Corrupt the authentication tag (last 16 bytes)
    let len = ciphertext.len();
    ciphertext[len - 1] ^= 0xFF;

    let result = provider.decrypt(&ciphertext);
    assert!(
        result.is_err(),
        "Decryption with corrupted ciphertext should fail"
    );
}

#[test]
fn test_key_provider_decrypt_fails_with_truncated_ciphertext() {
    let provider = MockKeyProvider::new_deterministic();

    // Too short to contain nonce + tag
    let short_ciphertext = vec![0u8; 20];

    let result = provider.decrypt(&short_ciphertext);
    assert!(
        result.is_err(),
        "Decryption with truncated ciphertext should fail"
    );
}

#[test]
fn test_key_provider_encrypt_empty_plaintext() {
    let provider = MockKeyProvider::new_deterministic();
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
fn test_key_provider_encrypt_large_plaintext() {
    let provider = MockKeyProvider::new_deterministic();
    let plaintext = vec![0x42u8; 10_000]; // 10KB

    let ciphertext = provider.encrypt(&plaintext).unwrap();
    let decrypted = provider.decrypt(&ciphertext).unwrap();

    assert_eq!(decrypted, plaintext, "Large plaintext should roundtrip");
}

#[test]
fn test_key_provider_with_custom_key() {
    let custom_key = [0x99u8; 32];
    let provider = MockKeyProvider::with_key(custom_key);

    let key = provider.get_device_key().unwrap();
    assert_eq!(*key, custom_key, "Custom key should be returned");
}

#[test]
fn test_key_provider_random_keys_differ() {
    let provider1 = MockKeyProvider::new_random();
    let provider2 = MockKeyProvider::new_random();

    let key1 = provider1.get_device_key().unwrap();
    let key2 = provider2.get_device_key().unwrap();

    assert_ne!(*key1, *key2, "Random keys should differ");
}

#[test]
fn test_key_provider_zeroizing() {
    let provider = MockKeyProvider::new_deterministic();
    let key = provider.get_device_key().unwrap();

    // Zeroizing wrapper should auto-zero on drop
    // This test verifies the type is correct
    let _key_copy = key.clone();
    // Drop happens here
}

// ============================================================================
// NetworkMonitor Contract Tests
// ============================================================================

#[test]
fn test_network_monitor_current_path() {
    let monitor = MockNetworkMonitor::new();
    let path = monitor.current_path();

    assert_eq!(path.interface_type, InterfaceType::Wifi);
    assert!(!path.is_expensive);
    assert!(!path.is_constrained);
}

#[test]
fn test_network_monitor_with_custom_path() {
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
fn test_network_monitor_simulate_path_change() {
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
fn test_network_monitor_callback_triggered() {
    let monitor = MockNetworkMonitor::new();
    let triggered = Arc::new(AtomicUsize::new(0));
    let triggered_clone = triggered.clone();

    monitor.on_path_change(Box::new(move |path| {
        assert_eq!(path.interface_type, InterfaceType::Cellular);
        triggered_clone.fetch_add(1, Ordering::SeqCst);
    }));

    monitor.simulate_path_change(NetworkPath {
        interface_type: InterfaceType::Cellular,
        is_expensive: true,
        is_constrained: false,
    });

    assert_eq!(
        triggered.load(Ordering::SeqCst),
        1,
        "Callback should be triggered once"
    );
}

#[test]
fn test_network_monitor_multiple_callbacks() {
    let monitor = MockNetworkMonitor::new();
    let count1 = Arc::new(AtomicUsize::new(0));
    let count2 = Arc::new(AtomicUsize::new(0));

    let count1_clone = count1.clone();
    let count2_clone = count2.clone();

    monitor.on_path_change(Box::new(move |_| {
        count1_clone.fetch_add(1, Ordering::SeqCst);
    }));

    monitor.on_path_change(Box::new(move |_| {
        count2_clone.fetch_add(1, Ordering::SeqCst);
    }));

    monitor.simulate_path_change(NetworkPath {
        interface_type: InterfaceType::Wired,
        is_expensive: false,
        is_constrained: false,
    });

    assert_eq!(count1.load(Ordering::SeqCst), 1, "First callback triggered");
    assert_eq!(
        count2.load(Ordering::SeqCst),
        1,
        "Second callback triggered"
    );
}

#[test]
fn test_network_monitor_wifi_to_cellular_transition() {
    let monitor = MockNetworkMonitor::new(); // Starts as WiFi
    let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
    let paths_clone = paths.clone();

    monitor.on_path_change(Box::new(move |path| {
        paths_clone.lock().unwrap().push(path);
    }));

    // Simulate WiFi -> Cellular transition
    monitor.simulate_path_change(NetworkPath {
        interface_type: InterfaceType::Cellular,
        is_expensive: true,
        is_constrained: false,
    });

    let collected_paths = paths.lock().unwrap();
    assert_eq!(collected_paths.len(), 1);
    assert_eq!(collected_paths[0].interface_type, InterfaceType::Cellular);
}

#[test]
fn test_network_monitor_multiple_transitions() {
    let monitor = MockNetworkMonitor::new();
    let paths = Arc::new(std::sync::Mutex::new(Vec::new()));
    let paths_clone = paths.clone();

    monitor.on_path_change(Box::new(move |path| {
        paths_clone.lock().unwrap().push(path.interface_type);
    }));

    // WiFi -> Cellular
    monitor.simulate_path_change(NetworkPath {
        interface_type: InterfaceType::Cellular,
        is_expensive: true,
        is_constrained: false,
    });

    // Cellular -> Wired
    monitor.simulate_path_change(NetworkPath {
        interface_type: InterfaceType::Wired,
        is_expensive: false,
        is_constrained: false,
    });

    // Wired -> WiFi
    monitor.simulate_path_change(NetworkPath {
        interface_type: InterfaceType::Wifi,
        is_expensive: false,
        is_constrained: false,
    });

    let collected = paths.lock().unwrap();
    assert_eq!(collected.len(), 3);
    assert_eq!(collected[0], InterfaceType::Cellular);
    assert_eq!(collected[1], InterfaceType::Wired);
    assert_eq!(collected[2], InterfaceType::Wifi);
}

#[test]
fn test_network_monitor_expensive_flag() {
    let monitor = MockNetworkMonitor::new();

    monitor.simulate_path_change(NetworkPath {
        interface_type: InterfaceType::Cellular,
        is_expensive: true,
        is_constrained: false,
    });

    let path = monitor.current_path();
    assert!(path.is_expensive, "Cellular should be marked expensive");
}

#[test]
fn test_network_monitor_constrained_flag() {
    let monitor = MockNetworkMonitor::new();

    monitor.simulate_path_change(NetworkPath {
        interface_type: InterfaceType::Wifi,
        is_expensive: false,
        is_constrained: true, // Low Data Mode
    });

    let path = monitor.current_path();
    assert!(path.is_constrained, "Low Data Mode should be constrained");
}

#[test]
fn test_network_path_default() {
    let path = NetworkPath::default();

    assert_eq!(path.interface_type, InterfaceType::Other);
    assert!(!path.is_expensive);
    assert!(!path.is_constrained);
}

#[test]
fn test_network_path_clone() {
    let path1 = NetworkPath {
        interface_type: InterfaceType::Cellular,
        is_expensive: true,
        is_constrained: true,
    };

    let path2 = path1.clone();

    assert_eq!(path1, path2);
}

#[test]
fn test_interface_type_variants() {
    // Ensure all variants are covered
    let wifi = InterfaceType::Wifi;
    let cellular = InterfaceType::Cellular;
    let wired = InterfaceType::Wired;
    let other = InterfaceType::Other;

    assert_ne!(wifi, cellular);
    assert_ne!(wifi, wired);
    assert_ne!(wifi, other);
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_key_provider_and_network_monitor_integration() {
    // Simulate scenario: device switches from WiFi to Cellular, triggering State Token save

    let key_provider = MockKeyProvider::new_deterministic();
    let network_monitor = MockNetworkMonitor::new();

    let saved_data = Arc::new(std::sync::Mutex::new(None));
    let saved_data_clone = saved_data.clone();

    network_monitor.on_path_change(Box::new(move |path| {
        if path.interface_type == InterfaceType::Cellular {
            // Simulate saving State Token when network changes
            let plaintext = b"State Token Data";
            let ciphertext = MockKeyProvider::new_deterministic()
                .encrypt(plaintext)
                .unwrap();
            *saved_data_clone.lock().unwrap() = Some(ciphertext);
        }
    }));

    // Trigger network change
    network_monitor.simulate_path_change(NetworkPath {
        interface_type: InterfaceType::Cellular,
        is_expensive: true,
        is_constrained: false,
    });

    // Verify State Token was saved
    let ciphertext = saved_data.lock().unwrap().clone().unwrap();
    let decrypted = key_provider.decrypt(&ciphertext).unwrap();

    assert_eq!(&decrypted[..], b"State Token Data");
}
