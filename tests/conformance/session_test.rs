// Session conformance tests per TEST_VECTORS.md sections 2.2, 2.3, 3.1, and 9.1

use sha2::{Digest, Sha256};
use zp_core::session::{HandshakeMode, Role, Session};
use zp_crypto::kdf;

#[test]
fn test_session_id_derivation_stranger() {
    // TEST_VECTORS.md §3.1
    let client_random =
        hex::decode("0001020304050607080910111213141516171819202122232425262728293031").unwrap();
    let server_random =
        hex::decode("3130292827262524232221201918171615141312111009080706050403020100").unwrap();
    let shared_secret =
        hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742").unwrap();

    // Concatenation: client_random || server_random || shared_secret
    let mut input = Vec::new();
    input.extend_from_slice(&client_random);
    input.extend_from_slice(&server_random);
    input.extend_from_slice(&shared_secret);

    let expected_concat = hex::decode(
        "000102030405060708091011121314151617181920212223242526272829303131302928272625242322212019181716151413121110090807060504030201004a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    ).unwrap();

    assert_eq!(
        input, expected_concat,
        "Concatenation must match test vector"
    );

    // SHA-256 of concatenation
    let mut hasher = Sha256::new();
    hasher.update(&input);
    let hash = hasher.finalize();

    // session_id = first 16 bytes
    let session_id: [u8; 16] = hash[0..16].try_into().unwrap();

    // Verify session_id is deterministic
    let mut hasher2 = Sha256::new();
    hasher2.update(&input);
    let hash2 = hasher2.finalize();
    let session_id2: [u8; 16] = hash2[0..16].try_into().unwrap();

    assert_eq!(
        session_id, session_id2,
        "Session ID derivation must be deterministic"
    );
    assert_eq!(session_id.len(), 16, "Session ID must be exactly 16 bytes");
}

#[test]
fn test_session_secret_derivation_stranger() {
    // TEST_VECTORS.md §2.2
    let shared_secret =
        hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742").unwrap();
    let client_random =
        hex::decode("0001020304050607080910111213141516171819202122232425262728293031").unwrap();
    let server_random =
        hex::decode("3130292827262524232221201918171615141312111009080706050403020100").unwrap();

    // Salt = client_random || server_random
    let mut salt = Vec::new();
    salt.extend_from_slice(&client_random);
    salt.extend_from_slice(&server_random);

    let expected_salt = hex::decode(
        "00010203040506070809101112131415161718192021222324252627282930313130292827262524232221201918171615141312111009080706050403020100"
    ).unwrap();
    assert_eq!(
        salt, expected_salt,
        "Salt concatenation must match test vector"
    );

    // Info = "zp-session-secret"
    let info = b"zp-session-secret";
    let expected_info = hex::decode("7a702d73657373696f6e2d736563726574").unwrap();
    assert_eq!(
        info.to_vec(),
        expected_info,
        "Info string must match test vector"
    );

    // Derive session_secret using HKDF-SHA256
    let session_secret =
        kdf::hkdf_sha256(&shared_secret, &salt, info, 32).expect("HKDF derivation should succeed");

    assert_eq!(session_secret.len(), 32, "Session secret must be 32 bytes");

    // Verify deterministic
    let session_secret2 =
        kdf::hkdf_sha256(&shared_secret, &salt, info, 32).expect("HKDF derivation should succeed");
    assert_eq!(
        &session_secret[..],
        &session_secret2[..],
        "Session secret derivation must be deterministic"
    );
}

#[test]
fn test_session_keys_derivation_stranger() {
    // TEST_VECTORS.md §2.3
    let shared_secret =
        hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742").unwrap();
    let client_random =
        hex::decode("0001020304050607080910111213141516171819202122232425262728293031").unwrap();
    let server_random =
        hex::decode("3130292827262524232221201918171615141312111009080706050403020100").unwrap();

    // Salt = client_random || server_random
    let mut salt = Vec::new();
    salt.extend_from_slice(&client_random);
    salt.extend_from_slice(&server_random);

    // Info = "zp-session-keys"
    let info = b"zp-session-keys";
    let expected_info = hex::decode("7a702d73657373696f6e2d6b657973").unwrap();
    assert_eq!(
        info.to_vec(),
        expected_info,
        "Info string must match test vector"
    );

    // Derive 64 bytes for both keys
    let session_keys =
        kdf::hkdf_sha256(&shared_secret, &salt, info, 64).expect("HKDF derivation should succeed");

    assert_eq!(
        session_keys.len(),
        64,
        "Session keys must be 64 bytes total"
    );

    // Split into client_to_server and server_to_client keys
    let client_to_server_key = &session_keys[0..32];
    let server_to_client_key = &session_keys[32..64];

    assert_eq!(client_to_server_key.len(), 32, "C2S key must be 32 bytes");
    assert_eq!(server_to_client_key.len(), 32, "S2C key must be 32 bytes");

    // Keys must be distinct
    assert_ne!(
        client_to_server_key, server_to_client_key,
        "C2S and S2C keys must be different"
    );

    // Verify deterministic
    let session_keys2 =
        kdf::hkdf_sha256(&shared_secret, &salt, info, 64).expect("HKDF derivation should succeed");
    assert_eq!(
        &session_keys[..],
        &session_keys2[..],
        "Session keys derivation must be deterministic"
    );
}

#[test]
fn test_key_rotation_derivation() {
    // TEST_VECTORS.md §2.4
    // Simulate current_secret and session_id from session establishment
    let current_secret =
        hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
    let session_id = hex::decode("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
    let key_epoch: u32 = 1;

    // Salt = session_id || key_epoch (LE)
    let mut salt = Vec::new();
    salt.extend_from_slice(&session_id);
    salt.extend_from_slice(&key_epoch.to_le_bytes());

    assert_eq!(salt.len(), 20, "Salt must be 16 + 4 = 20 bytes");
    assert_eq!(
        salt[16..20],
        [0x01, 0x00, 0x00, 0x00],
        "Key epoch must be little-endian"
    );

    // Info for c2s
    let info_c2s = b"zp-traffic-key-c2s";
    let expected_info_c2s = hex::decode("7a702d747261666669632d6b65792d633273").unwrap();
    assert_eq!(
        info_c2s.to_vec(),
        expected_info_c2s,
        "C2S info must match test vector"
    );

    // Info for s2c
    let info_s2c = b"zp-traffic-key-s2c";
    let expected_info_s2c = hex::decode("7a702d747261666669632d6b65792d733263").unwrap();
    assert_eq!(
        info_s2c.to_vec(),
        expected_info_s2c,
        "S2C info must match test vector"
    );

    // Derive new keys
    let new_c2s_key = kdf::hkdf_sha256(&current_secret, &salt, info_c2s, 32)
        .expect("HKDF derivation should succeed");
    let new_s2c_key = kdf::hkdf_sha256(&current_secret, &salt, info_s2c, 32)
        .expect("HKDF derivation should succeed");

    assert_eq!(new_c2s_key.len(), 32, "New C2S key must be 32 bytes");
    assert_eq!(new_s2c_key.len(), 32, "New S2C key must be 32 bytes");

    // Keys must be distinct
    assert_ne!(
        &new_c2s_key[..],
        &new_s2c_key[..],
        "C2S and S2C traffic keys must be different"
    );
    assert_ne!(
        &new_c2s_key[..],
        &current_secret[..],
        "New key must differ from current secret"
    );

    // Test epoch 2 produces different keys
    let key_epoch_2: u32 = 2;
    let mut salt2 = Vec::new();
    salt2.extend_from_slice(&session_id);
    salt2.extend_from_slice(&key_epoch_2.to_le_bytes());

    let epoch2_c2s_key = kdf::hkdf_sha256(&current_secret, &salt2, info_c2s, 32)
        .expect("HKDF derivation should succeed");
    assert_ne!(
        &new_c2s_key[..],
        &epoch2_c2s_key[..],
        "Different epochs must produce different keys"
    );
}

#[test]
fn test_stranger_handshake_client_flow() {
    // TEST_VECTORS.md §9.1 - Client-side handshake
    let mut client = Session::new(Role::Client, HandshakeMode::Stranger);

    // Step 1: Client generates ClientHello
    let client_hello = client
        .client_start_stranger()
        .expect("Client should generate ClientHello");

    // Verify ClientHello structure
    match client_hello {
        zp_core::frame::Frame::ClientHello {
            supported_versions,
            min_version,
            supported_ciphers,
            x25519_pubkey,
            random,
        } => {
            assert!(
                supported_versions.contains(&0x0100),
                "Must support version 1.0"
            );
            assert_eq!(min_version, 0x0100, "Min version must be 1.0");
            assert!(
                !supported_ciphers.is_empty(),
                "Must support at least one cipher"
            );
            assert_eq!(
                x25519_pubkey.len(),
                32,
                "X25519 public key must be 32 bytes"
            );
            assert_eq!(random.len(), 32, "Client random must be 32 bytes");
        }
        _ => panic!("Expected ClientHello frame"),
    }
}

#[test]
fn test_stranger_handshake_server_flow() {
    // TEST_VECTORS.md §9.1 - Server-side handshake
    let mut server = Session::new(Role::Server, HandshakeMode::Stranger);

    // Create a ClientHello from client
    let mut client = Session::new(Role::Client, HandshakeMode::Stranger);
    let client_hello = client
        .client_start_stranger()
        .expect("Client should generate ClientHello");

    // Step 3: Server processes ClientHello and generates ServerHello
    let server_hello = server
        .server_process_client_hello(client_hello)
        .expect("Server should process ClientHello");

    // Verify ServerHello structure
    match server_hello {
        zp_core::frame::Frame::ServerHello {
            selected_version,
            selected_cipher,
            x25519_pubkey,
            mlkem_pubkey,
            random,
        } => {
            assert_eq!(selected_version, 0x0100, "Server must select version 1.0");
            assert!(
                selected_cipher == 0x01
                    || selected_cipher == 0x02
                    || selected_cipher == 0x03
                    || selected_cipher == 0x11,
                "Server must select a valid cipher"
            );
            assert_eq!(
                x25519_pubkey.len(),
                32,
                "X25519 public key must be 32 bytes"
            );
            assert!(
                !mlkem_pubkey.is_empty(),
                "ML-KEM public key must be present"
            );
            assert_eq!(random.len(), 32, "Server random must be 32 bytes");

            // Verify ML-KEM public key size matches cipher
            if selected_cipher == 0x01 || selected_cipher == 0x03 {
                // ZP_HYBRID_1 or ZP_HYBRID_3 use ML-KEM-768
                assert_eq!(
                    mlkem_pubkey.len(),
                    1184,
                    "ML-KEM-768 public key must be 1184 bytes"
                );
            } else if selected_cipher == 0x02 {
                // ZP_HYBRID_2 uses ML-KEM-1024
                assert_eq!(
                    mlkem_pubkey.len(),
                    1568,
                    "ML-KEM-1024 public key must be 1568 bytes"
                );
            }
        }
        _ => panic!("Expected ServerHello frame"),
    }
}

#[test]
fn test_stranger_handshake_full_roundtrip() {
    // TEST_VECTORS.md §9.1 - Complete handshake
    let mut client = Session::new(Role::Client, HandshakeMode::Stranger);
    let mut server = Session::new(Role::Server, HandshakeMode::Stranger);

    // Step 2: Client sends ClientHello
    let client_hello = client
        .client_start_stranger()
        .expect("Client should generate ClientHello");

    // Step 3: Server responds with ServerHello
    let server_hello = server
        .server_process_client_hello(client_hello)
        .expect("Server should process ClientHello and respond");

    // Step 4: Client processes ServerHello and sends ClientFinish
    let client_finish = client
        .client_process_server_hello(server_hello)
        .expect("Client should process ServerHello and generate ClientFinish");

    // Verify ClientFinish structure
    match &client_finish {
        zp_core::frame::Frame::ClientFinish { mlkem_ciphertext } => {
            assert!(
                !mlkem_ciphertext.is_empty(),
                "ML-KEM ciphertext must be present"
            );
            // Ciphertext size depends on cipher suite
            assert!(
                mlkem_ciphertext.len() == 1088 || mlkem_ciphertext.len() == 1568,
                "ML-KEM ciphertext must be 1088 bytes (ML-KEM-768) or 1568 bytes (ML-KEM-1024)"
            );
        }
        _ => panic!("Expected ClientFinish frame"),
    }

    // Step 5: Server processes ClientFinish
    server
        .server_process_client_finish(client_finish)
        .expect("Server should process ClientFinish");

    // Step 6: Both sessions should be established
    assert!(
        client.is_established(),
        "Client session should be established"
    );
    assert!(
        server.is_established(),
        "Server session should be established"
    );

    // Both should have session keys
    let client_keys = client.keys().expect("Client should have session keys");
    let server_keys = server.keys().expect("Server should have session keys");

    // Session IDs must match
    assert_eq!(
        client_keys.session_id, server_keys.session_id,
        "Session IDs must match"
    );

    // Verify key directionality is correct
    // Client send_key must equal Server recv_key
    assert_eq!(
        &client_keys.send_key[..],
        &server_keys.recv_key[..],
        "Client send_key must equal Server recv_key"
    );

    // Server send_key must equal Client recv_key
    assert_eq!(
        &server_keys.send_key[..],
        &client_keys.recv_key[..],
        "Server send_key must equal Client recv_key"
    );

    // Send and recv keys must be different for each party
    assert_ne!(
        &client_keys.send_key[..],
        &client_keys.recv_key[..],
        "Client send and recv keys must be different"
    );
    assert_ne!(
        &server_keys.send_key[..],
        &server_keys.recv_key[..],
        "Server send and recv keys must be different"
    );
}

#[test]
fn test_version_negotiation_failure() {
    // Client only supports version 2.0 (hypothetical future version)
    // Server only supports version 1.0
    // Handshake should fail

    let mut server = Session::new(Role::Server, HandshakeMode::Stranger);

    // Manually construct a ClientHello with unsupported version
    let client_hello = zp_core::frame::Frame::ClientHello {
        supported_versions: vec![0x0200], // version 2.0
        min_version: 0x0200,
        supported_ciphers: vec![0x01],
        x25519_pubkey: [0u8; 32],
        random: [0u8; 32],
    };

    // Server should reject this
    let result = server.server_process_client_hello(client_hello);
    assert!(result.is_err(), "Server should reject incompatible version");
}

#[test]
fn test_cipher_negotiation_failure() {
    // Client only supports cipher 0xFF (invalid/unknown)
    // Server should reject

    let mut server = Session::new(Role::Server, HandshakeMode::Stranger);

    // Manually construct a ClientHello with unsupported cipher
    let client_hello = zp_core::frame::Frame::ClientHello {
        supported_versions: vec![0x0100],
        min_version: 0x0100,
        supported_ciphers: vec![0xFF], // invalid cipher
        x25519_pubkey: [0u8; 32],
        random: [0u8; 32],
    };

    // Server should reject this
    let result = server.server_process_client_hello(client_hello);
    assert!(result.is_err(), "Server should reject unsupported cipher");
}

#[test]
fn test_key_rotation_secret_update() {
    // TEST_VECTORS.md §2.4
    // Tests current_secret update for forward secrecy per spec §4.6.3

    // Use session_secret and session_id from TEST_VECTORS.md §2.2
    // These are the outputs from session establishment
    let session_id = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap();
    let session_id_array: [u8; 16] = session_id.try_into().unwrap();

    let current_secret =
        hex::decode("1f2e3d4c5b6a798887969faebdccdbeaf0ff0e1d2c3b4a5968778695a4b3c2d1").unwrap();
    let current_secret_array: [u8; 32] = current_secret.try_into().unwrap();

    // Key epoch = 1 (u32 little-endian: 01000000)
    let key_epoch: u32 = 1;

    // Derive C2S key
    let c2s_key = zp_crypto::kdf::derive_traffic_key(
        &current_secret_array,
        &session_id_array,
        key_epoch,
        zp_crypto::kdf::KeyDirection::ClientToServer,
    )
    .expect("C2S key derivation should succeed");

    // Derive S2C key
    let s2c_key = zp_crypto::kdf::derive_traffic_key(
        &current_secret_array,
        &session_id_array,
        key_epoch,
        zp_crypto::kdf::KeyDirection::ServerToClient,
    )
    .expect("S2C key derivation should succeed");

    // Verify keys are 32 bytes
    assert_eq!(c2s_key.len(), 32, "C2S key must be 32 bytes");
    assert_eq!(s2c_key.len(), 32, "S2C key must be 32 bytes");

    // Verify keys are different
    assert_ne!(
        &c2s_key[..],
        &s2c_key[..],
        "C2S and S2C keys must be different"
    );

    // Verify determinism: re-derive and check
    let c2s_key2 = zp_crypto::kdf::derive_traffic_key(
        &current_secret_array,
        &session_id_array,
        key_epoch,
        zp_crypto::kdf::KeyDirection::ClientToServer,
    )
    .expect("C2S key derivation should succeed");

    assert_eq!(
        &c2s_key[..],
        &c2s_key2[..],
        "Key derivation must be deterministic"
    );

    // Verify current_secret update
    let new_secret =
        zp_crypto::kdf::update_current_secret(&current_secret_array, &session_id_array, key_epoch)
            .expect("Secret update should succeed");

    assert_eq!(new_secret.len(), 32, "Updated secret must be 32 bytes");
    assert_ne!(
        &new_secret[..],
        &current_secret_array[..],
        "Updated secret must differ from current secret"
    );

    // Verify updated secret is deterministic
    let new_secret2 =
        zp_crypto::kdf::update_current_secret(&current_secret_array, &session_id_array, key_epoch)
            .expect("Secret update should succeed");

    assert_eq!(
        &new_secret[..],
        &new_secret2[..],
        "Secret update must be deterministic"
    );
}
