//! Frame format conformance tests per spec §3.3.
//!
//! Verifies exact wire format compliance with the specification.

use zp_core::{
    frame::{
        AckRange, Frame, StreamState, StreamSyncStatus, MAGIC_ACK, MAGIC_CLIENT_FINISH,
        MAGIC_CLIENT_HELLO, MAGIC_DATA, MAGIC_ERROR, MAGIC_KEY_UPDATE, MAGIC_KNOWN_FINISH,
        MAGIC_KNOWN_HELLO, MAGIC_KNOWN_RESPONSE, MAGIC_SERVER_HELLO, MAGIC_SYNC,
        MAGIC_WINDOW_UPDATE,
    },
    ErrorCode,
};

/// Test ClientHello frame format per spec §4.2.1.
#[test]
fn test_client_hello_format() {
    let frame = Frame::ClientHello {
        supported_versions: vec![0x0100], // v1.0
        min_version: 0x0100,
        supported_ciphers: vec![0x01, 0x02], // ZP_HYBRID_1, ZP_HYBRID_2
        x25519_pubkey: [0x42; 32],
        random: [0x99; 32],
    };

    let bytes = frame.serialize().unwrap();

    // Verify magic number (4 bytes)
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        MAGIC_CLIENT_HELLO
    );

    // Verify frame type (1 byte)
    assert_eq!(bytes[4], 0x50); // TYPE_CLIENT_HELLO

    // Total size: 4 (magic) + 1 (type) + 1 (version_count) + 2 (version) + 2 (min_version)
    //            + 1 (cipher_count) + 2 (ciphers) + 32 (x25519) + 32 (random) = 77 bytes
    assert_eq!(bytes.len(), 77);

    // Roundtrip
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed, frame);
}

/// Test ServerHello frame format per spec §4.2.2.
#[test]
fn test_server_hello_format() {
    let mlkem768_pubkey = vec![0xAB; 1184]; // ML-KEM-768 public key size

    let frame = Frame::ServerHello {
        selected_version: 0x0100,
        selected_cipher: 0x01, // ZP_HYBRID_1
        x25519_pubkey: [0x33; 32],
        mlkem_pubkey: mlkem768_pubkey.clone(),
        random: [0x77; 32],
    };

    let bytes = frame.serialize().unwrap();

    // Verify magic number
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        MAGIC_SERVER_HELLO
    );

    // Verify frame type
    assert_eq!(bytes[4], 0x51); // TYPE_SERVER_HELLO

    // Size: 4 (magic) + 1 (type) + 2 (version) + 1 (cipher) + 32 (x25519)
    //      + 2 (mlkem_len) + 1184 (mlkem) + 32 (random) = 1258 bytes
    assert_eq!(bytes.len(), 1258);

    // Roundtrip
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed, frame);
}

/// Test ClientFinish frame format per spec §4.2.3.
#[test]
fn test_client_finish_format() {
    let mlkem768_ciphertext = vec![0xCD; 1088]; // ML-KEM-768 ciphertext size

    let frame = Frame::ClientFinish {
        mlkem_ciphertext: mlkem768_ciphertext.clone(),
    };

    let bytes = frame.serialize().unwrap();

    // Verify magic number
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        MAGIC_CLIENT_FINISH
    );

    // Verify frame type
    assert_eq!(bytes[4], 0x52); // TYPE_CLIENT_FINISH

    // Size: 4 (magic) + 1 (type) + 2 (ct_len) + 1088 (ciphertext) = 1095 bytes
    assert_eq!(bytes.len(), 1095);

    // Roundtrip
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed, frame);
}

/// Test KnownHello frame format per spec §4.3.1.
#[test]
fn test_known_hello_format() {
    // NOTE: Using placeholder OPAQUE CredentialRequest per DA-0001
    // TODO: Replace with actual OPAQUE message from test vectors
    let opaque_request = vec![0x11; 64]; // Placeholder for OPAQUE CredentialRequest

    let frame = Frame::KnownHello {
        supported_versions: vec![0x0100],
        min_version: 0x0100,
        supported_ciphers: vec![0x01],
        opaque_credential_request: opaque_request,
        random: [0x22; 32],
    };

    let bytes = frame.serialize().unwrap();

    // Verify magic number
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        MAGIC_KNOWN_HELLO
    );

    // Verify frame type
    assert_eq!(bytes[4], 0x53); // TYPE_KNOWN_HELLO

    // Roundtrip
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed, frame);
}

/// Test KnownResponse frame format per spec §4.3.2.
#[test]
fn test_known_response_format() {
    // NOTE: Using placeholder OPAQUE CredentialResponse per DA-0001
    // TODO: Replace with actual OPAQUE message from test vectors
    let opaque_response = vec![0x44; 128]; // Placeholder for OPAQUE CredentialResponse
    let mlkem_encrypted = vec![0xEF; 1200]; // Encrypted ML-KEM-768 pubkey

    let frame = Frame::KnownResponse {
        selected_version: 0x0100,
        selected_cipher: 0x01,
        opaque_credential_response: opaque_response,
        random: [0x55; 32],
        mlkem_pubkey_encrypted: mlkem_encrypted,
    };

    let bytes = frame.serialize().unwrap();

    // Verify magic number
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        MAGIC_KNOWN_RESPONSE
    );

    // Verify frame type
    assert_eq!(bytes[4], 0x54); // TYPE_KNOWN_RESPONSE

    // Roundtrip
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed, frame);
}

/// Test KnownFinish frame format per spec §4.3.3.
#[test]
fn test_known_finish_format() {
    // NOTE: Using placeholder OPAQUE CredentialFinalization per DA-0001
    // TODO: Replace with actual OPAQUE message from test vectors
    let opaque_finalization = vec![0xCC; 96]; // Placeholder for OPAQUE CredentialFinalization
    let mlkem_ct_encrypted = vec![0xF0; 1104]; // Encrypted ML-KEM-768 ciphertext

    let frame = Frame::KnownFinish {
        opaque_credential_finalization: opaque_finalization,
        mlkem_ciphertext_encrypted: mlkem_ct_encrypted,
    };

    let bytes = frame.serialize().unwrap();

    // Verify magic number
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        MAGIC_KNOWN_FINISH
    );

    // Verify frame type
    assert_eq!(bytes[4], 0x55); // TYPE_KNOWN_FINISH

    // Roundtrip
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed, frame);
}

/// Test Sync-Frame format per spec §3.3.5.
/// Verifies exact byte layout: 28 bytes per stream + 24 byte header.
#[test]
fn test_sync_frame_format() {
    let stream1 = StreamState {
        stream_id: 4,
        global_seq: 1000,
        last_acked: 500,
    };
    let stream2 = StreamState {
        stream_id: 8,
        global_seq: 2000,
        last_acked: 1500,
    };

    let frame = Frame::SyncFrame {
        session_id: [0xAA; 16],
        streams: vec![stream1.clone(), stream2.clone()],
        flags: 0x01, // URGENT flag
    };

    let bytes = frame.serialize().unwrap();

    // Verify magic number
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        MAGIC_SYNC
    );

    // Verify frame type
    assert_eq!(bytes[4], 0x01); // TYPE_SYNC

    // Size: 4 (magic) + 1 (type) + 16 (session_id) + 2 (stream_count) + 1 (flags)
    //      + 2 * (4 + 8 + 8 + 8) = 24 + 56 = 80 bytes
    assert_eq!(bytes.len(), 80);

    // Verify stream count (little-endian)
    assert_eq!(u16::from_le_bytes(bytes[21..23].try_into().unwrap()), 2);

    // Verify flags
    assert_eq!(bytes[23], 0x01);

    // Verify first stream integrity hash is present
    // Offset: 24 (header) + 4 (stream_id) + 8 (global_seq) + 8 (last_acked) = 44
    let integrity1 = stream1.compute_integrity();
    let integrity1_wire = u64::from_le_bytes(bytes[44..52].try_into().unwrap());
    assert_eq!(integrity1_wire, integrity1);

    // Roundtrip
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed, frame);
}

/// Test Sync-Ack format per spec §3.3.6.
/// Verifies exact byte layout: 21 bytes per stream + 8 byte header.
#[test]
fn test_sync_ack_format() {
    let status1 = StreamSyncStatus {
        stream_id: 4,
        stream_status: 0x00, // OK
        receiver_last_acked: 500,
        receiver_seq: 1000,
    };

    let frame = Frame::SyncAck {
        streams: vec![status1],
        status: 0x00, // OK
    };

    let bytes = frame.serialize().unwrap();

    // Verify magic number
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        MAGIC_SYNC
    );

    // Verify frame type
    assert_eq!(bytes[4], 0x02); // TYPE_SYNC_ACK

    // Size: 4 (magic) + 1 (type) + 2 (stream_count) + 1 (status)
    //      + 1 * (4 + 1 + 8 + 8) = 8 + 21 = 29 bytes
    assert_eq!(bytes.len(), 29);

    // Verify stream count
    assert_eq!(u16::from_le_bytes(bytes[5..7].try_into().unwrap()), 1);

    // Verify status
    assert_eq!(bytes[7], 0x00);

    // Roundtrip
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed, frame);
}

/// Test KeyUpdate frame format per spec §4.6.2.
#[test]
fn test_key_update_format() {
    let frame = Frame::KeyUpdate {
        key_epoch: 5,
        direction: 0, // client-to-server
    };

    let bytes = frame.serialize().unwrap();

    // Verify magic number
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        MAGIC_KEY_UPDATE
    );

    // Verify frame type
    assert_eq!(bytes[4], 0x10); // TYPE_KEY_UPDATE

    // Size: 4 (magic) + 1 (type) + 4 (epoch) + 1 (direction) + 6 (reserved) = 16 bytes
    assert_eq!(bytes.len(), 16);

    // Roundtrip
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed, frame);
}

/// Test KeyUpdateAck frame format per spec §4.6.5.
#[test]
fn test_key_update_ack_format() {
    let frame = Frame::KeyUpdateAck { acked_epoch: 5 };

    let bytes = frame.serialize().unwrap();

    // Verify magic number
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        MAGIC_KEY_UPDATE
    );

    // Verify frame type
    assert_eq!(bytes[4], 0x11); // TYPE_KEY_UPDATE_ACK

    // Size: 4 (magic) + 1 (type) + 4 (epoch) = 9 bytes
    assert_eq!(bytes.len(), 9);

    // Roundtrip
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed, frame);
}

/// Test AckFrame format per spec §6.4.4.
#[test]
fn test_ack_frame_format() {
    let range1 = AckRange {
        start_seq: 100,
        end_seq: 200,
    };
    let range2 = AckRange {
        start_seq: 300,
        end_seq: 400,
    };

    let frame = Frame::AckFrame {
        stream_id: 4,
        ack_ranges: vec![range1, range2],
    };

    let bytes = frame.serialize().unwrap();

    // Verify magic number
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        MAGIC_ACK
    );

    // Verify frame type
    assert_eq!(bytes[4], 0x20); // TYPE_ACK

    // Size: 4 (magic) + 1 (type) + 4 (stream_id) + 1 (range_count)
    //      + 2 * (8 + 8) = 10 + 32 = 42 bytes
    assert_eq!(bytes.len(), 42);

    // Roundtrip
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed, frame);
}

/// Test WindowUpdate frame format per spec §3.3.9.
/// Verifies exact 17-byte size.
#[test]
fn test_window_update_format() {
    let frame = Frame::WindowUpdate {
        stream_id: 0, // connection-level
        window_increment: 1_048_576,
    };

    let bytes = frame.serialize().unwrap();

    // Verify magic number
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        MAGIC_WINDOW_UPDATE
    );

    // Verify frame type
    assert_eq!(bytes[4], 0x30); // TYPE_WINDOW_UPDATE

    // Verify exact size per spec: 17 bytes
    assert_eq!(bytes.len(), 17);

    // Verify stream_id is 0 (connection-level)
    assert_eq!(u32::from_le_bytes(bytes[5..9].try_into().unwrap()), 0);

    // Verify window increment
    assert_eq!(
        u64::from_le_bytes(bytes[9..17].try_into().unwrap()),
        1_048_576
    );

    // Roundtrip
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed, frame);
}

/// Test ErrorFrame format per spec §3.3.12.
/// Verifies exact 9-byte size.
#[test]
fn test_error_frame_format() {
    let frame = Frame::ErrorFrame {
        error_code: ErrorCode::HandshakeTimeout,
    };

    let bytes = frame.serialize().unwrap();

    // Verify magic number
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        MAGIC_ERROR
    );

    // Verify frame type
    assert_eq!(bytes[4], 0x60); // TYPE_ERROR

    // Verify exact size per spec: 9 bytes
    assert_eq!(bytes.len(), 9);

    // Verify error code
    assert_eq!(bytes[5], 0x01); // HandshakeTimeout = 0x01

    // Verify reserved bytes are zero
    assert_eq!(bytes[6], 0);
    assert_eq!(bytes[7], 0);
    assert_eq!(bytes[8], 0);

    // Roundtrip
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed, frame);
}

/// Test DataFrame format per spec §3.3.10.
/// Verifies 22-byte header + payload.
#[test]
fn test_data_frame_format() {
    let payload = vec![0x42; 100];

    let frame = Frame::DataFrame {
        stream_id: 4,
        seq: 1000,
        flags: 0x00, // No FIN
        payload: payload.clone(),
    };

    let bytes = frame.serialize().unwrap();

    // Verify magic number
    assert_eq!(
        u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
        MAGIC_DATA
    );

    // Verify frame type
    assert_eq!(bytes[4], 0x40); // TYPE_DATA

    // Size: 4 (magic) + 1 (type) + 4 (stream_id) + 8 (seq) + 1 (flags)
    //      + 4 (length) + 100 (payload) = 122 bytes
    assert_eq!(bytes.len(), 122);

    // Verify stream_id
    assert_eq!(u32::from_le_bytes(bytes[5..9].try_into().unwrap()), 4);

    // Verify seq
    assert_eq!(u64::from_le_bytes(bytes[9..17].try_into().unwrap()), 1000);

    // Verify flags
    assert_eq!(bytes[17], 0x00);

    // Verify payload length
    assert_eq!(u32::from_le_bytes(bytes[18..22].try_into().unwrap()), 100);

    // Roundtrip
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed, frame);
}

/// Test DataFrame with FIN flag per spec §3.3.11.
#[test]
fn test_data_frame_with_fin() {
    let frame = Frame::DataFrame {
        stream_id: 8,
        seq: 500,
        flags: 0x01, // FIN flag
        payload: vec![],
    };

    let bytes = frame.serialize().unwrap();

    // Verify FIN flag is set
    assert_eq!(bytes[17] & 0x01, 0x01);

    // Roundtrip
    let parsed = Frame::parse(&bytes).unwrap();
    assert_eq!(parsed, frame);
}

/// Test XXH64 integrity hash per spec §3.3.5.
#[test]
fn test_stream_state_integrity_hash() {
    let state = StreamState {
        stream_id: 0x12345678,
        global_seq: 0xABCDEF0123456789,
        last_acked: 0x0011223344556677,
    };

    // Compute integrity hash
    let integrity = state.compute_integrity();

    // Verify it's deterministic
    assert_eq!(state.compute_integrity(), integrity);

    // Verify different data produces different hash
    let state2 = StreamState {
        stream_id: 0x12345678,
        global_seq: 0xABCDEF0123456789,
        last_acked: 0x0011223344556678, // Different by 1
    };
    assert_ne!(state2.compute_integrity(), integrity);
}

/// Test all error codes roundtrip per spec Appendix B.
#[test]
fn test_error_codes_conformance() {
    let error_codes = vec![
        (ErrorCode::HandshakeTimeout, 0x01),
        (ErrorCode::CipherDowngrade, 0x02),
        (ErrorCode::MigrationFailed, 0x03),
        (ErrorCode::TokenExpired, 0x04),
        (ErrorCode::TeeAttestation, 0x05),
        (ErrorCode::RelayUnavailable, 0x06),
        (ErrorCode::VersionMismatch, 0x07),
        (ErrorCode::RateLimited, 0x08),
        (ErrorCode::TokenIpMismatch, 0x09),
        (ErrorCode::StreamLimit, 0x0A),
        (ErrorCode::RekeyFailed, 0x0B),
        (ErrorCode::SyncRejected, 0x0C),
        (ErrorCode::FlowStall, 0x0D),
        (ErrorCode::ProtocolViolation, 0x0E),
    ];

    for (code, expected_u8) in error_codes {
        // Test to_u8
        assert_eq!(code.to_u8(), expected_u8);

        // Test from_u8 roundtrip
        assert_eq!(ErrorCode::from_u8(expected_u8), Some(code));
    }

    // Test invalid error code
    assert_eq!(ErrorCode::from_u8(0xFF), None);
}

/// Test little-endian byte order per spec §3.3.
#[test]
fn test_little_endian_encoding() {
    let frame = Frame::WindowUpdate {
        stream_id: 0x12345678,
        window_increment: 0xABCDEF0123456789,
    };

    let bytes = frame.serialize().unwrap();

    // Verify stream_id is little-endian
    assert_eq!(bytes[5], 0x78);
    assert_eq!(bytes[6], 0x56);
    assert_eq!(bytes[7], 0x34);
    assert_eq!(bytes[8], 0x12);

    // Verify window_increment is little-endian
    assert_eq!(bytes[9], 0x89);
    assert_eq!(bytes[10], 0x67);
    assert_eq!(bytes[11], 0x45);
    assert_eq!(bytes[12], 0x23);
    assert_eq!(bytes[13], 0x01);
    assert_eq!(bytes[14], 0xEF);
    assert_eq!(bytes[15], 0xCD);
    assert_eq!(bytes[16], 0xAB);
}
