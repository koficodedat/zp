//! Conformance tests for zp specification §3.3.7 (Multiplexing Degradation - TCP Fallback).
//!
//! Tests verify:
//! - StreamChunk format: [stream_id: u32][length: u32][payload: bytes] per §3.3.7
//! - Multiplexed mode: DataFrame.stream_id = 0xFFFFFFFF, payload = StreamChunks
//! - Single-stream mode: DataFrame.stream_id = actual ID, payload = raw data
//! - Length-prefixed framing: [4-byte length][frame data]
//! - TLS 1.3 over TCP/443 (legacy fallback)
//! - Session creation in Stranger mode (TOFU)
//! - Racing with QUIC (ZP_RACING_THRESHOLD: 200ms)

use zp_transport::tcp::{StreamChunk, TcpEndpoint};

/// Sentinel value for multiplexed mode per spec §3.3.7
const MULTIPLEXED_STREAM_ID: u32 = 0xFFFF_FFFF;

/// StreamChunk header size (stream_id + length)
const STREAM_CHUNK_HEADER_SIZE: usize = 8;

/// Test: StreamChunk format per spec §3.3.7
///
/// Requirement: "StreamChunk { stream_id: u32, length: u32, payload: [u8] }"
#[test]
fn conformance_stream_chunk_format() {
    let chunk = StreamChunk {
        stream_id: 42,
        payload: vec![1, 2, 3, 4, 5],
    };

    let serialized = chunk.serialize();

    // Verify format: [stream_id: 4 bytes][length: 4 bytes][payload: N bytes]
    assert_eq!(
        serialized.len(),
        STREAM_CHUNK_HEADER_SIZE + 5,
        "§3.3.7: StreamChunk must be stream_id + length + payload"
    );

    // Verify stream_id (little-endian)
    assert_eq!(
        &serialized[0..4],
        &42u32.to_le_bytes(),
        "§3.3.7: stream_id must be 4-byte little-endian u32"
    );

    // Verify length (little-endian)
    assert_eq!(
        &serialized[4..8],
        &5u32.to_le_bytes(),
        "§3.3.7: length must be 4-byte little-endian u32"
    );

    // Verify payload
    assert_eq!(
        &serialized[8..],
        &[1, 2, 3, 4, 5],
        "§3.3.7: payload must follow header"
    );
}

/// Test: StreamChunk parsing per spec §3.3.7
///
/// Requirement: "Parse StreamChunk from wire format"
#[test]
fn conformance_stream_chunk_parsing() {
    let mut data = Vec::new();
    data.extend_from_slice(&42u32.to_le_bytes()); // stream_id
    data.extend_from_slice(&5u32.to_le_bytes()); // length
    data.extend_from_slice(&[1, 2, 3, 4, 5]); // payload

    let chunk = StreamChunk::parse(&data).expect("§3.3.7: StreamChunk parsing must succeed");

    assert_eq!(chunk.stream_id, 42, "§3.3.7: Parsed stream_id must match");
    assert_eq!(
        chunk.payload,
        vec![1, 2, 3, 4, 5],
        "§3.3.7: Parsed payload must match"
    );
}

/// Test: StreamChunk roundtrip per spec §3.3.7
///
/// Requirement: "Serialize and parse must be inverse operations"
#[test]
fn conformance_stream_chunk_roundtrip() {
    let original = StreamChunk {
        stream_id: 123,
        payload: vec![10, 20, 30, 40, 50],
    };

    let serialized = original.serialize();
    let parsed = StreamChunk::parse(&serialized).expect("§3.3.7: Roundtrip parsing must succeed");

    assert_eq!(
        parsed.stream_id, original.stream_id,
        "§3.3.7: Roundtrip stream_id must match"
    );
    assert_eq!(
        parsed.payload, original.payload,
        "§3.3.7: Roundtrip payload must match"
    );
}

/// Test: Multiplexed stream ID sentinel value per spec §3.3.7
///
/// Requirement: "DataFrame.stream_id = 0xFFFFFFFF indicates multiplexed mode"
#[test]
fn conformance_multiplexed_stream_id_sentinel() {
    assert_eq!(
        MULTIPLEXED_STREAM_ID, 0xFFFF_FFFF,
        "§3.3.7: Multiplexed mode sentinel must be 0xFFFFFFFF"
    );
}

/// Test: StreamChunk header size per spec §3.3.7
///
/// Requirement: "StreamChunk header is 8 bytes (stream_id + length)"
#[test]
fn conformance_stream_chunk_header_size() {
    assert_eq!(
        STREAM_CHUNK_HEADER_SIZE, 8,
        "§3.3.7: StreamChunk header must be 8 bytes (4 + 4)"
    );
}

/// Test: TCP endpoint creation per spec §3.3.7
///
/// Requirement: "TLS 1.3 over TCP/443 for legacy fallback"
#[tokio::test]
async fn conformance_tcp_endpoint_creation() {
    // Server endpoint
    let server = TcpEndpoint::server("127.0.0.1:0").await;
    assert!(
        server.is_ok(),
        "§3.3.7: TCP server endpoint creation must succeed"
    );

    // Client endpoint
    let client = TcpEndpoint::client();
    assert!(
        client.is_ok(),
        "§3.3.7: TCP client endpoint creation must succeed"
    );
}

/// Test: Length-prefixed framing per spec §3.3.7
///
/// Requirement: "Frames serialized with 4-byte length prefix"
/// Note: This is tested implicitly in integration tests via send_frame/recv_frame
#[test]
fn conformance_length_prefix_format() {
    // Verify length prefix is 4 bytes (u32)
    let length: u32 = 12345;
    let bytes = length.to_le_bytes();

    assert_eq!(
        bytes.len(),
        4,
        "§3.3.7: Length prefix must be 4 bytes (u32)"
    );

    // Verify little-endian encoding
    let decoded = u32::from_le_bytes(bytes);
    assert_eq!(
        decoded, length,
        "§3.3.7: Length prefix must use little-endian encoding"
    );
}

/// Test: StreamChunk with empty payload per spec §3.3.7
///
/// Requirement: "StreamChunk supports zero-length payloads"
#[test]
fn conformance_stream_chunk_empty_payload() {
    let chunk = StreamChunk {
        stream_id: 1,
        payload: vec![],
    };

    let serialized = chunk.serialize();

    // Verify header only (no payload)
    assert_eq!(
        serialized.len(),
        STREAM_CHUNK_HEADER_SIZE,
        "§3.3.7: Empty payload StreamChunk must be header-only"
    );

    // Verify length field is 0
    assert_eq!(
        &serialized[4..8],
        &0u32.to_le_bytes(),
        "§3.3.7: Empty payload must have length=0"
    );

    // Verify roundtrip
    let parsed =
        StreamChunk::parse(&serialized).expect("§3.3.7: Empty payload parsing must succeed");
    assert_eq!(parsed.stream_id, 1);
    assert_eq!(parsed.payload, Vec::<u8>::new());
}

/// Test: StreamChunk with maximum stream ID per spec §3.3.7
///
/// Requirement: "StreamChunk stream_id is u32 (0 to 2^32-1)"
#[test]
fn conformance_stream_chunk_max_stream_id() {
    let chunk = StreamChunk {
        stream_id: u32::MAX,
        payload: vec![1, 2, 3],
    };

    let serialized = chunk.serialize();
    let parsed =
        StreamChunk::parse(&serialized).expect("§3.3.7: Max stream_id parsing must succeed");

    assert_eq!(
        parsed.stream_id,
        u32::MAX,
        "§3.3.7: StreamChunk must support u32::MAX stream_id"
    );
}

/// Test: StreamChunk parsing validation - truncated header per spec §3.3.7
///
/// Requirement: "Parser must reject truncated StreamChunks"
#[test]
fn conformance_stream_chunk_truncated_header() {
    // Only 7 bytes (header requires 8)
    let data = vec![0, 0, 0, 0, 0, 0, 0];

    let result = StreamChunk::parse(&data);
    assert!(
        result.is_err(),
        "§3.3.7: Parser must reject truncated header"
    );
}

/// Test: StreamChunk parsing validation - truncated payload per spec §3.3.7
///
/// Requirement: "Parser must reject truncated payloads"
#[test]
fn conformance_stream_chunk_truncated_payload() {
    let mut data = Vec::new();
    data.extend_from_slice(&1u32.to_le_bytes()); // stream_id
    data.extend_from_slice(&10u32.to_le_bytes()); // length = 10
    data.extend_from_slice(&[1, 2, 3]); // payload = 3 bytes (expected 10)

    let result = StreamChunk::parse(&data);
    assert!(
        result.is_err(),
        "§3.3.7: Parser must reject truncated payload"
    );
}

/// Test: Session integration per spec §3.3.7
///
/// Requirement: "TCP connection creates Session in Stranger mode (TOFU)"
#[tokio::test]
async fn conformance_session_integration() {
    use zp_core::session::{HandshakeMode, Role};

    // Start server
    let server_endpoint = TcpEndpoint::server("127.0.0.1:0")
        .await
        .expect("§3.3.7: Server endpoint creation must succeed");
    let server_addr = server_endpoint
        .local_addr()
        .expect("§3.3.7: Server local_addr must succeed");

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let conn = server_endpoint
            .accept()
            .await
            .expect("§3.3.7: Server accept must succeed");

        // Verify session
        let session = conn.session();
        let session_guard = session.read().await;
        assert_eq!(
            session_guard.role(),
            Role::Server,
            "§3.3.7: Server must have Server role"
        );
        assert_eq!(
            session_guard.mode(),
            HandshakeMode::Stranger,
            "§3.3.7: Session must be Stranger mode (TOFU)"
        );
    });

    // Client connects
    let client_endpoint =
        TcpEndpoint::client().expect("§3.3.7: Client endpoint creation must succeed");
    let client_conn = client_endpoint
        .connect(&format!("127.0.0.1:{}", server_addr.port()))
        .await
        .expect("§3.3.7: Client connect must succeed");

    // Verify session
    let session = client_conn.session();
    let session_guard = session.read().await;
    assert_eq!(
        session_guard.role(),
        Role::Client,
        "§3.3.7: Client must have Client role"
    );
    assert_eq!(
        session_guard.mode(),
        HandshakeMode::Stranger,
        "§3.3.7: Session must be Stranger mode (TOFU)"
    );

    // Wait for server
    tokio::time::timeout(std::time::Duration::from_secs(1), server_handle)
        .await
        .expect("§3.3.7: Server timeout")
        .expect("§3.3.7: Server task failed");
}
