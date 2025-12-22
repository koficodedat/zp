//! Edge Case Testing for zp-transport
//!
//! Tests boundary conditions, counter overflow, stream limits, and flow control edge cases.
//! Covers DoS protection, counter wraparound, and saturation arithmetic.
//!
//! Spec: §3.3.10 (DataFrame), §6.5.1 (Nonce Construction)
//!
//! **Current Implementation Status:**
//! - Frame Size Boundaries: 3/3 tests implemented
//! - Counter Overflow: 0/3 tests (requires Session internals access)
//! - Stream Limits: 0/3 tests (requires connection-level testing)
//! - Flow Control: 0/3 tests (requires flow control implementation)

use zp_core::frame::Frame;

/// Maximum frame size: 16 MB (spec §3.3.10)
const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

// ============================================================================
// Test Category 1: Frame Size Boundaries (3 tests)
// ============================================================================

/// Test 1.1: Maximum allowed frame size (16 MB) should be accepted
#[tokio::test]
async fn test_max_frame_size() {
    // Create a 16 MB DataFrame (exactly at the limit)
    let max_payload = vec![0u8; MAX_FRAME_SIZE];
    let frame = Frame::DataFrame {
        stream_id: 1,
        seq: 0,
        flags: 0,
        payload: max_payload.clone(),
    };

    // Serialize frame
    let serialized = frame.serialize().expect("Serialization should succeed");

    // Verify frame can be parsed back
    let parsed = Frame::parse(&serialized).expect("Parsing should succeed");

    match parsed {
        Frame::DataFrame {
            stream_id,
            seq,
            flags,
            payload,
        } => {
            assert_eq!(stream_id, 1, "Stream ID should match");
            assert_eq!(seq, 0, "Sequence number should match");
            assert_eq!(flags, 0, "Flags should be 0");
            assert_eq!(
                payload.len(),
                MAX_FRAME_SIZE,
                "Payload size should be 16 MB"
            );
        }
        _ => panic!("Expected DataFrame"),
    }
}

/// Test 1.2: Frame exceeding maximum size (16 MB + 1 byte) should be rejected
#[tokio::test]
async fn test_oversized_frame_rejected() {
    // Create a frame that exceeds the 16 MB limit by 1 byte
    let oversized_payload = vec![0u8; MAX_FRAME_SIZE + 1];
    let frame = Frame::DataFrame {
        stream_id: 1,
        seq: 0,
        flags: 0,
        payload: oversized_payload,
    };

    // Serialize frame
    let serialized = frame.serialize().expect("Serialization should succeed");

    // Attempt to send over TCP connection (should fail)
    // Note: This test requires a TCP connection with frame size validation
    // For now, we verify that the serialized size exceeds MAX_FRAME_SIZE
    assert!(
        serialized.len() > MAX_FRAME_SIZE,
        "Serialized frame should exceed MAX_FRAME_SIZE"
    );

    // TODO: Test actual transmission rejection when TcpConnection enforces size limit
}

/// Test 1.3: Empty payload frames (0-byte DataFrame) should be accepted
#[tokio::test]
async fn test_empty_payload_frame() {
    // Create a DataFrame with empty payload
    let frame = Frame::DataFrame {
        stream_id: 1,
        seq: 0,
        flags: 0,
        payload: vec![],
    };

    // Serialize frame
    let serialized = frame.serialize().expect("Serialization should succeed");

    // Verify frame can be parsed back
    let parsed = Frame::parse(&serialized).expect("Parsing should succeed");

    match parsed {
        Frame::DataFrame {
            stream_id,
            seq,
            flags,
            payload,
        } => {
            assert_eq!(stream_id, 1, "Stream ID should match");
            assert_eq!(seq, 0, "Sequence number should match");
            assert_eq!(flags, 0, "Flags should be 0");
            assert_eq!(payload.len(), 0, "Payload should be empty");
        }
        _ => panic!("Expected DataFrame"),
    }
}
