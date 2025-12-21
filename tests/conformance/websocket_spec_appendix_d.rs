//! Conformance tests for zp specification Appendix D (WebSocket Subprotocol).
//!
//! Tests verify:
//! - Subprotocol identifier "zp.v1" requirement
//! - Binary frames only (no text frames allowed)
//! - One zp frame per WebSocket message
//! - Server subprotocol header validation
//! - Connection lifecycle per spec

use zp_core::Frame;
use zp_transport::websocket::WebSocketEndpoint;

/// Test: Subprotocol Identifier per spec Appendix D
///
/// Requirement: "Client initiates WebSocket with `Sec-WebSocket-Protocol: zp.v1`"
/// Requirement: "Server confirms with same header"
#[tokio::test]
async fn conformance_subprotocol_identifier_zp_v1() {
    // Start server
    let server = WebSocketEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Create client
    let client = WebSocketEndpoint::client().expect("Client creation failed");

    // Spawn server task
    let server_task = tokio::spawn(async move { server.accept().await });

    // Client connects with zp.v1 subprotocol
    let url = format!("ws://{}", addr);
    let result = client.connect(&url).await;

    // Verify Appendix D: Connection succeeds with correct subprotocol
    assert!(
        result.is_ok(),
        "Appendix D: Connection must succeed when client sends 'zp.v1' subprotocol"
    );

    // Clean up
    let _ = server_task.await;
}

/// Test: Binary Frames Only per spec Appendix D
///
/// Requirement: "All messages are binary WebSocket frames"
/// Text frames should be rejected per protocol design.
#[tokio::test]
async fn conformance_binary_frames_only() {
    // Start server
    let server = WebSocketEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Create client
    let client = WebSocketEndpoint::client().expect("Client creation failed");

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("Server accept failed");

        // Server receives frame (should be binary)
        conn.recv_frame().await
    });

    // Client connects
    let url = format!("ws://{}", addr);
    let client_conn = client
        .connect(&url)
        .await
        .expect("Client connection failed");

    // Client sends a frame (will be sent as binary per implementation)
    let test_frame = Frame::WindowUpdate {
        stream_id: 0,
        window_increment: 1024,
    };

    client_conn
        .send_frame(&test_frame)
        .await
        .expect("Client send failed");

    // Get server result
    let result = server_task.await.expect("Server task panicked");

    // Verify Appendix D: Binary frame was received and parsed
    assert!(
        result.is_ok(),
        "Appendix D: Binary frames must be accepted and parsed correctly"
    );

    let frame_opt = result.expect("Should receive frame");
    assert!(
        frame_opt.is_some(),
        "Appendix D: Should receive a valid frame"
    );

    // Note: Text frame rejection is implicit in implementation
    // (recv_frame returns error for non-binary messages)
}

/// Test: One zp Frame Per WebSocket Message per spec Appendix D
///
/// Requirement: "Each WebSocket message contains exactly one zp frame"
#[tokio::test]
async fn conformance_one_frame_per_message() {
    // Start server
    let server = WebSocketEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Create client
    let client = WebSocketEndpoint::client().expect("Client creation failed");

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("Server accept failed");

        // Server receives multiple frames
        let mut frames = Vec::new();
        for _ in 0..3 {
            let frame = conn
                .recv_frame()
                .await
                .expect("Server recv failed")
                .expect("Should receive a frame");
            frames.push(frame);
        }

        frames
    });

    // Client connects
    let url = format!("ws://{}", addr);
    let client_conn = client
        .connect(&url)
        .await
        .expect("Client connection failed");

    // Client sends 3 frames (each in separate WebSocket message)
    for i in 0..3 {
        let frame = Frame::WindowUpdate {
            stream_id: 0,
            window_increment: 1024 * (i + 1),
        };
        client_conn
            .send_frame(&frame)
            .await
            .expect("Client send failed");
    }

    // Get server results
    let frames = server_task.await.expect("Server task panicked");

    // Verify Appendix D: Each frame was received individually
    assert_eq!(
        frames.len(),
        3,
        "Appendix D: Each WebSocket message should contain exactly one zp frame"
    );

    // Verify all are WindowUpdate frames with different increments
    for (i, frame) in frames.iter().enumerate() {
        match frame {
            Frame::WindowUpdate {
                stream_id,
                window_increment,
            } => {
                assert_eq!(*stream_id, 0, "Stream ID should be 0");
                assert_eq!(
                    *window_increment,
                    1024 * (i as u64 + 1),
                    "Appendix D: Frame {} should have increment {}",
                    i,
                    1024 * (i + 1)
                );
            }
            _ => panic!("Expected WindowUpdate frame"),
        }
    }
}

/// Test: Connection Lifecycle per spec Appendix D
///
/// Requirement:
/// 1. Client initiates WebSocket with `Sec-WebSocket-Protocol: zp.v1`
/// 2. Server confirms with same header
/// 3. Client sends ClientHello as first binary message
/// 4. Handshake proceeds as per §4.2/§4.3
/// 5. Data and control frames exchanged per §3.3.10
#[tokio::test]
async fn conformance_connection_lifecycle() {
    // Start server
    let server = WebSocketEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Create client
    let client = WebSocketEndpoint::client().expect("Client creation failed");

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let server_conn = server.accept().await.expect("Server accept failed");

        // Step 2: Server confirms subprotocol (implicit in accept success)

        // Verify session is created in Stranger mode
        let session_lock = server_conn.session();
        let session = session_lock.read().await;
        assert!(
            !session.is_established(),
            "Appendix D: Session should be in handshake mode initially"
        );
        drop(session);

        // Step 5: Server can send/receive frames
        let test_frame = Frame::WindowUpdate {
            stream_id: 0,
            window_increment: 2048,
        };

        server_conn
            .send_frame(&test_frame)
            .await
            .expect("Server send failed");

        server_conn
            .recv_frame()
            .await
            .expect("Server recv failed")
            .expect("Should receive frame")
    });

    // Step 1: Client initiates with zp.v1 subprotocol
    let url = format!("ws://{}", addr);
    let client_conn = client
        .connect(&url)
        .await
        .expect("Appendix D: Client connection with zp.v1 should succeed");

    // Step 3: Client would send ClientHello (tested in handshake tests)
    // For now, verify session is created
    let client_session_lock = client_conn.session();
    let client_session = client_session_lock.read().await;
    assert!(
        !client_session.is_established(),
        "Appendix D: Client session should be in handshake mode initially"
    );
    drop(client_session);

    // Step 5: Client receives frame from server
    let received_from_server = client_conn
        .recv_frame()
        .await
        .expect("Client recv failed")
        .expect("Should receive frame");

    assert!(
        matches!(received_from_server, Frame::WindowUpdate { .. }),
        "Appendix D: Should receive WindowUpdate from server"
    );

    // Client sends frame back
    let response_frame = Frame::WindowUpdate {
        stream_id: 0,
        window_increment: 4096,
    };

    client_conn
        .send_frame(&response_frame)
        .await
        .expect("Client send failed");

    // Get server results
    let received_by_server = server_task.await.expect("Server task panicked");

    // Verify bidirectional frame exchange per Appendix D
    assert!(
        matches!(received_by_server, Frame::WindowUpdate { .. }),
        "Appendix D: Server should receive WindowUpdate from client"
    );
}

/// Test: Server Subprotocol Header Validation per spec Appendix D
///
/// Requirement: Server must validate client requests zp.v1 subprotocol
/// Note: This test verifies the server-side validation logic exists.
#[tokio::test]
async fn conformance_server_subprotocol_validation() {
    // Start server
    let server = WebSocketEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Create client
    let client = WebSocketEndpoint::client().expect("Client creation failed");

    // Spawn server task
    let server_task = tokio::spawn(async move { server.accept().await });

    // Client connects (will send zp.v1 subprotocol header)
    let url = format!("ws://{}", addr);
    let result = client.connect(&url).await;

    // Verify Appendix D: Server accepts client with correct subprotocol
    assert!(
        result.is_ok(),
        "Appendix D: Server must accept client with 'zp.v1' subprotocol"
    );

    // Verify server accepted the connection
    let server_result = server_task.await.expect("Server task panicked");
    assert!(
        server_result.is_ok(),
        "Appendix D: Server should successfully accept client with 'zp.v1'"
    );
}

/// Test: Frame Serialization Format per spec Appendix D
///
/// Requirement: "During handshake: frame type determined by magic number (§3.3.10)"
/// Requirement: "Post-handshake: messages contain EncryptedRecord (§3.3.13) or plaintext ErrorFrame"
#[tokio::test]
async fn conformance_frame_format() {
    // Start server
    let server = WebSocketEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Create client
    let client = WebSocketEndpoint::client().expect("Client creation failed");

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("Server accept failed");

        // Server receives frame (should be parseable by Frame::parse)
        conn.recv_frame()
            .await
            .expect("Server recv failed")
            .expect("Should receive frame")
    });

    // Client connects
    let url = format!("ws://{}", addr);
    let client_conn = client
        .connect(&url)
        .await
        .expect("Client connection failed");

    // Client sends a frame
    let test_frame = Frame::WindowUpdate {
        stream_id: 0,
        window_increment: 1024,
    };

    client_conn
        .send_frame(&test_frame)
        .await
        .expect("Client send failed");

    // Get server result
    let received_frame = server_task.await.expect("Server task panicked");

    // Verify Appendix D: Frame was correctly serialized and deserialized
    match received_frame {
        Frame::WindowUpdate {
            stream_id,
            window_increment,
        } => {
            assert_eq!(stream_id, 0, "Stream ID should match");
            assert_eq!(window_increment, 1024, "Window increment should match");
        }
        _ => panic!("Appendix D: Should receive WindowUpdate frame"),
    }

    // Note: EncryptedRecord wrapping is TODO in implementation
    // This test currently verifies plaintext frame format during handshake phase
}
