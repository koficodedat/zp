//! WebSocket transport integration tests.
//!
//! Tests end-to-end scenarios involving multiple components:
//! - Bidirectional frame exchange
//! - Session state integration
//! - Subprotocol negotiation (zp.v1)
//! - Connection lifecycle
//! - Error handling

use zp_core::Frame;
use zp_transport::websocket::WebSocketEndpoint;

#[tokio::test]
async fn test_bidirectional_frame_exchange() {
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

        // Server sends a frame
        let test_frame = Frame::WindowUpdate {
            stream_id: 0,
            window_increment: 1024,
        };

        server_conn
            .send_frame(&test_frame)
            .await
            .expect("Server send failed");

        // Server receives a frame
        server_conn
            .recv_frame()
            .await
            .expect("Server recv failed")
            .expect("Should receive a frame")
    });

    // Client connects
    let url = format!("ws://{}", addr);
    let client_conn = client
        .connect(&url)
        .await
        .expect("Client connection failed");

    // Client receives frame from server
    let received_from_server = client_conn
        .recv_frame()
        .await
        .expect("Client recv failed")
        .expect("Should receive a frame");

    // Verify received frame
    assert!(
        matches!(received_from_server, Frame::WindowUpdate { .. }),
        "Should receive WindowUpdate from server"
    );

    // Client sends frame back
    let response_frame = Frame::WindowUpdate {
        stream_id: 0,
        window_increment: 2048,
    };

    client_conn
        .send_frame(&response_frame)
        .await
        .expect("Client send failed");

    // Get server results
    let received_by_server = server_task.await.expect("Server task panicked");

    // Verify bidirectional communication
    assert!(
        matches!(received_by_server, Frame::WindowUpdate { .. }),
        "Server should receive WindowUpdate from client"
    );
}

#[tokio::test]
async fn test_session_state_during_websocket_operations() {
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

        // Check session state
        let session_lock = server_conn.session();
        let session = session_lock.read().await;

        // Session should be in Stranger mode (TOFU)
        assert!(
            !session.is_established(),
            "Session should not be established yet"
        );

        drop(session);
        server_conn
    });

    // Client connects
    let url = format!("ws://{}", addr);
    let client_conn = client
        .connect(&url)
        .await
        .expect("Client connection failed");

    // Check client session state
    let client_session_lock = client_conn.session();
    let client_session = client_session_lock.read().await;

    assert!(
        !client_session.is_established(),
        "Client session should not be established yet"
    );

    drop(client_session);

    // Get server connection
    let _server_conn = server_task.await.expect("Server task panicked");
}

#[tokio::test]
async fn test_subprotocol_negotiation() {
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
    let client_conn = client.connect(&url).await;

    // Should succeed because client sends zp.v1 subprotocol header
    assert!(
        client_conn.is_ok(),
        "Connection should succeed with correct subprotocol"
    );

    // Clean up
    let _ = server_task.await;
}

#[tokio::test]
async fn test_connection_lifecycle() {
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

        // Server receives a frame
        let received = server_conn
            .recv_frame()
            .await
            .expect("Server recv failed")
            .expect("Should receive a frame");

        // Server closes connection
        server_conn.close().await.expect("Server close failed");

        received
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

    // Get server results
    let received_by_server = server_task.await.expect("Server task panicked");

    // Verify server received the frame
    assert!(
        matches!(received_by_server, Frame::WindowUpdate { .. }),
        "Server should receive WindowUpdate from client"
    );

    // Client should receive close (None)
    let close_result = client_conn.recv_frame().await;
    assert!(
        close_result.is_ok() && close_result.unwrap().is_none(),
        "Client should receive WebSocket close"
    );
}

#[tokio::test]
async fn test_multiple_frame_exchange() {
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

        // Server sends 5 frames
        for i in 0..5 {
            let frame = Frame::WindowUpdate {
                stream_id: 0,
                window_increment: 1024 * (i + 1),
            };
            server_conn
                .send_frame(&frame)
                .await
                .expect("Server send failed");
        }

        // Server receives 5 frames
        let mut received_frames = Vec::new();
        for _ in 0..5 {
            let frame = server_conn
                .recv_frame()
                .await
                .expect("Server recv failed")
                .expect("Should receive a frame");
            received_frames.push(frame);
        }

        received_frames
    });

    // Client connects
    let url = format!("ws://{}", addr);
    let client_conn = client
        .connect(&url)
        .await
        .expect("Client connection failed");

    // Client receives 5 frames from server
    let mut received_from_server = Vec::new();
    for _ in 0..5 {
        let frame = client_conn
            .recv_frame()
            .await
            .expect("Client recv failed")
            .expect("Should receive a frame");
        received_from_server.push(frame);
    }

    // Verify all frames received
    assert_eq!(
        received_from_server.len(),
        5,
        "Should receive 5 frames from server"
    );

    // Client sends 5 frames back
    for i in 0..5 {
        let frame = Frame::WindowUpdate {
            stream_id: 0,
            window_increment: 2048 * (i + 1),
        };
        client_conn
            .send_frame(&frame)
            .await
            .expect("Client send failed");
    }

    // Get server results
    let received_by_server = server_task.await.expect("Server task panicked");

    // Verify server received 5 frames
    assert_eq!(
        received_by_server.len(),
        5,
        "Server should receive 5 frames from client"
    );

    // Verify all are WindowUpdate frames
    for frame in received_by_server {
        assert!(
            matches!(frame, Frame::WindowUpdate { .. }),
            "All frames should be WindowUpdate"
        );
    }
}
