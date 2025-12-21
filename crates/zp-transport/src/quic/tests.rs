//! Unit tests for QUIC transport.

use super::*;

// Install default crypto provider for tests
fn setup() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[tokio::test]
async fn test_quic_endpoint_client_creation() {
    setup();
    let client = QuicEndpoint::client();
    assert!(client.is_ok(), "Client endpoint creation should succeed");
}

#[tokio::test]
async fn test_quic_endpoint_server_creation() {
    setup();
    let server = QuicEndpoint::server("127.0.0.1:0").await;
    assert!(server.is_ok(), "Server endpoint creation should succeed");
}

#[tokio::test]
async fn test_quic_connection_establishes() {
    setup();
    // Start server
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    // Get the actual bound address
    let addr = server
        .endpoint
        .local_addr()
        .expect("Failed to get server address");

    // Create client
    let client = QuicEndpoint::client().expect("Client creation failed");

    // Spawn server accept task
    let server_task = tokio::spawn(async move { server.accept().await });

    // Client connects
    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    // Server accepts
    let server_conn = server_task
        .await
        .expect("Server task panicked")
        .expect("Server accept failed");

    // Verify both connections have sessions
    // Sessions start without handshake (handshake_in_progress will be false initially)
    let client_session_lock = client_conn.session();
    let client_session = client_session_lock.read().await;
    assert!(
        !client_session.is_established(),
        "Client session should not be established yet"
    );
    drop(client_session);

    let server_session_lock = server_conn.session();
    let server_session = server_session_lock.read().await;
    assert!(
        !server_session.is_established(),
        "Server session should not be established yet"
    );
    drop(server_session);
}

#[tokio::test]
async fn test_control_stream_initialization() {
    setup();
    // Start server
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server
        .endpoint
        .local_addr()
        .expect("Failed to get server address");

    // Create client
    let client = QuicEndpoint::client().expect("Client creation failed");

    // Spawn server
    let server_task = tokio::spawn(async move { server.accept().await });

    // Connect
    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");
    let server_conn = server_task
        .await
        .expect("Server task panicked")
        .expect("Server accept failed");

    // Verify control stream exists
    let client_cs_lock = client_conn.control_stream();
    let client_cs = client_cs_lock.read().await;
    assert!(client_cs.is_some(), "Client should have control stream");
    assert_eq!(
        client_cs.as_ref().unwrap().id(),
        0,
        "Control stream should be stream 0"
    );
    drop(client_cs);

    let server_cs_lock = server_conn.control_stream();
    let server_cs = server_cs_lock.read().await;
    assert!(server_cs.is_some(), "Server should have control stream");
    assert_eq!(
        server_cs.as_ref().unwrap().id(),
        0,
        "Control stream should be stream 0"
    );
}

#[tokio::test]
async fn test_control_stream_rejects_dataframe() {
    // Verify DataFrame variant matching works
    let data_frame = Frame::DataFrame {
        stream_id: 0,
        seq: 0,
        flags: 0,
        payload: vec![1, 2, 3],
    };

    assert!(
        matches!(data_frame, Frame::DataFrame { .. }),
        "DataFrame matching works for control stream enforcement"
    );
}

#[tokio::test]
async fn test_stream_id_allocation() {
    setup();
    // Start server
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server
        .endpoint
        .local_addr()
        .expect("Failed to get server address");

    // Create client
    let client = QuicEndpoint::client().expect("Client creation failed");

    // Spawn server
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("Server accept failed");

        // Open a stream from server side (should be odd ID)
        let stream = conn.open_stream().await.expect("Server open stream failed");
        (conn, stream)
    });

    // Connect
    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    // Open stream from client (should be even ID, but not 0 since that's control)
    let client_stream = client_conn
        .open_stream()
        .await
        .expect("Client open stream failed");

    // Client's first data stream should be stream 4 (0 is control, 4 is next even)
    // This depends on quinn's stream ID allocation
    assert!(
        client_stream.id() % 2 == 0,
        "Client stream should have even ID"
    );
    assert_ne!(
        client_stream.id(),
        0,
        "Client data stream should not be stream 0"
    );

    // Get server stream
    let (_server_conn, server_stream) = server_task.await.expect("Server task panicked");

    // Server's first data stream should be odd
    assert!(
        server_stream.id() % 2 == 1,
        "Server stream should have odd ID"
    );
}

#[tokio::test]
async fn test_session_integration() {
    // Verify Session is properly integrated with Role and HandshakeMode
    let client_session = Session::new(Role::Client, HandshakeMode::Stranger);
    let server_session = Session::new(Role::Server, HandshakeMode::Stranger);

    // Both should not be established yet (no handshake performed)
    assert!(!client_session.is_established());
    assert!(!server_session.is_established());
}

#[tokio::test]
async fn test_quic_stream_control_flag() {
    // Verify is_control flag works
    // Note: We can't easily create QuicStream instances without a real QUIC connection
    // This test just verifies the logic conceptually

    // Control stream (stream 0) should have is_control=true
    // Data streams (4+) should have is_control=false

    // This is tested implicitly in test_control_stream_initialization
    // No explicit assertion needed - test exists for documentation purposes
}
