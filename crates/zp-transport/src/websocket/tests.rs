//! Unit tests for WebSocket transport.

use super::*;

#[tokio::test]
async fn test_websocket_endpoint_client_creation() {
    let client = WebSocketEndpoint::client();
    assert!(client.is_ok(), "Client endpoint creation should succeed");
}

#[tokio::test]
async fn test_websocket_endpoint_server_creation() {
    let server = WebSocketEndpoint::server("127.0.0.1:0").await;
    assert!(server.is_ok(), "Server endpoint creation should succeed");
}

#[tokio::test]
async fn test_websocket_connection_establishes() {
    // Start server
    let server = WebSocketEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Create client
    let client = WebSocketEndpoint::client().expect("Client creation failed");

    // Spawn server accept task
    let server_task = tokio::spawn(async move { server.accept().await });

    // Client connects
    let url = format!("ws://{}", addr);
    let client_conn = client
        .connect(&url)
        .await
        .expect("Client connection failed");

    // Server accepts
    let server_conn = server_task
        .await
        .expect("Server task panicked")
        .expect("Server accept failed");

    // Verify both connections have sessions
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
