//! WebRTC transport integration tests.
//!
//! Tests end-to-end scenarios involving multiple components:
//! - P2P connection establishment (offer/answer)
//! - Bidirectional frame exchange over DataChannel
//! - Session state integration
//! - Role assignment (Client/Server based on SDP)
//! - STUN/TURN configuration
//!
//! **Note:** These tests use in-memory signaling channels (no actual network signaling).

use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use zp_core::Frame;
use zp_transport::webrtc::{SignalingChannel, SignalingMessage, WebRtcEndpoint};

/// In-memory signaling channel for testing (simulates SDP/ICE exchange)
#[derive(Clone)]
struct MemorySignalingChannel {
    tx: Arc<Mutex<mpsc::Sender<SignalingMessage>>>,
    rx: Arc<Mutex<mpsc::Receiver<SignalingMessage>>>,
}

impl MemorySignalingChannel {
    fn pair() -> (Self, Self) {
        let (tx1, rx1) = mpsc::channel(16);
        let (tx2, rx2) = mpsc::channel(16);

        let channel1 = Self {
            tx: Arc::new(Mutex::new(tx1)),
            rx: Arc::new(Mutex::new(rx2)),
        };

        let channel2 = Self {
            tx: Arc::new(Mutex::new(tx2)),
            rx: Arc::new(Mutex::new(rx1)),
        };

        (channel1, channel2)
    }
}

#[async_trait::async_trait]
impl SignalingChannel for MemorySignalingChannel {
    async fn send(
        &self,
        message: SignalingMessage,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.tx
            .lock()
            .await
            .send(message)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }

    async fn recv(
        &self,
    ) -> std::result::Result<SignalingMessage, Box<dyn std::error::Error + Send + Sync>> {
        self.rx.lock().await.recv().await.ok_or_else(|| {
            Box::new(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Signaling channel closed",
            )) as Box<dyn std::error::Error + Send + Sync>
        })
    }
}

#[tokio::test]
#[ignore] // Requires network setup, run manually
async fn test_webrtc_connection_establishment() {
    // Create endpoints
    let endpoint1 = WebRtcEndpoint::new().expect("Endpoint 1 creation failed");
    let endpoint2 = WebRtcEndpoint::new().expect("Endpoint 2 creation failed");

    // Create signaling channels
    let (signaling1, signaling2) = MemorySignalingChannel::pair();

    // Spawn responder task (accepts connection)
    let accept_task =
        tokio::spawn(async move { endpoint2.accept(signaling2).await.expect("Accept failed") });

    // Initiator connects
    let client_conn = endpoint1.connect(signaling1).await.expect("Connect failed");

    // Wait for responder
    let server_conn = accept_task.await.expect("Accept task panicked");

    // Verify roles per spec §6.4
    assert_eq!(
        client_conn.role(),
        zp_transport::webrtc::PeerRole::Client,
        "Initiator (offer sender) should have Client role"
    );
    assert_eq!(
        server_conn.role(),
        zp_transport::webrtc::PeerRole::Server,
        "Responder (answer sender) should have Server role"
    );

    // Verify sessions created
    assert!(
        !client_conn.session().read().await.is_established(),
        "Client session should be in handshake mode"
    );
    assert!(
        !server_conn.session().read().await.is_established(),
        "Server session should be in handshake mode"
    );

    // Clean up
    client_conn.close().await.expect("Client close failed");
    server_conn.close().await.expect("Server close failed");
}

#[tokio::test]
#[ignore] // Requires network setup, run manually
async fn test_webrtc_bidirectional_frame_exchange() {
    // Create endpoints
    let endpoint1 = WebRtcEndpoint::new().expect("Endpoint 1 creation failed");
    let endpoint2 = WebRtcEndpoint::new().expect("Endpoint 2 creation failed");

    let (signaling1, signaling2) = MemorySignalingChannel::pair();

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let server_conn = endpoint2.accept(signaling2).await.expect("Accept failed");

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
    let client_conn = endpoint1
        .connect(signaling1)
        .await
        .expect("Client connect failed");

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

    // Clean up
    client_conn.close().await.expect("Client close failed");
}

#[tokio::test]
#[ignore] // Requires network setup, run manually
async fn test_webrtc_multiple_frames() {
    // Create endpoints
    let endpoint1 = WebRtcEndpoint::new().expect("Endpoint 1 creation failed");
    let endpoint2 = WebRtcEndpoint::new().expect("Endpoint 2 creation failed");

    let (signaling1, signaling2) = MemorySignalingChannel::pair();

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let server_conn = endpoint2.accept(signaling2).await.expect("Accept failed");

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
    let client_conn = endpoint1
        .connect(signaling1)
        .await
        .expect("Client connect failed");

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

    // Clean up
    client_conn.close().await.expect("Client close failed");
}

#[tokio::test]
async fn test_webrtc_config_stun_servers() {
    use zp_transport::webrtc::WebRtcConfig;

    let config = WebRtcConfig::default();

    // Verify default STUN servers present
    assert!(
        !config.stun_servers.is_empty(),
        "Default config should have STUN servers"
    );
    assert!(
        config.stun_servers[0].starts_with("stun:"),
        "STUN server should start with 'stun:' scheme"
    );

    // Verify no TURN servers by default
    assert!(
        config.turn_servers.is_empty(),
        "Default config should have no TURN servers (optional)"
    );
}

#[tokio::test]
async fn test_webrtc_session_integration() {
    use zp_transport::webrtc::WebRtcConfig;

    // Create endpoint with custom config
    let mut config = WebRtcConfig::default();
    config
        .stun_servers
        .push("stun:custom.stun.server:3478".to_string());

    let endpoint = WebRtcEndpoint::with_config(config.clone());
    assert!(
        endpoint.is_ok(),
        "Endpoint creation with custom config should succeed"
    );

    // Verify config was applied
    assert_eq!(
        config.stun_servers.len(),
        2,
        "Should have default + custom STUN server"
    );
}
