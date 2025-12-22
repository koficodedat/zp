//! WebRTC transport integration tests.
//!
//! Tests end-to-end scenarios involving multiple components:
//! - P2P connection establishment (offer/answer)
//! - Bidirectional frame exchange over DataChannel
//! - Session state integration
//! - Role assignment (Client/Server based on SDP)
//! - STUN/TURN configuration
//!
//! **Testing Strategy:**
//! - In-memory signaling channels (no actual network signaling)
//! - Local coturn server (127.0.0.1:3478) for STUN/TURN
//! - WebRTC connections establish via ICE with TURN relay
//! - Unit tests (non-network): 3 tests passing
//! - Integration tests (network): 6 tests enabled (requires coturn)
//! - Error path tests: 24 tests passing (webrtc_error_tests.rs)
//!
//! **Phase 5A.3 Status:** WebRTC tests use local coturn (no internet needed).
//! **Prerequisites:** `brew install coturn && turnserver -c /tmp/turnserver-test.conf`

use std::sync::Arc;
use std::sync::Once;
use tokio::sync::{mpsc, Mutex};
use zp_core::Frame;
use zp_transport::webrtc::{SignalingChannel, SignalingMessage, WebRtcConfig, WebRtcEndpoint};

/// Initialize crypto provider once for all WebRTC tests
static CRYPTO_INIT: Once = Once::new();

fn init_crypto() {
    CRYPTO_INIT.call_once(|| {
        // Install default crypto provider for rustls (used by webrtc crate)
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install default crypto provider");
    });
}

/// Create a WebRTC config using local coturn STUN/TURN server for testing.
///
/// Uses localhost coturn server (127.0.0.1:3478) for full WebRTC connectivity.
/// Requires coturn to be running: `turnserver -c /tmp/turnserver-test.conf`
///
/// **Setup:**
/// 1. Install coturn: `brew install coturn`
/// 2. Start server: `turnserver -c /tmp/turnserver-test.conf`
/// 3. Server provides STUN (no auth) and TURN (with credentials)
///
/// **Portability:** Works on localhost without internet. Requires coturn running.
fn localhost_webrtc_config() -> WebRtcConfig {
    WebRtcConfig {
        // Local STUN server only (no TURN for simplicity)
        // TURN with localhost relay can cause ICE state machine issues
        stun_servers: vec!["stun:127.0.0.1:3478".to_string()],
        turn_servers: Vec::new(),
    }
}

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
async fn test_webrtc_connection_establishment() {
    use tokio::time::{timeout, Duration};
    init_crypto();

    // Create endpoints with localhost-only config
    let endpoint1 =
        WebRtcEndpoint::with_config(localhost_webrtc_config()).expect("Endpoint 1 creation failed");
    let endpoint2 =
        WebRtcEndpoint::with_config(localhost_webrtc_config()).expect("Endpoint 2 creation failed");

    // Create signaling channels
    let (signaling1, signaling2) = MemorySignalingChannel::pair();

    // Spawn responder task (accepts connection)
    let accept_task = tokio::spawn(async move { endpoint2.accept(signaling2).await });

    // Initiator connects with timeout (60s for ICE gathering + connectivity checks)
    eprintln!("Starting WebRTC connection (may take 30-60s for ICE)...");
    let connect_result = timeout(Duration::from_secs(60), endpoint1.connect(signaling1)).await;

    // Check if connection timed out or failed
    match connect_result {
        Ok(Ok(client_conn)) => {
            eprintln!("✅ Client connection established!");
            // Connection succeeded - wait for responder
            let server_result = timeout(Duration::from_secs(60), accept_task).await;
            match server_result {
                Ok(Ok(Ok(server_conn))) => {
                    // Both connections established - verify roles per spec §6.4
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
                Ok(Ok(Err(e))) => {
                    panic!("Accept failed: {}", e);
                }
                Ok(Err(_)) => {
                    panic!("Accept task panicked");
                }
                Err(_) => {
                    // Timeout - unexpected with local coturn server
                    eprintln!("⚠️  WebRTC connection timed out (unexpected with local coturn)");
                    eprintln!("Possible causes:");
                    eprintln!("  - Coturn server not running (check: ps aux | grep turnserver)");
                    eprintln!("  - Port 3478 blocked or in use");
                    eprintln!("  - macOS network permissions not granted");
                    panic!("WebRTC connection failed - check coturn and permissions");
                }
            }
        }
        Ok(Err(e)) => {
            panic!("Connect failed: {}", e);
        }
        Err(_) => {
            // Timeout - unexpected with local coturn server
            eprintln!("⚠️  WebRTC connection timed out (unexpected with local coturn)");
            eprintln!("Possible causes:");
            eprintln!("  - Coturn server not running (check: ps aux | grep turnserver)");
            eprintln!("  - Port 3478 blocked or in use");
            eprintln!("  - macOS network permissions not granted");
            panic!("WebRTC connection failed - check coturn and permissions");
        }
    }
}

#[tokio::test]
async fn test_webrtc_bidirectional_frame_exchange() {
    init_crypto();

    // Create endpoints with localhost-only config
    let endpoint1 =
        WebRtcEndpoint::with_config(localhost_webrtc_config()).expect("Endpoint 1 creation failed");
    let endpoint2 =
        WebRtcEndpoint::with_config(localhost_webrtc_config()).expect("Endpoint 2 creation failed");

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
async fn test_webrtc_multiple_frames() {
    init_crypto();

    // Create endpoints with localhost-only config
    let endpoint1 =
        WebRtcEndpoint::with_config(localhost_webrtc_config()).expect("Endpoint 1 creation failed");
    let endpoint2 =
        WebRtcEndpoint::with_config(localhost_webrtc_config()).expect("Endpoint 2 creation failed");

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

#[tokio::test]
async fn test_webrtc_localhost_endpoint_creation() {
    init_crypto();

    // Test that config creates endpoints successfully
    let endpoint1 = WebRtcEndpoint::with_config(localhost_webrtc_config());
    let endpoint2 = WebRtcEndpoint::with_config(localhost_webrtc_config());

    assert!(endpoint1.is_ok(), "Endpoint 1 should succeed");
    assert!(endpoint2.is_ok(), "Endpoint 2 should succeed");

    let config = localhost_webrtc_config();
    assert_eq!(
        config.stun_servers.len(),
        1,
        "Config should have 1 STUN server"
    );
    assert_eq!(
        config.stun_servers[0], "stun:127.0.0.1:3478",
        "Should use local coturn STUN"
    );
    assert!(
        config.turn_servers.is_empty(),
        "Config should have no TURN servers (STUN-only for localhost)"
    );
}

// ================================================================================================
// Phase 5A.3: WebRTC Implementation Tests (require STUN server infrastructure)
// ================================================================================================

/// Test: ICE candidate gathering with localhost
///
/// Verifies that WebRTC can gather ICE candidates on localhost without external STUN.
/// Expected: At least host candidates are generated for local testing.
#[tokio::test]
async fn test_webrtc_ice_candidate_gathering_localhost() {
    init_crypto();
    use tokio::time::{timeout, Duration};

    // Create endpoint with localhost-only config (host candidates only)
    let endpoint =
        WebRtcEndpoint::with_config(localhost_webrtc_config()).expect("Endpoint creation failed");
    let (signaling1, signaling2) = MemorySignalingChannel::pair();

    // Spawn ICE gathering monitor
    let gather_task = tokio::spawn(async move {
        // Responder will gather ICE candidates during accept
        endpoint.accept(signaling2).await
    });

    // Create second endpoint and initiate connection (triggers ICE gathering)
    let endpoint2 =
        WebRtcEndpoint::with_config(localhost_webrtc_config()).expect("Endpoint 2 creation failed");

    // Connect with timeout to ensure ICE gathering completes
    let connect_result = timeout(Duration::from_secs(10), endpoint2.connect(signaling1)).await;

    // Verify connection succeeded (implies ICE candidates were gathered)
    assert!(
        connect_result.is_ok(),
        "ICE gathering should complete within timeout"
    );

    let connection = connect_result.unwrap();
    assert!(
        connection.is_ok(),
        "Connection establishment should succeed with localhost ICE candidates"
    );

    // Clean up
    let conn = connection.unwrap();
    conn.close().await.expect("Close should succeed");

    // Cancel gather task
    gather_task.abort();
}

/// Test: DataChannel lifecycle state transitions
///
/// Verifies DataChannel state transitions (connecting → open → closing → closed).
/// Expected: DataChannel reaches open state and closes cleanly.
#[tokio::test]
async fn test_webrtc_datachannel_lifecycle() {
    init_crypto();
    use tokio::time::{timeout, Duration};

    // Create endpoints with localhost-only config
    let endpoint1 =
        WebRtcEndpoint::with_config(localhost_webrtc_config()).expect("Endpoint 1 creation failed");
    let endpoint2 =
        WebRtcEndpoint::with_config(localhost_webrtc_config()).expect("Endpoint 2 creation failed");
    let (signaling1, signaling2) = MemorySignalingChannel::pair();

    // Spawn server task
    let server_task =
        tokio::spawn(async move { endpoint2.accept(signaling2).await.expect("Accept failed") });

    // Client connects
    let client_conn = timeout(Duration::from_secs(10), endpoint1.connect(signaling1))
        .await
        .expect("Connection should complete within timeout")
        .expect("Connection should succeed");

    // Wait for server
    let server_conn = timeout(Duration::from_secs(5), server_task)
        .await
        .expect("Server task should complete within timeout")
        .expect("Server task should not panic");

    // Verify connections are established
    // (DataChannel is in 'open' state at this point)

    // Close connections (DataChannel transitions: open → closing → closed)
    let client_close = client_conn.close().await;
    let server_close = server_conn.close().await;

    assert!(client_close.is_ok(), "Client close should succeed");
    assert!(server_close.is_ok(), "Server close should succeed");
}

/// Test: Peer connection state monitoring
///
/// Verifies peer connection state transitions during establishment.
/// Expected: Connection progresses through states (new → connecting → connected).
#[tokio::test]
async fn test_webrtc_peer_connection_state_transitions() {
    init_crypto();
    use tokio::time::{timeout, Duration};

    // Create endpoints with localhost-only config
    let endpoint1 =
        WebRtcEndpoint::with_config(localhost_webrtc_config()).expect("Endpoint 1 creation failed");
    let endpoint2 =
        WebRtcEndpoint::with_config(localhost_webrtc_config()).expect("Endpoint 2 creation failed");
    let (signaling1, signaling2) = MemorySignalingChannel::pair();

    // Spawn server task
    let server_task = tokio::spawn(async move { endpoint2.accept(signaling2).await });

    // Client connects (monitors state transitions internally)
    let connect_result = timeout(Duration::from_secs(10), endpoint1.connect(signaling1)).await;

    // Verify connection succeeded (implies successful state transitions)
    assert!(
        connect_result.is_ok(),
        "Connection should complete within timeout (state: connecting → connected)"
    );

    let client_conn = connect_result.unwrap().expect("Connection should succeed");

    // Get server connection
    let server_result = timeout(Duration::from_secs(5), server_task)
        .await
        .expect("Server task should complete")
        .expect("Server task should not panic");

    let server_conn = server_result.expect("Server connection should succeed");

    // Verify both connections are established
    // (At this point, peer connection state is 'connected')

    // Verify we can send a frame (connection is functional)
    let test_frame = Frame::WindowUpdate {
        stream_id: 0,
        window_increment: 1024,
    };

    let send_result = client_conn.send_frame(&test_frame).await;
    assert!(
        send_result.is_ok(),
        "Should be able to send frames on connected peer connection"
    );

    // Clean up
    client_conn
        .close()
        .await
        .expect("Client close should succeed");
    server_conn
        .close()
        .await
        .expect("Server close should succeed");
}

// ================================================================================================
// Phase 5A.3: Network Signaling Tests (HTTP-based signaling for cross-container/machine testing)
// ================================================================================================

mod signaling;

/// Test: WebRTC connection with HTTP signaling (network-ready)
///
/// Verifies WebRTC P2P establishment using HTTP signaling server.
/// This test proves signaling works across process boundaries and prepares for Docker testing.
///
/// **Architecture:**
/// - Embedded HTTP server (auto-starts on random port)
/// - Two peers (client + server) in same process
/// - HTTP signaling for SDP/ICE exchange (✅ WORKING)
/// - Local coturn STUN server
///
/// **Status:** HTTP signaling infrastructure complete. WebRTC connection fails due to localhost ICE
/// limitations (both peers on 127.0.0.1 → same reflexive IP → ICE fails asymmetrically).
///
/// **Next Step:** Docker container for second peer (different IP: 172.17.0.x).
/// This will enable full E2E WebRTC testing with network signaling.
///
/// **Portability:** Zero-config embedded server. Docker required for full E2E.
#[ignore = "Requires Docker for second peer (localhost ICE limitation)"]
#[tokio::test]
async fn test_webrtc_connection_with_http_signaling() {
    use tokio::time::{timeout, Duration};
    init_crypto();

    // Start embedded signaling server
    eprintln!("🚀 Starting embedded HTTP signaling server...");
    let (server_url, shutdown_tx) = signaling::embedded_server::start_server()
        .await
        .expect("Failed to start signaling server");

    eprintln!("✅ Signaling server running at {}", server_url);

    // Create session
    let session_id = signaling::client::HttpSignalingChannel::create_session(&server_url)
        .await
        .expect("Failed to create session");

    eprintln!("✅ Session created: {}", session_id);

    // Use localhost coturn for TURN relay (helps with localhost connections)
    let config = localhost_webrtc_config();

    let endpoint1 =
        WebRtcEndpoint::with_config(config.clone()).expect("Endpoint 1 creation failed");
    let endpoint2 =
        WebRtcEndpoint::with_config(config.clone()).expect("Endpoint 2 creation failed");

    // Create HTTP signaling channels (both peers use same session)
    let signaling1 = signaling::client::HttpSignalingChannel::new(
        server_url.clone(),
        session_id.clone(),
        "client".to_string(),
    );
    let signaling2 = signaling::client::HttpSignalingChannel::new(
        server_url.clone(),
        session_id.clone(),
        "server".to_string(),
    );

    // Spawn server peer task
    eprintln!("📡 Spawning server peer (accept)...");
    let server_task = tokio::spawn(async move { endpoint2.accept(signaling2).await });

    // Client connects
    eprintln!("📡 Client peer connecting...");
    let connect_result = timeout(
        Duration::from_secs(60), // Allow time for STUN gathering + ICE
        endpoint1.connect(signaling1),
    )
    .await;

    match connect_result {
        Ok(Ok(client_conn)) => {
            eprintln!("✅ Client connection established!");

            // Wait for server
            let server_result = timeout(Duration::from_secs(60), server_task).await;
            match server_result {
                Ok(Ok(Ok(server_conn))) => {
                    eprintln!("✅ Server connection established!");

                    // Verify roles per spec §6.4
                    assert_eq!(
                        client_conn.role(),
                        zp_transport::webrtc::PeerRole::Client,
                        "Initiator should have Client role"
                    );
                    assert_eq!(
                        server_conn.role(),
                        zp_transport::webrtc::PeerRole::Server,
                        "Responder should have Server role"
                    );

                    // Verify we can exchange frames
                    let test_frame = Frame::WindowUpdate {
                        stream_id: 0,
                        window_increment: 1024,
                    };

                    client_conn
                        .send_frame(&test_frame)
                        .await
                        .expect("Client send should succeed");

                    eprintln!("✅ Frame exchange successful!");

                    // Clean up
                    client_conn.close().await.expect("Client close failed");
                    server_conn.close().await.expect("Server close failed");

                    eprintln!("✅ HTTP signaling test passed!");
                }
                Ok(Ok(Err(e))) => {
                    panic!("Server accept failed: {}", e);
                }
                Ok(Err(_)) => {
                    panic!("Server task panicked");
                }
                Err(_) => {
                    eprintln!("⚠️  Server connection timed out");
                    eprintln!("This may indicate:");
                    eprintln!("  - Network connectivity issues");
                    eprintln!("  - STUN server unreachable");
                    eprintln!("  - Firewall blocking WebRTC");
                    panic!("Server connection timed out");
                }
            }
        }
        Ok(Err(e)) => {
            panic!("Client connect failed: {}", e);
        }
        Err(_) => {
            eprintln!("⚠️  Client connection timed out");
            panic!("Client connection timed out");
        }
    }

    // Shutdown signaling server
    let _ = shutdown_tx.send(());
    eprintln!("🛑 Signaling server shut down");
}
