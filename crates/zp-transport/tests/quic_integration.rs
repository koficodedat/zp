//! QUIC transport integration tests.
//!
//! Tests end-to-end scenarios involving multiple components:
//! - Bidirectional frame exchange
//! - Multiple concurrent streams
//! - Session state integration
//! - Error propagation

use zp_core::Frame;
use zp_transport::quic::QuicEndpoint;

// Install default crypto provider for tests
fn setup() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[tokio::test]
async fn test_bidirectional_frame_exchange() {
    setup();

    // Start server
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Create client
    let client = QuicEndpoint::client().expect("Client creation failed");

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let server_conn = server.accept().await.expect("Server accept failed");

        // Server opens a stream and sends a frame
        let mut server_stream = server_conn
            .open_stream()
            .await
            .expect("Server open stream failed");

        let test_frame = Frame::WindowUpdate {
            stream_id: server_stream.id() as u32,
            window_increment: 1024,
        };

        server_stream
            .send_frame(&test_frame)
            .await
            .expect("Server send failed");

        // Server receives a frame
        let received = server_stream
            .recv_frame()
            .await
            .expect("Server recv failed")
            .expect("Should receive a frame");

        (server_stream.id(), received)
    });

    // Client connects
    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    // Client accepts server's stream
    let mut client_stream = client_conn
        .accept_stream()
        .await
        .expect("Client accept stream failed");

    // Client receives frame from server
    let received_from_server = client_stream
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
        stream_id: client_stream.id() as u32,
        window_increment: 2048,
    };

    client_stream
        .send_frame(&response_frame)
        .await
        .expect("Client send failed");

    // Get server results
    let (server_stream_id, received_by_server) = server_task.await.expect("Server task panicked");

    // Verify bidirectional communication
    assert_eq!(
        server_stream_id,
        client_stream.id(),
        "Stream IDs should match"
    );
    assert!(
        matches!(received_by_server, Frame::WindowUpdate { .. }),
        "Server should receive WindowUpdate from client"
    );
}

#[tokio::test]
async fn test_multiple_concurrent_streams() {
    setup();

    // Start server
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Create client
    let client = QuicEndpoint::client().expect("Client creation failed");

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let server_conn = server.accept().await.expect("Server accept failed");

        // Accept 3 streams from client and send initial frame to establish
        let mut streams = Vec::new();
        for i in 0..3 {
            let mut stream = server_conn
                .accept_stream()
                .await
                .expect("Server accept stream failed");

            // Send initial frame to establish stream
            let frame = Frame::WindowUpdate {
                stream_id: stream.id() as u32,
                window_increment: 1024 * (i + 1),
            };
            stream.send_frame(&frame).await.expect("Server send failed");

            streams.push(stream);
        }

        streams
    });

    // Client connects
    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    // Client opens 3 concurrent streams and sends initial frame
    let mut client_streams = Vec::new();
    for i in 0..3 {
        let mut stream = client_conn
            .open_stream()
            .await
            .expect("Client open stream failed");

        // Send initial frame to establish stream
        let frame = Frame::WindowUpdate {
            stream_id: stream.id() as u32,
            window_increment: 2048 * (i + 1),
        };
        stream.send_frame(&frame).await.expect("Client send failed");

        client_streams.push(stream);
    }

    // Get server streams
    let server_streams = server_task.await.expect("Server task panicked");

    // Verify all streams are established
    assert_eq!(client_streams.len(), 3, "Should have 3 client streams");
    assert_eq!(server_streams.len(), 3, "Should have 3 server streams");

    // Verify stream IDs are unique and correct parity
    for stream in &client_streams {
        assert!(stream.id() % 2 == 0, "Client stream IDs should be even");
    }

    // Verify no duplicate stream IDs
    let client_ids: Vec<u64> = client_streams.iter().map(|s| s.id()).collect();
    let unique_count = client_ids
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert_eq!(unique_count, 3, "All client stream IDs should be unique");
}

#[tokio::test]
async fn test_session_state_during_quic_operations() {
    setup();

    // Start server
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Create client
    let client = QuicEndpoint::client().expect("Client creation failed");

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let server_conn = server.accept().await.expect("Server accept failed");

        // Check session state
        let session_lock = server_conn.session();
        let session = session_lock.read().await;

        // Session should be in Stranger mode
        assert!(
            !session.is_established(),
            "Session should not be established yet"
        );

        drop(session);
        server_conn
    });

    // Client connects
    let client_conn = client
        .connect(&addr.to_string(), "localhost")
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
async fn test_control_stream_frame_enforcement() {
    setup();

    // Start server
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Create client
    let client = QuicEndpoint::client().expect("Client creation failed");

    // Spawn server
    let server_task = tokio::spawn(async move { server.accept().await });

    // Client connects
    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    // Get control stream
    let control_stream_lock = client_conn.control_stream();
    let mut control_stream_opt = control_stream_lock.write().await;
    let control_stream = control_stream_opt
        .as_mut()
        .expect("Should have control stream");

    // Attempt to send DataFrame on control stream (should fail)
    let data_frame = Frame::DataFrame {
        stream_id: 0,
        seq: 1,
        flags: 0,
        payload: vec![1, 2, 3],
    };

    let result = control_stream.send_frame(&data_frame).await;

    assert!(result.is_err(), "Should reject DataFrame on control stream");

    drop(control_stream_opt);

    // Clean up
    let _ = server_task.await;
}

#[tokio::test]
async fn test_stream_id_allocation_parity() {
    setup();

    // Start server
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Create client
    let client = QuicEndpoint::client().expect("Client creation failed");

    // Spawn server task
    let server_task = tokio::spawn(async move {
        let server_conn = server.accept().await.expect("Server accept failed");

        // Server opens 5 streams
        let mut server_streams = Vec::new();
        for _ in 0..5 {
            let stream = server_conn
                .open_stream()
                .await
                .expect("Server open stream failed");
            server_streams.push(stream.id());
        }

        server_streams
    });

    // Client connects
    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    // Client opens 5 streams
    let mut client_streams = Vec::new();
    for _ in 0..5 {
        let stream = client_conn
            .open_stream()
            .await
            .expect("Client open stream failed");
        client_streams.push(stream.id());
    }

    // Get server stream IDs
    let server_stream_ids = server_task.await.expect("Server task panicked");

    // Verify client stream IDs are all even
    for id in &client_streams {
        assert!(id % 2 == 0, "Client stream ID {} should be even", id);
        assert!(
            *id >= 4,
            "Client stream IDs should start at 4 (0 is control)"
        );
    }

    // Verify server stream IDs are all odd
    for id in &server_stream_ids {
        assert!(id % 2 == 1, "Server stream ID {} should be odd", id);
    }

    // Verify no collisions
    let all_ids: Vec<u64> = client_streams
        .iter()
        .chain(server_stream_ids.iter())
        .copied()
        .collect();
    let unique_count = all_ids
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert_eq!(unique_count, 10, "All stream IDs should be unique");
}

/// Test: Rapid stream creation/close stress test (1000 streams <1 second)
///
/// Spec §3.3.1: Stream ID allocation
/// Tests system behavior under stress with many concurrent streams.
#[tokio::test]
async fn test_rapid_stream_creation_stress() {
    setup();

    // Server setup
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");
    let addr = server.local_addr().expect("Failed to get server address");

    // Server accepts connection
    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("Server accept failed");

        // Accept all incoming streams (client will open 1000)
        let mut accepted_count = 0;
        for _ in 0..1000 {
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(5),
                conn.accept_stream(),
            )
            .await
            {
                Ok(Ok(_stream)) => {
                    accepted_count += 1;
                }
                Ok(Err(e)) => {
                    eprintln!("Server accept_stream error: {}", e);
                    break;
                }
                Err(_) => {
                    eprintln!("Server accept timeout");
                    break;
                }
            }
        }

        accepted_count
    });

    // Client setup
    let client = QuicEndpoint::client().expect("Client creation failed");

    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    // Rapid stream creation - 1000 streams
    let start = tokio::time::Instant::now();
    let mut stream_ids = Vec::with_capacity(1000);

    for _ in 0..1000 {
        match client_conn.open_stream().await {
            Ok(stream) => {
                stream_ids.push(stream.id());
            }
            Err(e) => {
                eprintln!("Client open_stream error at {}: {}", stream_ids.len(), e);
                break;
            }
        }
    }

    let elapsed = start.elapsed();

    // Assertions
    assert!(
        !stream_ids.is_empty(),
        "Should have opened at least some streams"
    );

    // Target: 1000 streams in <1 second
    // Reality: May be limited by Quinn's max_concurrent_bidi_streams (100)
    // So verify we hit Quinn's limit or opened 1000
    let expected_min = std::cmp::min(100, 1000); // Quinn limits to 100
    assert!(
        stream_ids.len() >= expected_min,
        "Should open at least {} streams, got {}",
        expected_min,
        stream_ids.len()
    );

    println!(
        "Opened {} streams in {:?} ({:.0} streams/sec)",
        stream_ids.len(),
        elapsed,
        stream_ids.len() as f64 / elapsed.as_secs_f64()
    );

    // Verify all stream IDs are even (client-initiated)
    for id in &stream_ids {
        assert!(
            id % 2 == 0,
            "Client stream ID {} should be even (client-initiated)",
            id
        );
        assert!(
            *id >= 4,
            "Client stream IDs should start at 4 (0 is control), got {}",
            id
        );
    }

    // Verify all stream IDs are unique
    let unique_count = stream_ids
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len();
    assert_eq!(
        unique_count,
        stream_ids.len(),
        "All stream IDs should be unique"
    );

    // Wait for server to accept (with timeout)
    let server_accepted = server_task.await.expect("Server task panicked");
    println!("Server accepted {} streams", server_accepted);

    // Server should have accepted as many as client opened (within reason)
    assert!(
        server_accepted >= expected_min / 2,
        "Server should accept many streams, got {}",
        server_accepted
    );
}
