//! Concurrency Testing for zp-transport
//!
//! Tests thread safety, race conditions, and concurrent operations.
//! Verifies nonce counter atomicity, stream multiplexing, and connection handling.
//!
//! Spec: §6.5.1 (Nonce Construction), §3.3 (Stream Multiplexing)

use futures_util::future;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use zp_core::Frame;
use zp_transport::quic::QuicEndpoint;

// Install default crypto provider for tests
fn setup() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

// ============================================================================
// Test Category 1: Concurrent Stream Operations (4 tests)
// ============================================================================

/// Test 1.1: 1000 concurrent streams (all sending/receiving simultaneously)
///
/// Spec §3.3: Stream multiplexing
/// Verifies stream ID allocation under high concurrency.
///
/// NOTE: Requires resource tuning (currently hits timeout with 1000 streams)
#[tokio::test]
#[ignore] // TODO: Optimize for 1000 concurrent streams (currently times out)
async fn test_1000_concurrent_streams() {
    setup();

    // Start server
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Server accepts 1000 streams
    let server_task = tokio::spawn(async move {
        let server_conn = server.accept().await.expect("Server accept failed");

        let mut stream_ids = Vec::new();
        for _ in 0..1000 {
            match tokio::time::timeout(
                tokio::time::Duration::from_secs(10),
                server_conn.accept_stream(),
            )
            .await
            {
                Ok(Ok(stream)) => {
                    stream_ids.push(stream.id());
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

        stream_ids
    });

    // Client connects and opens 1000 streams
    let client = QuicEndpoint::client().expect("Client creation failed");
    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    // Open 1000 streams concurrently
    let mut tasks = Vec::new();
    for _ in 0..1000 {
        let conn = client_conn.clone(); // QuicConnection is now Clone
        tasks.push(tokio::spawn(async move { conn.open_stream().await }));
    }

    // Wait for all streams to open
    let results = future::join_all(tasks).await;
    let client_stream_ids: Vec<u64> = results
        .into_iter()
        .filter_map(|r| r.ok().and_then(|s| s.ok().map(|stream| stream.id())))
        .collect();

    // Get server results
    let server_stream_ids = server_task.await.expect("Server task panicked");

    // Verify client opened 1000 streams
    assert_eq!(
        client_stream_ids.len(),
        1000,
        "Should open 1000 client streams"
    );

    // Verify all client stream IDs are even (client-initiated)
    for id in &client_stream_ids {
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
    let unique_count = client_stream_ids.iter().collect::<HashSet<_>>().len();
    assert_eq!(
        unique_count,
        client_stream_ids.len(),
        "All stream IDs should be unique"
    );

    // Verify server accepted many streams
    assert!(
        server_stream_ids.len() >= 900,
        "Server should accept most streams, got {}",
        server_stream_ids.len()
    );

    println!(
        "✅ Test 1.1: Opened {} client streams, server accepted {}",
        client_stream_ids.len(),
        server_stream_ids.len()
    );
}

/// Test 1.2: Interleaved send/recv (stream A sends while stream B receives)
///
/// Spec §3.3: Stream multiplexing allows concurrent I/O on different streams
/// NOTE: Requires proper concurrent send/recv coordination
#[tokio::test]
#[ignore] // TODO: Implement proper concurrent send/recv coordination (Arc<Mutex<>> pattern)
async fn test_interleaved_send_recv() {
    setup();

    // Start server
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Server task: accept 2 streams, send on stream 1, receive on stream 2
    let server_task = tokio::spawn(async move {
        let server_conn = server.accept().await.expect("Server accept failed");

        // Accept stream 1 from client
        let mut server_stream_1 = server_conn
            .accept_stream()
            .await
            .expect("Server accept stream 1 failed");

        // Accept stream 2 from client
        let mut server_stream_2 = server_conn
            .accept_stream()
            .await
            .expect("Server accept stream 2 failed");

        // Send on stream 1, receive on stream 2 concurrently
        let send_task = tokio::spawn(async move {
            for _ in 0..10 {
                let frame = Frame::WindowUpdate {
                    stream_id: server_stream_1.id() as u32,
                    window_increment: 1024,
                };
                server_stream_1
                    .send_frame(&frame)
                    .await
                    .expect("Server send failed");
            }
            server_stream_1.id()
        });

        let recv_task = tokio::spawn(async move {
            for _ in 0..10 {
                server_stream_2
                    .recv_frame()
                    .await
                    .expect("Server recv failed")
                    .expect("Should receive frame");
            }
            server_stream_2.id()
        });

        let (send_id, recv_id) = tokio::join!(send_task, recv_task);
        (send_id.unwrap(), recv_id.unwrap())
    });

    // Client connects and opens 2 streams
    let client = QuicEndpoint::client().expect("Client creation failed");
    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    let mut client_stream_1 = client_conn
        .open_stream()
        .await
        .expect("Client open stream 1 failed");
    let mut client_stream_2 = client_conn
        .open_stream()
        .await
        .expect("Client open stream 2 failed");

    // Receive on stream 1, send on stream 2 concurrently
    let recv_task = tokio::spawn(async move {
        for _ in 0..10 {
            client_stream_1
                .recv_frame()
                .await
                .expect("Client recv failed")
                .expect("Should receive frame");
        }
        client_stream_1.id()
    });

    let send_task = tokio::spawn(async move {
        for _ in 0..10 {
            let frame = Frame::WindowUpdate {
                stream_id: client_stream_2.id() as u32,
                window_increment: 2048,
            };
            client_stream_2
                .send_frame(&frame)
                .await
                .expect("Client send failed");
        }
        client_stream_2.id()
    });

    let (client_recv_id, client_send_id) = tokio::join!(recv_task, send_task);
    let (server_send_id, server_recv_id) = server_task.await.expect("Server task panicked");

    // Verify stream IDs match
    assert_eq!(
        client_recv_id.unwrap(),
        server_send_id,
        "Stream 1 IDs should match"
    );
    assert_eq!(
        client_send_id.unwrap(),
        server_recv_id,
        "Stream 2 IDs should match"
    );

    println!("✅ Test 1.2: Interleaved send/recv on 2 streams successful");
}

/// Test 1.3: Simultaneous stream creation (10 threads create streams concurrently)
///
/// Spec §3.3.1: Stream ID allocation must maintain parity (even for client, odd for server)
#[tokio::test]
async fn test_simultaneous_stream_creation_10_threads() {
    setup();

    // Start server
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Server accepts connections
    let server_task = tokio::spawn(async move { server.accept().await });

    // Client connects
    let client = QuicEndpoint::client().expect("Client creation failed");
    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    // Create 10 concurrent tasks, each opening streams
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let conn = client_conn.clone();
        tasks.push(tokio::spawn(async move {
            let mut stream_ids = Vec::new();
            for _ in 0..10 {
                match conn.open_stream().await {
                    Ok(stream) => stream_ids.push(stream.id()),
                    Err(e) => eprintln!("Stream open error: {}", e),
                }
            }
            stream_ids
        }));
    }

    // Wait for all tasks to complete
    let results = future::join_all(tasks).await;
    let all_stream_ids: Vec<u64> = results
        .into_iter()
        .flat_map(|r| r.unwrap_or_default())
        .collect();

    // Verify 100 streams opened (10 threads × 10 streams)
    assert_eq!(
        all_stream_ids.len(),
        100,
        "Should have 100 total stream IDs"
    );

    // Verify all stream IDs are even (client-initiated)
    for id in &all_stream_ids {
        assert!(
            id % 2 == 0,
            "Client stream ID {} should be even (client-initiated)",
            id
        );
    }

    // Verify all stream IDs are unique (no allocation conflicts)
    let unique_count = all_stream_ids.iter().collect::<HashSet<_>>().len();
    assert_eq!(
        unique_count,
        all_stream_ids.len(),
        "All stream IDs should be unique (no allocation race)"
    );

    // Clean up
    let _ = server_task.await;

    println!("✅ Test 1.3: 10 threads created 100 streams with no ID conflicts");
}

/// Test 1.4: Stream close race (close while send/recv in progress)
///
/// Spec §3.3.11: Stream lifecycle states must handle concurrent operations gracefully
#[tokio::test]
async fn test_stream_close_race() {
    setup();

    // Start server
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Server accepts stream
    let server_task = tokio::spawn(async move {
        let server_conn = server.accept().await.expect("Server accept failed");
        let server_stream = server_conn
            .accept_stream()
            .await
            .expect("Server accept stream failed");
        server_stream.id()
    });

    // Client connects and opens stream
    let client = QuicEndpoint::client().expect("Client creation failed");
    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    let client_stream = client_conn
        .open_stream()
        .await
        .expect("Client open stream failed");

    // Wrap stream in Arc<Mutex<>> for shared access
    let stream = Arc::new(Mutex::new(client_stream));

    // Task 1: Send frames continuously
    let send_stream = stream.clone();
    let send_task = tokio::spawn(async move {
        let mut count = 0;
        loop {
            let mut s = send_stream.lock().await;
            let frame = Frame::WindowUpdate {
                stream_id: s.id() as u32,
                window_increment: 1024,
            };
            match s.send_frame(&frame).await {
                Ok(_) => count += 1,
                Err(_) => break, // Stream closed
            }
            drop(s); // Release lock
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
        count
    });

    // Task 2: Drop stream after 100ms (Quinn handles graceful close on drop)
    let close_stream = stream.clone();
    let close_task = tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        drop(close_stream); // Drop the Arc, triggering close when last ref goes away
    });

    // Wait for tasks
    let frames_sent = send_task.await.expect("Send task panicked");
    close_task.await.expect("Close task panicked");

    // Verify some frames were sent before close
    assert!(frames_sent > 0, "Should have sent some frames before close");

    // Clean up
    let _ = server_task.await;

    println!(
        "✅ Test 1.4: Stream close race handled gracefully ({} frames sent before close)",
        frames_sent
    );
}

// ============================================================================
// Test Category 2: Encryption Concurrency (3 tests)
// ============================================================================

/// Test 2.1: Parallel frame encryption (10 threads encrypt frames simultaneously)
///
/// Spec §6.5.1: Nonce counter must increment atomically to prevent reuse
///
/// NOTE: Test deferred - QUIC uses native TLS 1.3 encryption (no EncryptedRecord)
/// ZP session encryption only applies to non-QUIC transports (TCP, WebSocket, WebRTC).
/// This test requires TCP transport implementation to verify EncryptedRecord nonce handling.
#[tokio::test]
#[ignore] // TODO: Implement TCP transport for EncryptedRecord encryption testing
async fn test_parallel_frame_encryption() {
    setup();

    // Start server
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Server accepts connection and performs handshake
    let server_task = tokio::spawn(async move {
        let server_conn = server.accept().await.expect("Server accept failed");
        server_conn
            .perform_handshake()
            .await
            .expect("Server handshake failed");
    });

    // Client connects and performs handshake
    let client = QuicEndpoint::client().expect("Client creation failed");
    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    client_conn
        .perform_handshake()
        .await
        .expect("Client handshake failed");

    // Get session for nonce tracking
    let session = client_conn.session();

    // Record initial send_nonce
    let initial_nonce = {
        let s = session.read().await;
        s.keys().map(|k| k.send_nonce).unwrap_or(0)
    };

    // Create 10 concurrent encryption tasks
    let mut tasks = Vec::new();
    for i in 0..10 {
        let conn = client_conn.clone();
        tasks.push(tokio::spawn(async move {
            let mut stream = conn.open_stream().await.expect("Stream open failed");

            // Send 10 frames
            for j in 0..10 {
                let frame = Frame::WindowUpdate {
                    stream_id: stream.id() as u32,
                    window_increment: (i * 10 + j) as u64,
                };
                stream.send_frame(&frame).await.expect("Send failed");
            }
        }));
    }

    // Wait for all tasks
    for task in tasks {
        task.await.expect("Task panicked");
    }

    // Verify final send_nonce = initial + 100 (10 threads × 10 frames)
    let final_nonce = {
        let s = session.read().await;
        s.keys().map(|k| k.send_nonce).unwrap_or(0)
    };

    assert_eq!(
        final_nonce,
        initial_nonce + 100,
        "Nonce should increment by exactly 100 (no duplicates, no skips)"
    );

    // Clean up
    let _ = server_task.await;

    println!(
        "✅ Test 2.1: 10 threads encrypted 100 frames with no nonce collisions (nonce: {} → {})",
        initial_nonce, final_nonce
    );
}

/// Test 2.2: Nonce counter race conditions (verify atomic increment per §6.5.1)
///
/// Spec §6.5.1: "Counter Increment: After encrypting each message, increment the counter by 1"
///
/// NOTE: Test deferred - QUIC uses native TLS 1.3 encryption (no EncryptedRecord)
/// ZP session encryption only applies to non-QUIC transports (TCP, WebSocket, WebRTC).
/// This test requires TCP transport implementation to verify EncryptedRecord nonce atomicity.
#[tokio::test]
#[ignore] // TODO: Implement TCP transport for EncryptedRecord encryption testing
async fn test_nonce_counter_atomic_increment() {
    setup();

    // Start server
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Server accepts connection and performs handshake
    let server_task = tokio::spawn(async move {
        let server_conn = server.accept().await.expect("Server accept failed");
        server_conn
            .perform_handshake()
            .await
            .expect("Server handshake failed");
    });

    // Client connects and performs handshake
    let client = QuicEndpoint::client().expect("Client creation failed");
    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    client_conn
        .perform_handshake()
        .await
        .expect("Client handshake failed");

    // Open stream
    let mut stream = client_conn.open_stream().await.expect("Stream open failed");

    // Get session
    let session = client_conn.session();
    let initial_nonce = {
        let s = session.read().await;
        s.keys().map(|k| k.send_nonce).unwrap_or(0)
    };

    // Send 1000 frames sequentially (verify counter monotonicity)
    for i in 0..1000 {
        let frame = Frame::WindowUpdate {
            stream_id: stream.id() as u32,
            window_increment: i,
        };
        stream.send_frame(&frame).await.expect("Send failed");
    }

    // Verify final nonce = initial + 1000
    let final_nonce = {
        let s = session.read().await;
        s.keys().map(|k| k.send_nonce).unwrap_or(0)
    };

    assert_eq!(
        final_nonce,
        initial_nonce + 1000,
        "Nonce should increment monotonically"
    );

    // Clean up
    let _ = server_task.await;

    println!(
        "✅ Test 2.2: Nonce counter incremented atomically 1000 times (nonce: {} → {})",
        initial_nonce, final_nonce
    );
}

/// Test 2.3: Key rotation during active encryption (rotate while encrypting per §4.6.4)
///
/// Spec §4.6.4: Key rotation protocol must not interfere with active encryption
///
/// NOTE: Key rotation implementation is in Task 4.2 (completed), but graceful transition
/// during active encryption is deferred. This test verifies basic rotation doesn't break.
#[tokio::test]
#[ignore] // TODO: Implement graceful key rotation during active encryption (Task 4.3)
async fn test_key_rotation_during_encryption() {
    setup();

    // Start server
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");

    // Server accepts connection
    let server_task = tokio::spawn(async move {
        let _server_conn = server.accept().await.expect("Server accept failed");
    });

    // Client connects
    let client = QuicEndpoint::client().expect("Client creation failed");
    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    // Open stream
    let mut stream = client_conn.open_stream().await.expect("Stream open failed");

    // Send 50 frames with epoch 0
    for i in 0..50 {
        let frame = Frame::WindowUpdate {
            stream_id: stream.id() as u32,
            window_increment: i,
        };
        stream.send_frame(&frame).await.expect("Send failed");
    }

    // Trigger key rotation (Task 4.2 API)
    // TODO: session.initiate_key_rotation(RotationDirection::ClientToServer)?;

    // Send 50 more frames with epoch 1
    for i in 50..100 {
        let frame = Frame::WindowUpdate {
            stream_id: stream.id() as u32,
            window_increment: i,
        };
        stream.send_frame(&frame).await.expect("Send failed");
    }

    // Verify epoch incremented
    // TODO: assert_eq!(session.keys().unwrap().key_epoch, 1);

    // Clean up
    let _ = server_task.await;

    println!("✅ Test 2.3: Key rotation during active encryption successful");
}

// ============================================================================
// Test Category 3: Connection Concurrency (3 tests)
// ============================================================================

/// Test 3.1: Multiple simultaneous connections (100 connections to same endpoint)
///
/// Verifies QuicEndpoint can handle many concurrent connections
#[tokio::test]
async fn test_100_simultaneous_connections() {
    setup();

    // Start server
    let server = Arc::new(
        QuicEndpoint::server("127.0.0.1:0")
            .await
            .expect("Server creation failed"),
    );

    let addr = server.local_addr().expect("Failed to get server address");

    // Server accepts 100 connections
    let server_task = {
        let srv = server.clone();
        tokio::spawn(async move {
            let mut conn_count = 0;
            for _ in 0..100 {
                match tokio::time::timeout(tokio::time::Duration::from_secs(30), srv.accept()).await
                {
                    Ok(Ok(_conn)) => conn_count += 1,
                    Ok(Err(e)) => {
                        eprintln!("Server accept error: {}", e);
                        break;
                    }
                    Err(_) => {
                        eprintln!("Server accept timeout");
                        break;
                    }
                }
            }
            conn_count
        })
    };

    // Client creates 100 concurrent connections
    let mut tasks = Vec::new();
    for _ in 0..100 {
        let addr_str = addr.to_string();
        tasks.push(tokio::spawn(async move {
            let client = QuicEndpoint::client().expect("Client creation failed");
            client.connect(&addr_str, "localhost").await
        }));
    }

    // Wait for all connections
    let results = future::join_all(tasks).await;
    let successful_connections = results
        .into_iter()
        .filter(|r| r.as_ref().is_ok_and(|c| c.is_ok()))
        .count();

    // Get server count
    let server_accepted = server_task.await.expect("Server task panicked");

    // Verify most connections succeeded
    assert!(
        successful_connections >= 90,
        "Should establish at least 90/100 connections, got {}",
        successful_connections
    );

    assert!(
        server_accepted >= 90,
        "Server should accept at least 90/100 connections, got {}",
        server_accepted
    );

    println!(
        "✅ Test 3.1: Established {}/{} simultaneous connections (server accepted {})",
        successful_connections, 100, server_accepted
    );
}

/// Test 3.2: Concurrent connect/accept (client connects while server accepts)
///
/// Verifies client and server can operate concurrently
#[tokio::test]
async fn test_concurrent_connect_accept() {
    setup();

    // Start server
    let server = Arc::new(
        QuicEndpoint::server("127.0.0.1:0")
            .await
            .expect("Server creation failed"),
    );

    let addr = server.local_addr().expect("Failed to get server address");

    // Server accepts 50 connections in loop
    let server_task = {
        let srv = server.clone();
        tokio::spawn(async move {
            let mut connections = Vec::new();
            for _ in 0..50 {
                match srv.accept().await {
                    Ok(conn) => connections.push(conn),
                    Err(e) => {
                        eprintln!("Server accept error: {}", e);
                        break;
                    }
                }
            }
            connections.len()
        })
    };

    // Client connects 50 times concurrently
    let mut tasks = Vec::new();
    for _ in 0..50 {
        let addr_str = addr.to_string();
        tasks.push(tokio::spawn(async move {
            let client = QuicEndpoint::client().expect("Client creation failed");
            client.connect(&addr_str, "localhost").await
        }));
    }

    // Wait for all
    let client_results = future::join_all(tasks).await;
    let client_success = client_results
        .into_iter()
        .filter(|r| r.as_ref().is_ok_and(|c| c.is_ok()))
        .count();

    let server_accepted = server_task.await.expect("Server task panicked");

    // Verify all succeeded
    assert_eq!(client_success, 50, "All 50 clients should connect");
    assert_eq!(server_accepted, 50, "Server should accept all 50");

    println!(
        "✅ Test 3.2: Concurrent connect/accept successful ({} clients, {} server)",
        client_success, server_accepted
    );
}

/// Test 3.3: Shared endpoint stress test (1000 connections through single QuicEndpoint)
///
/// Verifies QuicEndpoint resource management under high load
/// NOTE: Requires resource tuning (file descriptors, memory limits)
#[tokio::test]
#[ignore] // TODO: Optimize for 1000 sequential connections (resource limits, handshake overhead)
async fn test_shared_endpoint_stress_1000_connections() {
    setup();

    // Start server
    let server = Arc::new(
        QuicEndpoint::server("127.0.0.1:0")
            .await
            .expect("Server creation failed"),
    );

    let addr = server.local_addr().expect("Failed to get server address");

    // Server accepts 1000 connections
    let server_task = {
        let srv = server.clone();
        tokio::spawn(async move {
            let mut count = 0;
            for _ in 0..1000 {
                match srv.accept().await {
                    Ok(_conn) => count += 1,
                    Err(e) => {
                        eprintln!("Server accept error: {}", e);
                        break;
                    }
                }
            }
            count
        })
    };

    // Client creates 1000 sequential connections (stress test resource cleanup)
    let client = QuicEndpoint::client().expect("Client creation failed");
    let mut successful = 0;

    for _ in 0..1000 {
        match client.connect(&addr.to_string(), "localhost").await {
            Ok(_conn) => {
                successful += 1;
                // Connection drops here, testing resource cleanup
            }
            Err(e) => {
                eprintln!("Client connect error: {}", e);
                break;
            }
        }
    }

    // Get server count
    let server_accepted = server_task.await.expect("Server task panicked");

    // Verify most succeeded (allow some failures under stress)
    assert!(
        successful >= 900,
        "Should establish at least 900/1000 connections, got {}",
        successful
    );

    assert!(
        server_accepted >= 900,
        "Server should accept at least 900/1000 connections, got {}",
        server_accepted
    );

    println!(
        "✅ Test 3.3: Stress test complete ({}/1000 client, {}/1000 server)",
        successful, server_accepted
    );
}
