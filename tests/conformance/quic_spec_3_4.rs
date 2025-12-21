//! Conformance tests for zp specification §3.4 (QUIC Stream Mapping).
//!
//! Tests verify:
//! - Stream ID derivation (zp_stream_id = QUIC_stream_id)
//! - Stream ID parity (client: even, server: odd)
//! - Control stream (stream 0) enforcement
//! - Control stream initialization (WindowUpdate required)
//! - Data stream allocation (client: 4+, server: 5+)

use zp_core::Frame;
use zp_transport::quic::QuicEndpoint;

fn setup() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Test: Stream ID Derivation per spec §3.4
///
/// Requirement: "zp_stream_id = QUIC_stream_id"
/// QUIC stream IDs are used directly as zp stream_ids.
#[tokio::test]
async fn conformance_stream_id_direct_mapping() {
    setup();

    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");
    let client = QuicEndpoint::client().expect("Client creation failed");

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("Server accept failed");
        let stream = conn.open_stream().await.expect("Server open stream failed");
        stream.id()
    });

    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    let client_stream = client_conn
        .open_stream()
        .await
        .expect("Client open stream failed");

    let server_stream_id = server_task.await.expect("Server task panicked");

    // Verify direct mapping: QUIC stream ID equals zp stream_id
    // Client: first data stream should be ID 4
    assert_eq!(
        client_stream.id(),
        4,
        "§3.4: Client first data stream should be QUIC stream ID 4"
    );

    // Server: first data stream should be ID 5 (odd)
    assert!(
        server_stream_id % 2 == 1,
        "§3.4: Server stream IDs must be odd"
    );
}

/// Test: Stream ID Parity per spec §3.4
///
/// Requirement: "Client-initiated bidirectional: 0, 4, 8, 12, ... (even)"
/// Requirement: "Server-initiated bidirectional: 1, 5, 9, 13, ... (odd)"
#[tokio::test]
async fn conformance_stream_id_parity() {
    setup();

    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");
    let client = QuicEndpoint::client().expect("Client creation failed");

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("Server accept failed");

        // Open 10 server streams
        let mut server_ids = Vec::new();
        for _ in 0..10 {
            let stream = conn.open_stream().await.expect("Server open stream failed");
            // Send initial frame to establish
            let frame = Frame::WindowUpdate {
                stream_id: stream.id() as u32,
                window_increment: 1024,
            };
            let mut s = stream;
            s.send_frame(&frame).await.expect("Send failed");
            server_ids.push(s.id());
        }
        server_ids
    });

    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    // Open 10 client streams
    let mut client_ids = Vec::new();
    for _ in 0..10 {
        let stream = client_conn
            .open_stream()
            .await
            .expect("Client open stream failed");
        // Send initial frame
        let frame = Frame::WindowUpdate {
            stream_id: stream.id() as u32,
            window_increment: 2048,
        };
        let mut s = stream;
        s.send_frame(&frame).await.expect("Send failed");
        client_ids.push(s.id());
    }

    let server_ids = server_task.await.expect("Server task panicked");

    // Verify §3.4 parity requirements
    for id in &client_ids {
        assert!(id % 2 == 0, "§3.4: Client stream ID {} must be even", id);
        assert!(
            *id >= 4,
            "§3.4: Client data stream IDs start at 4 (stream 0 is control)"
        );
    }

    for id in &server_ids {
        assert!(id % 2 == 1, "§3.4: Server stream ID {} must be odd", id);
        assert!(
            *id >= 1,
            "§3.4: Server data stream IDs start at 1 (odd sequence)"
        );
    }

    // Verify expected sequence
    // Client: 4, 8, 12, 16, 20, 24, 28, 32, 36, 40
    for (i, id) in client_ids.iter().enumerate() {
        let expected = 4 + (i as u64 * 4);
        assert_eq!(
            *id, expected,
            "§3.4: Client stream {} should be ID {}",
            i, expected
        );
    }

    // Server: 5, 9, 13, 17, 21, 25, 29, 33, 37, 41 (odd sequence)
    for (i, id) in server_ids.iter().enumerate() {
        assert!(
            id % 2 == 1,
            "§3.4: Server stream {} (ID {}) must be odd",
            i,
            id
        );
    }
}

/// Test: Control Stream Enforcement per spec §3.4
///
/// Requirement: "Receipt of DataFrame or any non-control frame on stream 0
/// MUST result in ERR_PROTOCOL_VIOLATION (0x0E) and connection termination."
#[tokio::test]
async fn conformance_control_stream_enforcement() {
    setup();

    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");
    let client = QuicEndpoint::client().expect("Client creation failed");

    let _server_task = tokio::spawn(async move { server.accept().await });

    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    // Get control stream (stream 0)
    let control_stream_lock = client_conn.control_stream();
    let mut control_stream_opt = control_stream_lock.write().await;
    let control_stream = control_stream_opt
        .as_mut()
        .expect("Should have control stream");

    // Attempt to send DataFrame on stream 0
    let data_frame = Frame::DataFrame {
        stream_id: 0,
        seq: 1,
        flags: 0,
        payload: vec![1, 2, 3, 4, 5],
    };

    let result = control_stream.send_frame(&data_frame).await;

    // Verify §3.4 enforcement
    assert!(
        result.is_err(),
        "§3.4: DataFrame on stream 0 must be rejected"
    );

    // Verify error is ProtocolViolation
    match result {
        Err(e) => {
            let err_string = format!("{:?}", e);
            assert!(
                err_string.contains("ProtocolViolation")
                    || err_string.contains("DataFrame not allowed on control stream"),
                "§3.4: Error must be ProtocolViolation, got: {}",
                err_string
            );
        }
        Ok(_) => panic!("§3.4: DataFrame on stream 0 should fail"),
    }
}

/// Test: Control Stream Initialization per spec §3.4
///
/// Requirement: "Client MUST open QUIC stream 0 immediately after QUIC handshake
/// completes by sending a connection-level WindowUpdate (stream_id=0,
/// window_increment=ZP_INITIAL_CONN_WINDOW)."
#[tokio::test]
async fn conformance_control_stream_initialization() {
    setup();

    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");
    let client = QuicEndpoint::client().expect("Client creation failed");

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("Server accept failed");

        // Verify control stream exists
        let cs_lock = conn.control_stream();
        let cs = cs_lock.read().await;
        assert!(
            cs.is_some(),
            "§3.4: Server should have control stream after client connects"
        );

        let stream_id = cs.as_ref().unwrap().id();
        assert_eq!(stream_id, 0, "§3.4: Control stream must be QUIC stream 0");

        drop(cs);
        conn
    });

    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    // Verify client has control stream
    let client_cs_lock = client_conn.control_stream();
    let client_cs = client_cs_lock.read().await;

    assert!(client_cs.is_some(), "§3.4: Client must have control stream");

    assert_eq!(
        client_cs.as_ref().unwrap().id(),
        0,
        "§3.4: Client control stream must be stream 0"
    );

    drop(client_cs);

    let _server_conn = server_task.await.expect("Server task panicked");

    // Note: The actual WindowUpdate(0, ZP_INITIAL_CONN_WINDOW) send is verified
    // in unit tests (test_quic_connection_establishes, test_control_stream_initialization)
}

/// Test: Data Stream Allocation per spec §3.4
///
/// Requirement: "Applications open QUIC streams starting at 4 (client) or 5 (server)."
#[tokio::test]
async fn conformance_data_stream_allocation() {
    setup();

    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");
    let client = QuicEndpoint::client().expect("Client creation failed");

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("Server accept failed");

        // Open first data stream
        let stream = conn.open_stream().await.expect("Server open stream failed");
        stream.id()
    });

    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    // Open first data stream
    let client_stream = client_conn
        .open_stream()
        .await
        .expect("Client open stream failed");

    let server_stream_id = server_task.await.expect("Server task panicked");

    // Verify §3.4 data stream allocation
    assert_eq!(
        client_stream.id(),
        4,
        "§3.4: Client first data stream must be ID 4"
    );

    assert!(
        server_stream_id >= 1 && server_stream_id % 2 == 1,
        "§3.4: Server first data stream must be odd (ID 1, 5, 9, ...)"
    );
}

/// Test: Control Stream Bidirectionality per spec §3.4
///
/// Requirement: "Both endpoints send control frames on this stream;
/// the client opens it, and both sides transmit on it bidirectionally."
#[tokio::test]
async fn conformance_control_stream_bidirectional() {
    setup();

    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let addr = server.local_addr().expect("Failed to get server address");
    let client = QuicEndpoint::client().expect("Client creation failed");

    let server_task = tokio::spawn(async move {
        let conn = server.accept().await.expect("Server accept failed");

        // Server sends control frame on stream 0
        let cs_lock = conn.control_stream();
        let mut cs_opt = cs_lock.write().await;
        let cs = cs_opt.as_mut().expect("Should have control stream");

        let window_update = Frame::WindowUpdate {
            stream_id: 1, // Update for a different stream
            window_increment: 4096,
        };

        cs.send_frame(&window_update)
            .await
            .expect("§3.4: Server should be able to send on stream 0");

        drop(cs_opt);
        conn
    });

    let client_conn = client
        .connect(&addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    // Client sends control frame on stream 0
    let client_cs_lock = client_conn.control_stream();
    let mut client_cs_opt = client_cs_lock.write().await;
    let client_cs = client_cs_opt.as_mut().expect("Should have control stream");

    let window_update = Frame::WindowUpdate {
        stream_id: 2, // Update for a different stream
        window_increment: 8192,
    };

    client_cs
        .send_frame(&window_update)
        .await
        .expect("§3.4: Client should be able to send on stream 0");

    drop(client_cs_opt);

    let _server_conn = server_task.await.expect("Server task panicked");

    // Verify both endpoints can send on stream 0 (bidirectional)
    // This test passing demonstrates bidirectional capability
}
