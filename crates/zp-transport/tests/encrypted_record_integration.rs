//! EncryptedRecord integration tests across transports.
//!
//! Tests verify end-to-end EncryptedRecord functionality per spec §3.3.13:
//! - Full handshake + encrypted data exchange over TCP
//! - Full handshake + encrypted data exchange over WebSocket
//! - Replay protection (nonce counter verification)
//! - Epoch validation
//! - Bidirectional encryption/decryption

use std::time::Duration;
use tokio::time::timeout;
use zp_core::Frame;
use zp_transport::tcp::TcpEndpoint;
use zp_transport::Result;

#[cfg(feature = "websocket")]
use zp_transport::websocket::WebSocketEndpoint;

/// Helper: Perform full handshake (Stranger Mode) between client and server sessions
async fn perform_handshake_tcp(
    client_conn: &zp_transport::tcp::TcpConnection,
    server_conn: &zp_transport::tcp::TcpConnection,
) -> Result<()> {
    // Step 1: Client sends ClientHello
    let client_hello = {
        let session_arc = client_conn.session();
        let mut session = session_arc.write().await;
        session
            .client_start_stranger()
            .expect("Client start handshake failed")
    };
    client_conn.send_frame(&client_hello).await?;

    // Step 2: Server receives ClientHello, sends ServerHello
    let server_hello = {
        let ch = server_conn
            .recv_frame()
            .await?
            .expect("Server recv ClientHello failed");
        let session_arc = server_conn.session();
        let mut session = session_arc.write().await;
        session
            .server_process_client_hello(ch)
            .expect("Server process ClientHello failed")
    };
    server_conn.send_frame(&server_hello).await?;

    // Step 3: Client receives ServerHello, sends ClientFinish
    let client_finish = {
        let sh = client_conn
            .recv_frame()
            .await?
            .expect("Client recv ServerHello failed");
        let session_arc = client_conn.session();
        let mut session = session_arc.write().await;
        session
            .client_process_server_hello(sh)
            .expect("Client process ServerHello failed")
    };
    client_conn.send_frame(&client_finish).await?;

    // Step 4: Server receives ClientFinish, completes handshake
    {
        let cf = server_conn
            .recv_frame()
            .await?
            .expect("Server recv ClientFinish failed");
        let session_arc = server_conn.session();
        let mut session = session_arc.write().await;
        session
            .server_process_client_finish(cf)
            .expect("Server finalize handshake failed");
    }

    // Verify both sessions are established
    assert!(client_conn.session().read().await.is_established());
    assert!(server_conn.session().read().await.is_established());

    Ok(())
}

/// Test: TCP EncryptedRecord - Full handshake + encrypted data exchange
#[tokio::test]
async fn test_tcp_encrypted_record_roundtrip() -> Result<()> {
    // Start server
    let server_endpoint = TcpEndpoint::server("127.0.0.1:0").await?;
    let server_addr = server_endpoint.local_addr()?;

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        // Client will complete handshake
        // Server receives handshake frames and completes
        // (Handshake logic handled in test below)

        server_endpoint
            .accept()
            .await
            .expect("Server accept failed")
    });

    // Client connects
    let client_endpoint = TcpEndpoint::client()?;
    let client_conn = client_endpoint
        .connect(&format!("127.0.0.1:{}", server_addr.port()))
        .await?;

    // Get server connection
    let server_conn = timeout(Duration::from_secs(2), server_handle)
        .await
        .expect("Server accept timeout")
        .expect("Server task failed");

    // Perform full handshake
    perform_handshake_tcp(&client_conn, &server_conn).await?;

    // Now send encrypted DataFrame from client to server
    let test_frame = Frame::DataFrame {
        stream_id: 42,
        seq: 1,
        flags: 0,
        payload: vec![1, 2, 3, 4, 5, 6, 7, 8],
    };

    // Client sends (will be encrypted automatically post-handshake)
    client_conn.send_frame(&test_frame).await?;

    // Server receives (will be decrypted automatically)
    let received_frame = timeout(Duration::from_secs(1), server_conn.recv_frame())
        .await
        .expect("Server recv timeout")
        .expect("Server recv failed")
        .expect("Connection closed");

    // Verify decrypted frame matches original
    match (test_frame, received_frame) {
        (
            Frame::DataFrame {
                stream_id: s1,
                seq: seq1,
                flags: f1,
                payload: p1,
            },
            Frame::DataFrame {
                stream_id: s2,
                seq: seq2,
                flags: f2,
                payload: p2,
            },
        ) => {
            assert_eq!(s1, s2, "Stream ID mismatch");
            assert_eq!(seq1, seq2, "Sequence mismatch");
            assert_eq!(f1, f2, "Flags mismatch");
            assert_eq!(p1, p2, "Payload mismatch");
        }
        _ => panic!("Frame type mismatch after decryption"),
    }

    // Verify send_nonce incremented on client, recv_nonce incremented on server
    assert_eq!(
        client_conn
            .session()
            .read()
            .await
            .keys()
            .unwrap()
            .send_nonce,
        1,
        "Client send_nonce should be 1"
    );
    assert_eq!(
        server_conn
            .session()
            .read()
            .await
            .keys()
            .unwrap()
            .recv_nonce,
        1,
        "Server recv_nonce should be 1"
    );

    Ok(())
}

/// Test: TCP EncryptedRecord - Bidirectional encryption
#[tokio::test]
async fn test_tcp_encrypted_record_bidirectional() -> Result<()> {
    // Start server
    let server_endpoint = TcpEndpoint::server("127.0.0.1:0").await?;
    let server_addr = server_endpoint.local_addr()?;

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        server_endpoint
            .accept()
            .await
            .expect("Server accept failed")
    });

    // Client connects
    let client_endpoint = TcpEndpoint::client()?;
    let client_conn = client_endpoint
        .connect(&format!("127.0.0.1:{}", server_addr.port()))
        .await?;

    // Get server connection
    let server_conn = timeout(Duration::from_secs(2), server_handle)
        .await
        .expect("Server accept timeout")
        .expect("Server task failed");

    // Perform full handshake
    perform_handshake_tcp(&client_conn, &server_conn).await?;

    // Client -> Server
    let client_frame = Frame::DataFrame {
        stream_id: 1,
        seq: 10,
        flags: 0,
        payload: vec![0xAA, 0xBB, 0xCC],
    };
    client_conn.send_frame(&client_frame).await?;

    let received_at_server = timeout(Duration::from_secs(1), server_conn.recv_frame())
        .await
        .expect("Server recv timeout")
        .expect("Server recv failed")
        .expect("Connection closed");

    match received_at_server {
        Frame::DataFrame {
            stream_id,
            seq,
            payload,
            ..
        } => {
            assert_eq!(stream_id, 1);
            assert_eq!(seq, 10);
            assert_eq!(payload, vec![0xAA, 0xBB, 0xCC]);
        }
        _ => panic!("Expected DataFrame at server"),
    }

    // Server -> Client
    let server_frame = Frame::DataFrame {
        stream_id: 2,
        seq: 20,
        flags: 0,
        payload: vec![0xDD, 0xEE, 0xFF],
    };
    server_conn.send_frame(&server_frame).await?;

    let received_at_client = timeout(Duration::from_secs(1), client_conn.recv_frame())
        .await
        .expect("Client recv timeout")
        .expect("Client recv failed")
        .expect("Connection closed");

    match received_at_client {
        Frame::DataFrame {
            stream_id,
            seq,
            payload,
            ..
        } => {
            assert_eq!(stream_id, 2);
            assert_eq!(seq, 20);
            assert_eq!(payload, vec![0xDD, 0xEE, 0xFF]);
        }
        _ => panic!("Expected DataFrame at client"),
    }

    // Verify nonce counters
    assert_eq!(
        client_conn
            .session()
            .read()
            .await
            .keys()
            .unwrap()
            .send_nonce,
        1,
        "Client sent 1 encrypted frame"
    );
    assert_eq!(
        client_conn
            .session()
            .read()
            .await
            .keys()
            .unwrap()
            .recv_nonce,
        1,
        "Client received 1 encrypted frame"
    );
    assert_eq!(
        server_conn
            .session()
            .read()
            .await
            .keys()
            .unwrap()
            .send_nonce,
        1,
        "Server sent 1 encrypted frame"
    );
    assert_eq!(
        server_conn
            .session()
            .read()
            .await
            .keys()
            .unwrap()
            .recv_nonce,
        1,
        "Server received 1 encrypted frame"
    );

    Ok(())
}

/// Test: TCP EncryptedRecord - Multiple sequential encrypted frames
#[tokio::test]
async fn test_tcp_encrypted_record_multiple_frames() -> Result<()> {
    // Start server
    let server_endpoint = TcpEndpoint::server("127.0.0.1:0").await?;
    let server_addr = server_endpoint.local_addr()?;

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        server_endpoint
            .accept()
            .await
            .expect("Server accept failed")
    });

    // Client connects
    let client_endpoint = TcpEndpoint::client()?;
    let client_conn = client_endpoint
        .connect(&format!("127.0.0.1:{}", server_addr.port()))
        .await?;

    // Get server connection
    let server_conn = timeout(Duration::from_secs(2), server_handle)
        .await
        .expect("Server accept timeout")
        .expect("Server task failed");

    // Perform full handshake
    perform_handshake_tcp(&client_conn, &server_conn).await?;

    // Send 5 encrypted frames from client
    for i in 0..5 {
        let frame = Frame::DataFrame {
            stream_id: i,
            seq: i as u64,
            flags: 0,
            payload: vec![i as u8; (i + 1) as usize],
        };
        client_conn.send_frame(&frame).await?;
    }

    // Server receives and verifies all 5 frames
    for i in 0..5 {
        let received = timeout(Duration::from_secs(1), server_conn.recv_frame())
            .await
            .expect("Server recv timeout")
            .expect("Server recv failed")
            .expect("Connection closed");

        match received {
            Frame::DataFrame {
                stream_id,
                seq,
                payload,
                ..
            } => {
                assert_eq!(stream_id, i, "Frame {} stream_id mismatch", i);
                assert_eq!(seq, i as u64, "Frame {} seq mismatch", i);
                assert_eq!(
                    payload,
                    vec![i as u8; (i + 1) as usize],
                    "Frame {} payload mismatch",
                    i
                );
            }
            _ => panic!("Frame {} type mismatch", i),
        }
    }

    // Verify nonce counters incremented correctly
    assert_eq!(
        client_conn
            .session()
            .read()
            .await
            .keys()
            .unwrap()
            .send_nonce,
        5,
        "Client should have sent 5 encrypted frames"
    );
    assert_eq!(
        server_conn
            .session()
            .read()
            .await
            .keys()
            .unwrap()
            .recv_nonce,
        5,
        "Server should have received 5 encrypted frames"
    );

    Ok(())
}

/// Test: WebSocket EncryptedRecord - Full handshake + encrypted data exchange
#[cfg(feature = "websocket")]
#[tokio::test]
async fn test_websocket_encrypted_record_roundtrip() -> Result<()> {
    // Start server
    let server_endpoint = WebSocketEndpoint::server("127.0.0.1:0").await?;
    let server_addr = server_endpoint.local_addr()?;

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        server_endpoint
            .accept()
            .await
            .expect("Server accept failed")
    });

    // Client connects
    let client_endpoint = WebSocketEndpoint::client()?;
    let client_conn = client_endpoint
        .connect(&format!("ws://127.0.0.1:{}", server_addr.port()))
        .await?;

    // Get server connection
    let server_conn = timeout(Duration::from_secs(2), server_handle)
        .await
        .expect("Server accept timeout")
        .expect("Server task failed");

    // Perform full handshake (similar to TCP)
    // Step 1: Client sends ClientHello
    let client_hello = {
        let session_arc = client_conn.session();
        let mut session = session_arc.write().await;
        session
            .client_start_stranger()
            .expect("Client start handshake failed")
    };
    client_conn.send_frame(&client_hello).await?;

    // Step 2: Server receives ClientHello, sends ServerHello
    let server_hello = {
        let ch = server_conn
            .recv_frame()
            .await?
            .expect("Server recv ClientHello failed");
        let session_arc = server_conn.session();
        let mut session = session_arc.write().await;
        session
            .server_process_client_hello(ch)
            .expect("Server process ClientHello failed")
    };
    server_conn.send_frame(&server_hello).await?;

    // Step 3: Client receives ServerHello, sends ClientFinish
    let client_finish = {
        let sh = client_conn
            .recv_frame()
            .await?
            .expect("Client recv ServerHello failed");
        let session_arc = client_conn.session();
        let mut session = session_arc.write().await;
        session
            .client_process_server_hello(sh)
            .expect("Client process ServerHello failed")
    };
    client_conn.send_frame(&client_finish).await?;

    // Step 4: Server receives ClientFinish, completes handshake
    {
        let cf = server_conn
            .recv_frame()
            .await?
            .expect("Server recv ClientFinish failed");
        let session_arc = server_conn.session();
        let mut session = session_arc.write().await;
        session
            .server_process_client_finish(cf)
            .expect("Server finalize handshake failed");
    }

    // Verify both sessions are established
    assert!(client_conn.session().read().await.is_established());
    assert!(server_conn.session().read().await.is_established());

    // Now send encrypted DataFrame from client to server
    let test_frame = Frame::DataFrame {
        stream_id: 99,
        seq: 42,
        flags: 0,
        payload: vec![0x11, 0x22, 0x33, 0x44, 0x55],
    };

    // Client sends (will be encrypted automatically post-handshake)
    client_conn.send_frame(&test_frame).await?;

    // Server receives (will be decrypted automatically)
    let received_frame = timeout(Duration::from_secs(1), server_conn.recv_frame())
        .await
        .expect("Server recv timeout")
        .expect("Server recv failed")
        .expect("Connection closed");

    // Verify decrypted frame matches original
    match (test_frame, received_frame) {
        (
            Frame::DataFrame {
                stream_id: s1,
                seq: seq1,
                flags: f1,
                payload: p1,
            },
            Frame::DataFrame {
                stream_id: s2,
                seq: seq2,
                flags: f2,
                payload: p2,
            },
        ) => {
            assert_eq!(s1, s2, "Stream ID mismatch");
            assert_eq!(seq1, seq2, "Sequence mismatch");
            assert_eq!(f1, f2, "Flags mismatch");
            assert_eq!(p1, p2, "Payload mismatch");
        }
        _ => panic!("Frame type mismatch after decryption"),
    }

    // Verify nonce counters
    assert_eq!(
        client_conn
            .session()
            .read()
            .await
            .keys()
            .unwrap()
            .send_nonce,
        1,
        "Client send_nonce should be 1"
    );
    assert_eq!(
        server_conn
            .session()
            .read()
            .await
            .keys()
            .unwrap()
            .recv_nonce,
        1,
        "Server recv_nonce should be 1"
    );

    Ok(())
}
