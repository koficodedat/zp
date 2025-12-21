//! TCP transport integration tests.
//!
//! Tests verify end-to-end TCP transport functionality:
//! - Connection establishment (client/server)
//! - Bidirectional frame exchange
//! - Session state integration
//! - StreamChunk multiplexing
//! - Length-prefixed framing

use std::time::Duration;
use tokio::time::timeout;
use zp_core::session::{HandshakeMode, Role};
use zp_core::Frame;
use zp_transport::tcp::{StreamChunk, TcpEndpoint};
use zp_transport::Result;

/// Test: TCP connection establishment (client connects to server)
#[tokio::test]
async fn test_tcp_connection_establishment() -> Result<()> {
    // Start server
    let server_endpoint = TcpEndpoint::server("127.0.0.1:0").await?;
    let server_addr = server_endpoint.local_addr()?;

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let conn = server_endpoint
            .accept()
            .await
            .expect("Server accept failed");

        // Verify session created with Server role
        let session = conn.session();
        let session_guard = session.read().await;
        assert_eq!(session_guard.role(), Role::Server);
        assert_eq!(session_guard.mode(), HandshakeMode::Stranger);

        conn
    });

    // Client connects
    let client_endpoint = TcpEndpoint::client()?;
    let client_conn = client_endpoint
        .connect(&format!("127.0.0.1:{}", server_addr.port()))
        .await?;

    // Verify session created with Client role
    let session = client_conn.session();
    let session_guard = session.read().await;
    assert_eq!(session_guard.role(), Role::Client);
    assert_eq!(session_guard.mode(), HandshakeMode::Stranger);

    // Verify server accepted connection
    let _server_conn = timeout(Duration::from_secs(1), server_handle)
        .await
        .expect("Server timeout")
        .expect("Server task failed");

    Ok(())
}

/// Test: Bidirectional frame exchange over TCP
#[tokio::test]
async fn test_tcp_bidirectional_frame_exchange() -> Result<()> {
    // Start server
    let server_endpoint = TcpEndpoint::server("127.0.0.1:0").await?;
    let server_addr = server_endpoint.local_addr()?;

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let conn = server_endpoint
            .accept()
            .await
            .expect("Server accept failed");

        // Receive frame from client
        let frame = conn
            .recv_frame()
            .await
            .expect("Server recv failed")
            .expect("Connection closed");

        // Verify it's a DataFrame
        match frame {
            Frame::DataFrame { .. } => {}
            _ => panic!("Expected DataFrame"),
        }

        // Send response frame
        let response = Frame::DataFrame {
            stream_id: 0,
            seq: 0,
            flags: 0,
            payload: vec![5, 6, 7, 8],
        };
        conn.send_frame(&response)
            .await
            .expect("Server send failed");

        conn
    });

    // Client connects
    let client_endpoint = TcpEndpoint::client()?;
    let client_conn = client_endpoint
        .connect(&format!("127.0.0.1:{}", server_addr.port()))
        .await?;

    // Send frame to server
    let request = Frame::DataFrame {
        stream_id: 0,
        seq: 0,
        flags: 0,
        payload: vec![1, 2, 3, 4],
    };
    client_conn.send_frame(&request).await?;

    // Receive response from server
    let response = timeout(Duration::from_secs(1), client_conn.recv_frame())
        .await
        .expect("Client recv timeout")
        .expect("Client recv failed")
        .expect("Connection closed");

    // Verify it's a DataFrame
    match response {
        Frame::DataFrame { .. } => {}
        _ => panic!("Expected DataFrame"),
    }

    // Wait for server to complete
    let _server_conn = timeout(Duration::from_secs(1), server_handle)
        .await
        .expect("Server timeout")
        .expect("Server task failed");

    Ok(())
}

/// Test: TCP connection lifecycle (connect, send, recv, close)
#[tokio::test]
async fn test_tcp_connection_lifecycle() -> Result<()> {
    // Start server
    let server_endpoint = TcpEndpoint::server("127.0.0.1:0").await?;
    let server_addr = server_endpoint.local_addr()?;

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let conn = server_endpoint
            .accept()
            .await
            .expect("Server accept failed");

        // Receive frame
        let _frame = conn
            .recv_frame()
            .await
            .expect("Server recv failed")
            .expect("Connection closed");

        // Close connection
        conn.close().await.expect("Server close failed");
    });

    // Client connects
    let client_endpoint = TcpEndpoint::client()?;
    let client_conn = client_endpoint
        .connect(&format!("127.0.0.1:{}", server_addr.port()))
        .await?;

    // Send frame
    let frame = Frame::DataFrame {
        stream_id: 0,
        seq: 0,
        flags: 0,
        payload: vec![1, 2, 3, 4],
    };
    client_conn.send_frame(&frame).await?;

    // Wait for server to close
    timeout(Duration::from_secs(1), server_handle)
        .await
        .expect("Server timeout")
        .expect("Server task failed");

    // Client attempts to receive (should detect closed connection)
    let result = timeout(Duration::from_secs(1), client_conn.recv_frame()).await;
    assert!(result.is_ok(), "Recv should complete (detecting closure)");

    Ok(())
}

/// Test: Multiple frames over single TCP connection
#[tokio::test]
async fn test_tcp_multiple_frames() -> Result<()> {
    // Start server
    let server_endpoint = TcpEndpoint::server("127.0.0.1:0").await?;
    let server_addr = server_endpoint.local_addr()?;

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let conn = server_endpoint
            .accept()
            .await
            .expect("Server accept failed");

        // Receive 3 frames
        for _ in 0..3 {
            let frame = conn
                .recv_frame()
                .await
                .expect("Server recv failed")
                .expect("Connection closed");

            // Verify it's a DataFrame
            match frame {
                Frame::DataFrame { .. } => {}
                _ => panic!("Expected DataFrame"),
            }
        }

        conn
    });

    // Client connects
    let client_endpoint = TcpEndpoint::client()?;
    let client_conn = client_endpoint
        .connect(&format!("127.0.0.1:{}", server_addr.port()))
        .await?;

    // Send 3 frames
    for i in 0..3 {
        let frame = Frame::DataFrame {
            stream_id: 0,
            seq: i,
            flags: 0,
            payload: vec![i as u8, i as u8 + 1, i as u8 + 2],
        };
        client_conn.send_frame(&frame).await?;
    }

    // Wait for server to complete
    let _server_conn = timeout(Duration::from_secs(1), server_handle)
        .await
        .expect("Server timeout")
        .expect("Server task failed");

    Ok(())
}

/// Test: StreamChunk multiplexing over TCP per spec §3.3.7
#[tokio::test]
async fn test_tcp_stream_chunk_multiplexing() -> Result<()> {
    // Start server
    let server_endpoint = TcpEndpoint::server("127.0.0.1:0").await?;
    let server_addr = server_endpoint.local_addr()?;

    // Spawn server task
    let server_handle = tokio::spawn(async move {
        let conn = server_endpoint
            .accept()
            .await
            .expect("Server accept failed");

        // Receive StreamChunks from different streams
        let chunk1 = conn
            .recv_stream_chunk()
            .await
            .expect("Server recv chunk 1 failed")
            .expect("Connection closed");
        assert_eq!(chunk1.stream_id, 1);
        assert_eq!(chunk1.payload, vec![1, 2, 3]);

        let chunk2 = conn
            .recv_stream_chunk()
            .await
            .expect("Server recv chunk 2 failed")
            .expect("Connection closed");
        assert_eq!(chunk2.stream_id, 2);
        assert_eq!(chunk2.payload, vec![4, 5, 6]);

        // Send response chunks
        let response1 = StreamChunk {
            stream_id: 1,
            payload: vec![10, 11, 12],
        };
        conn.send_stream_chunk(&response1)
            .await
            .expect("Server send chunk 1 failed");

        let response2 = StreamChunk {
            stream_id: 2,
            payload: vec![13, 14, 15],
        };
        conn.send_stream_chunk(&response2)
            .await
            .expect("Server send chunk 2 failed");

        conn
    });

    // Client connects
    let client_endpoint = TcpEndpoint::client()?;
    let client_conn = client_endpoint
        .connect(&format!("127.0.0.1:{}", server_addr.port()))
        .await?;

    // Send StreamChunks for different streams
    let chunk1 = StreamChunk {
        stream_id: 1,
        payload: vec![1, 2, 3],
    };
    client_conn.send_stream_chunk(&chunk1).await?;

    let chunk2 = StreamChunk {
        stream_id: 2,
        payload: vec![4, 5, 6],
    };
    client_conn.send_stream_chunk(&chunk2).await?;

    // Receive response chunks
    let response1 = timeout(Duration::from_secs(1), client_conn.recv_stream_chunk())
        .await
        .expect("Client recv chunk 1 timeout")
        .expect("Client recv chunk 1 failed")
        .expect("Connection closed");
    assert_eq!(response1.stream_id, 1);
    assert_eq!(response1.payload, vec![10, 11, 12]);

    let response2 = timeout(Duration::from_secs(1), client_conn.recv_stream_chunk())
        .await
        .expect("Client recv chunk 2 timeout")
        .expect("Client recv chunk 2 failed")
        .expect("Connection closed");
    assert_eq!(response2.stream_id, 2);
    assert_eq!(response2.payload, vec![13, 14, 15]);

    // Wait for server to complete
    let _server_conn = timeout(Duration::from_secs(1), server_handle)
        .await
        .expect("Server timeout")
        .expect("Server task failed");

    Ok(())
}
