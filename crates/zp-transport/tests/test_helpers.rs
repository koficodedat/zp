//! Integration test helpers for multi-stream testing.
//!
//! Provides reusable utilities for:
//! - Connection pair setup (client + server)
//! - Batched concurrent stream creation
//! - Stream ID validation
//! - Timeout protection

use futures_util::future;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::task::JoinHandle;
use zp_transport::quic::{QuicConnection, QuicEndpoint, QuicStream};

/// Default timeout for test operations (10 seconds).
pub const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Setup rustls crypto provider (must be called once per test).
pub fn setup_rustls() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Connection pair result.
pub struct ConnectionPair {
    /// Client connection.
    pub client: QuicConnection,
    /// Server connection (future).
    pub server_task: JoinHandle<QuicConnection>,
    /// Server address.
    #[allow(dead_code)]
    pub server_addr: SocketAddr,
}

/// Setup a QUIC client/server connection pair.
///
/// Returns the client connection and a server task that will yield the server connection.
///
/// # Example
///
/// ```no_run
/// let pair = setup_connection_pair().await;
/// let client_conn = pair.client;
/// let server_conn = pair.server_task.await.unwrap();
/// ```
pub async fn setup_connection_pair() -> ConnectionPair {
    setup_rustls();

    // Create server endpoint
    let server = QuicEndpoint::server("127.0.0.1:0")
        .await
        .expect("Server creation failed");

    let server_addr = server.local_addr().expect("Failed to get server address");

    // Spawn server accept task
    let server_task =
        tokio::spawn(async move { server.accept().await.expect("Server accept failed") });

    // Create client and connect
    let client = QuicEndpoint::client().expect("Client creation failed");

    let client_conn = client
        .connect(&server_addr.to_string(), "localhost")
        .await
        .expect("Client connection failed");

    ConnectionPair {
        client: client_conn,
        server_task,
        server_addr,
    }
}

/// Batch configuration for concurrent stream creation.
pub struct BatchConfig {
    /// Total number of streams to create.
    pub total_streams: usize,
    /// Streams per batch.
    pub batch_size: usize,
    /// Delay between batches in milliseconds.
    pub batch_delay_ms: u64,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            total_streams: 100,
            batch_size: 10,
            batch_delay_ms: 10,
        }
    }
}

/// Create multiple streams concurrently with batching and backpressure.
///
/// Returns a vector of successfully created stream IDs.
///
/// # Example
///
/// ```no_run
/// let config = BatchConfig {
///     total_streams: 1000,
///     batch_size: 100,
///     batch_delay_ms: 50,
/// };
///
/// let stream_ids = create_streams_batched(&client_conn, config).await;
/// assert_eq!(stream_ids.len(), 1000);
/// ```
pub async fn create_streams_batched(conn: &QuicConnection, config: BatchConfig) -> Vec<u64> {
    let mut all_stream_ids = Vec::new();
    let num_batches = (config.total_streams + config.batch_size - 1) / config.batch_size;

    for batch_idx in 0..num_batches {
        let streams_in_batch = if batch_idx == num_batches - 1 {
            // Last batch may be smaller
            config.total_streams - (batch_idx * config.batch_size)
        } else {
            config.batch_size
        };

        let mut batch_tasks = Vec::new();

        for _ in 0..streams_in_batch {
            let conn_clone = conn.clone();
            batch_tasks.push(tokio::spawn(async move { conn_clone.open_stream().await }));
        }

        // Wait for batch to complete
        let results = future::join_all(batch_tasks).await;

        let batch_ids: Vec<u64> = results
            .into_iter()
            .filter_map(|r| r.ok().and_then(|s| s.ok().map(|stream| stream.id())))
            .collect();

        all_stream_ids.extend(batch_ids);

        // Pause between batches (except after last batch)
        if batch_idx < num_batches - 1 {
            tokio::time::sleep(Duration::from_millis(config.batch_delay_ms)).await;
        }
    }

    all_stream_ids
}

/// Validate stream IDs for correctness.
///
/// Checks:
/// - All IDs are unique
/// - Client streams have even IDs
/// - Server streams have odd IDs
///
/// # Panics
///
/// Panics if validation fails.
pub fn validate_stream_ids(stream_ids: &[u64], is_client: bool) {
    // Check uniqueness
    let unique_ids: HashSet<u64> = stream_ids.iter().copied().collect();
    assert_eq!(
        unique_ids.len(),
        stream_ids.len(),
        "Stream IDs must be unique (found {} duplicates)",
        stream_ids.len() - unique_ids.len()
    );

    // Check parity (client = even, server = odd)
    for &id in stream_ids {
        let expected_parity = if is_client { 0 } else { 1 };
        let actual_parity = id % 2;

        assert_eq!(
            actual_parity, expected_parity,
            "Stream ID {} has wrong parity (expected {}, got {})",
            id, expected_parity, actual_parity
        );
    }
}

/// Execute an async operation with timeout.
///
/// Returns `Ok(T)` on success, `Err(msg)` on timeout.
///
/// # Example
///
/// ```no_run
/// let result = with_timeout("stream creation", async {
///     conn.open_stream().await
/// }).await;
///
/// assert!(result.is_ok());
/// ```
pub async fn with_timeout<F, T>(operation_name: &str, future: F) -> Result<T, String>
where
    F: std::future::Future<Output = T>,
{
    match tokio::time::timeout(TEST_TIMEOUT, future).await {
        Ok(result) => Ok(result),
        Err(_) => Err(format!(
            "{} timed out after {:?}",
            operation_name, TEST_TIMEOUT
        )),
    }
}

/// Helper for rapid stream creation stress test.
///
/// Creates `count` streams as fast as possible without batching delays.
///
/// Returns (successful_ids, failed_count).
#[allow(dead_code)]
pub async fn rapid_stream_creation(conn: &QuicConnection, count: usize) -> (Vec<u64>, usize) {
    let mut tasks = Vec::new();

    for _ in 0..count {
        let conn_clone = conn.clone();
        tasks.push(tokio::spawn(async move { conn_clone.open_stream().await }));
    }

    let results = future::join_all(tasks).await;

    let mut successful_ids = Vec::new();
    let mut failed_count = 0;

    for result in results {
        match result {
            Ok(Ok(stream)) => successful_ids.push(stream.id()),
            _ => failed_count += 1,
        }
    }

    (successful_ids, failed_count)
}

/// Accept multiple streams on the server side.
///
/// Returns a vector of successfully accepted streams.
///
/// # Example
///
/// ```no_run
/// let streams = accept_streams(&server_conn, 10).await;
/// assert_eq!(streams.len(), 10);
/// ```
pub async fn accept_streams(conn: &QuicConnection, count: usize) -> Vec<QuicStream> {
    let mut streams = Vec::new();

    for _ in 0..count {
        match conn.accept_stream().await {
            Ok(stream) => streams.push(stream),
            Err(e) => {
                eprintln!("Failed to accept stream: {}", e);
                break;
            }
        }
    }

    streams
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_pair_setup() {
        let pair = setup_connection_pair().await;
        let server_conn = pair.server_task.await.expect("Server task failed");

        // Connections established successfully - verify session exists
        let client_session = pair.client.session();
        let server_session = server_conn.session();

        // Both should have sessions (Arc<RwLock<Session>>)
        assert!(client_session.try_read().is_ok());
        assert!(server_session.try_read().is_ok());
    }

    #[tokio::test]
    async fn test_stream_id_validation() {
        // Client streams (even IDs)
        let client_ids = vec![0, 2, 4, 6];
        validate_stream_ids(&client_ids, true); // Should not panic

        // Server streams (odd IDs)
        let server_ids = vec![1, 3, 5, 7];
        validate_stream_ids(&server_ids, false); // Should not panic
    }

    #[tokio::test]
    #[should_panic(expected = "Stream IDs must be unique")]
    async fn test_stream_id_validation_duplicates() {
        let ids = vec![0, 2, 2, 4]; // Duplicate ID 2
        validate_stream_ids(&ids, true);
    }

    #[tokio::test]
    #[should_panic(expected = "has wrong parity")]
    async fn test_stream_id_validation_wrong_parity() {
        let ids = vec![0, 2, 3, 4]; // ID 3 is odd (server), but we say it's client
        validate_stream_ids(&ids, true);
    }

    #[tokio::test]
    async fn test_with_timeout_success() {
        let result = with_timeout("test operation", async {
            tokio::time::sleep(Duration::from_millis(10)).await;
            42
        })
        .await;

        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_with_timeout_failure() {
        let result = with_timeout("slow operation", async {
            tokio::time::sleep(Duration::from_secs(15)).await; // Exceeds TEST_TIMEOUT
            42
        })
        .await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timed out"));
    }
}
