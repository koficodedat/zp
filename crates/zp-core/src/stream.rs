//! Stream multiplexing and flow control.
//!
//! Implements:
//! - Stream lifecycle management (§3.3.11)
//! - Flow control per spec §3.3.9
//! - Priority scheduling per spec §3.3.8
//!
//! Flow control operates at two levels:
//! - Connection-level: Limits total bytes across all streams
//! - Stream-level: Limits bytes per individual stream

use crate::{Error, Result};
use std::collections::{HashMap, VecDeque};

/// Flow control constants per spec Appendix C.
/// Initial connection-level flow control window (1 MB).
pub const ZP_INITIAL_CONN_WINDOW: u32 = 1_048_576;
/// Initial stream-level flow control window (256 KB).
pub const ZP_INITIAL_STREAM_WINDOW: u32 = 262_144;
/// Flow control timeout in milliseconds (30 seconds).
pub const ZP_FLOW_TIMEOUT_MS: u64 = 30_000;

/// A multiplexed stream within a session.
pub struct Stream {
    /// Stream identifier.
    id: u32,
    /// Current state.
    state: StreamState,
    /// Send window (bytes available to send).
    send_window: u32,
    /// Receive window (bytes available to receive).
    recv_window: u32,
    /// Bytes consumed by application (triggers WindowUpdate).
    consumed: u32,
    /// Priority (1-255, higher is more urgent).
    priority: u8,
    /// Send buffer for outgoing data.
    send_buffer: VecDeque<u8>,
    /// Receive buffer for incoming data.
    recv_buffer: VecDeque<u8>,
    /// Global sequence number for this stream.
    global_seq: u64,
    /// Last acknowledged byte.
    last_acked: u64,
}

/// Stream states per spec §3.3.11.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is open and can send/receive data.
    Open,
    /// Local side closed (sent FIN).
    HalfClosedLocal,
    /// Remote side closed (received FIN).
    HalfClosedRemote,
    /// Both sides closed.
    Closed,
}

impl Stream {
    /// Create a new stream with given ID.
    pub fn new(id: u32, initial_window: u32) -> Self {
        Self {
            id,
            state: StreamState::Open,
            send_window: initial_window,
            recv_window: initial_window,
            consumed: 0,
            priority: 128, // Default priority
            send_buffer: VecDeque::new(),
            recv_buffer: VecDeque::new(),
            global_seq: 0,
            last_acked: 0,
        }
    }

    /// Get stream ID.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Get current state.
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// Check if stream can send data.
    pub fn can_send(&self) -> bool {
        matches!(
            self.state,
            StreamState::Open | StreamState::HalfClosedRemote
        )
    }

    /// Check if stream can receive data.
    pub fn can_recv(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal)
    }

    /// Queue data for sending (respects flow control).
    ///
    /// Returns the number of bytes queued (may be less than data.len() if window exhausted).
    pub fn queue_send(&mut self, data: &[u8]) -> Result<usize> {
        if !self.can_send() {
            return Err(Error::StreamClosed);
        }

        // Limit by send window
        let to_send = (data.len() as u32).min(self.send_window) as usize;

        if to_send == 0 {
            return Ok(0); // Window exhausted
        }

        self.send_buffer.extend(&data[..to_send]);
        self.send_window -= to_send as u32;
        self.global_seq += to_send as u64;

        Ok(to_send)
    }

    /// Dequeue data to transmit (up to max_bytes).
    ///
    /// Returns the dequeued bytes ready for transmission.
    pub fn dequeue_send(&mut self, max_bytes: usize) -> Vec<u8> {
        let to_dequeue = max_bytes.min(self.send_buffer.len());
        self.send_buffer.drain(..to_dequeue).collect()
    }

    /// Get number of bytes queued for sending.
    pub fn send_buffered(&self) -> usize {
        self.send_buffer.len()
    }

    /// Receive data into stream buffer.
    pub fn receive_data(&mut self, data: &[u8]) -> Result<()> {
        if !self.can_recv() {
            return Err(Error::StreamClosed);
        }

        // Check receive window
        if data.len() as u32 > self.recv_window {
            return Err(Error::ProtocolViolation("Flow control violation".into()));
        }

        self.recv_buffer.extend(data);
        self.recv_window -= data.len() as u32;

        Ok(())
    }

    /// Read data from receive buffer (application consumption).
    ///
    /// Returns available data and indicates if WindowUpdate should be sent.
    pub fn read(&mut self, max_bytes: usize) -> (Vec<u8>, bool) {
        let to_read = max_bytes.min(self.recv_buffer.len());
        let data: Vec<u8> = self.recv_buffer.drain(..to_read).collect();

        // Track consumed bytes
        self.consumed += data.len() as u32;

        // Check if we should send WindowUpdate (§3.3.9: when consumed >= initial_window / 2)
        let should_update = self.consumed >= ZP_INITIAL_STREAM_WINDOW / 2;

        (data, should_update)
    }

    /// Generate WindowUpdate increment and reset consumed counter.
    ///
    /// Returns the window increment to send (0 if no update needed).
    pub fn generate_window_update(&mut self) -> u32 {
        if self.consumed == 0 {
            return 0;
        }

        let increment = self.consumed;
        self.consumed = 0;

        // Update receive window with saturating addition
        self.recv_window = self.recv_window.saturating_add(increment);

        increment
    }

    /// Update send window (received WindowUpdate from peer).
    ///
    /// Per spec §3.3.9: use saturating addition.
    pub fn update_send_window(&mut self, increment: u32) {
        self.send_window = self.send_window.saturating_add(increment);
    }

    /// Close this stream for sending (send FIN).
    pub fn close_send(&mut self) -> Result<()> {
        match self.state {
            StreamState::Open => {
                self.state = StreamState::HalfClosedLocal;
                Ok(())
            }
            StreamState::HalfClosedRemote => {
                self.state = StreamState::Closed;
                Ok(())
            }
            _ => Err(Error::StreamClosed),
        }
    }

    /// Mark remote side as closed (received FIN).
    pub fn close_recv(&mut self) -> Result<()> {
        match self.state {
            StreamState::Open => {
                self.state = StreamState::HalfClosedRemote;
                Ok(())
            }
            StreamState::HalfClosedLocal => {
                self.state = StreamState::Closed;
                Ok(())
            }
            _ => Err(Error::StreamClosed),
        }
    }

    /// Update priority.
    pub fn set_priority(&mut self, priority: u8) {
        // Per spec §3.3.8: priority 0 is clamped to 1
        self.priority = priority.max(1);
    }

    /// Get current priority.
    pub fn priority(&self) -> u8 {
        self.priority
    }

    /// Get global sequence number.
    pub fn global_seq(&self) -> u64 {
        self.global_seq
    }

    /// Get last acknowledged byte.
    pub fn last_acked(&self) -> u64 {
        self.last_acked
    }

    /// Acknowledge sent bytes.
    pub fn acknowledge(&mut self, acked_seq: u64) {
        self.last_acked = self.last_acked.max(acked_seq);
    }
}

/// Stream multiplexer with connection-level flow control.
pub struct StreamMultiplexer {
    /// Active streams indexed by ID.
    streams: HashMap<u32, Stream>,
    /// Connection-level send window.
    conn_send_window: u32,
    /// Connection-level receive window.
    conn_recv_window: u32,
    /// Connection-level consumed bytes.
    conn_consumed: u32,
    /// Next stream ID to allocate (even for client, odd for server).
    next_stream_id: u32,
}

impl StreamMultiplexer {
    /// Create a new multiplexer.
    ///
    /// `is_client`: true if this is the client side (uses even stream IDs).
    pub fn new(is_client: bool) -> Self {
        Self {
            streams: HashMap::new(),
            conn_send_window: ZP_INITIAL_CONN_WINDOW,
            conn_recv_window: ZP_INITIAL_CONN_WINDOW,
            conn_consumed: 0,
            next_stream_id: if is_client { 0 } else { 1 },
        }
    }

    /// Open a new stream.
    ///
    /// Returns the stream ID.
    pub fn open_stream(&mut self) -> u32 {
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2; // Even IDs for client, odd for server

        let stream = Stream::new(stream_id, ZP_INITIAL_STREAM_WINDOW);
        self.streams.insert(stream_id, stream);

        stream_id
    }

    /// Get a stream by ID.
    pub fn get_stream(&self, stream_id: u32) -> Option<&Stream> {
        self.streams.get(&stream_id)
    }

    /// Get a mutable stream by ID.
    pub fn get_stream_mut(&mut self, stream_id: u32) -> Option<&mut Stream> {
        self.streams.get_mut(&stream_id)
    }

    /// Queue data for sending on a stream (respects both stream and connection flow control).
    ///
    /// Returns the number of bytes queued.
    pub fn send(&mut self, stream_id: u32, data: &[u8]) -> Result<usize> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(Error::ProtocolViolation("Unknown stream".into()))?;

        // Limit by minimum of stream window and connection window
        let max_send = (data.len() as u32)
            .min(stream.send_window)
            .min(self.conn_send_window);

        if max_send == 0 {
            return Ok(0); // Both windows exhausted
        }

        let queued = stream.queue_send(&data[..max_send as usize])?;

        // Decrement connection-level window
        self.conn_send_window -= queued as u32;

        Ok(queued)
    }

    /// Receive data on a stream.
    pub fn receive(&mut self, stream_id: u32, data: &[u8]) -> Result<()> {
        // Check connection-level flow control first
        if data.len() as u32 > self.conn_recv_window {
            return Err(Error::ProtocolViolation(
                "Connection flow control violation".into(),
            ));
        }

        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(Error::ProtocolViolation("Unknown stream".into()))?;

        stream.receive_data(data)?;

        // Decrement connection-level window
        self.conn_recv_window -= data.len() as u32;

        Ok(())
    }

    /// Read data from a stream (application consumption).
    ///
    /// Returns (data, stream_needs_update, conn_needs_update).
    pub fn read(&mut self, stream_id: u32, max_bytes: usize) -> Result<(Vec<u8>, bool, bool)> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(Error::ProtocolViolation("Unknown stream".into()))?;

        let (data, stream_needs_update) = stream.read(max_bytes);

        // Track connection-level consumption
        self.conn_consumed += data.len() as u32;

        // Check if connection-level WindowUpdate needed
        let conn_needs_update = self.conn_consumed >= ZP_INITIAL_CONN_WINDOW / 2;

        Ok((data, stream_needs_update, conn_needs_update))
    }

    /// Generate stream-level WindowUpdate.
    pub fn generate_stream_window_update(&mut self, stream_id: u32) -> Result<u32> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(Error::ProtocolViolation("Unknown stream".into()))?;

        Ok(stream.generate_window_update())
    }

    /// Generate connection-level WindowUpdate.
    pub fn generate_conn_window_update(&mut self) -> u32 {
        if self.conn_consumed == 0 {
            return 0;
        }

        let increment = self.conn_consumed;
        self.conn_consumed = 0;

        // Update receive window with saturating addition
        self.conn_recv_window = self.conn_recv_window.saturating_add(increment);

        increment
    }

    /// Update stream send window (received WindowUpdate).
    pub fn update_stream_send_window(&mut self, stream_id: u32, increment: u32) -> Result<()> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(Error::ProtocolViolation("Unknown stream".into()))?;

        stream.update_send_window(increment);
        Ok(())
    }

    /// Update connection send window (received WindowUpdate with stream_id=0).
    pub fn update_conn_send_window(&mut self, increment: u32) {
        self.conn_send_window = self.conn_send_window.saturating_add(increment);
    }

    /// Get connection send window.
    pub fn conn_send_window(&self) -> u32 {
        self.conn_send_window
    }

    /// Get connection receive window.
    pub fn conn_recv_window(&self) -> u32 {
        self.conn_recv_window
    }

    /// Close a stream.
    pub fn close_stream(&mut self, stream_id: u32) -> Result<()> {
        let stream = self
            .streams
            .get_mut(&stream_id)
            .ok_or(Error::ProtocolViolation("Unknown stream".into()))?;

        stream.close_send()
    }

    /// Get all active stream IDs.
    pub fn stream_ids(&self) -> Vec<u32> {
        self.streams.keys().copied().collect()
    }

    /// Get number of active streams.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_creation() {
        let stream = Stream::new(1, 65536);
        assert_eq!(stream.id(), 1);
        assert_eq!(stream.priority(), 128);
        assert_eq!(stream.state(), StreamState::Open);
    }

    #[test]
    fn test_priority_clamping() {
        let mut stream = Stream::new(1, 65536);
        stream.set_priority(0);
        assert_eq!(stream.priority(), 1); // Clamped to 1 per spec
    }

    #[test]
    fn test_stream_send_flow_control() {
        let mut stream = Stream::new(1, 100);

        // Send within window
        let queued = stream.queue_send(&[0u8; 50]).unwrap();
        assert_eq!(queued, 50);
        assert_eq!(stream.send_buffered(), 50);

        // Send partial due to window
        let queued = stream.queue_send(&[0u8; 100]).unwrap();
        assert_eq!(queued, 50); // Only 50 remaining in window
        assert_eq!(stream.send_buffered(), 100);

        // Window exhausted
        let queued = stream.queue_send(&[0u8; 10]).unwrap();
        assert_eq!(queued, 0);
    }

    #[test]
    fn test_stream_recv_flow_control() {
        let mut stream = Stream::new(1, 100);

        // Receive within window
        stream.receive_data(&[0u8; 50]).unwrap();

        // Receive partial
        stream.receive_data(&[0u8; 50]).unwrap();

        // Window exhausted - should fail
        let result = stream.receive_data(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_window_update_generation() {
        let mut stream = Stream::new(1, ZP_INITIAL_STREAM_WINDOW);

        // Receive and consume half the window
        let half_window = ZP_INITIAL_STREAM_WINDOW / 2;
        stream
            .receive_data(&vec![0u8; half_window as usize])
            .unwrap();

        let (data, should_update) = stream.read(half_window as usize);
        assert_eq!(data.len(), half_window as usize);
        assert!(should_update); // Should trigger WindowUpdate

        let increment = stream.generate_window_update();
        assert_eq!(increment, half_window);
    }

    #[test]
    fn test_saturating_window_update() {
        let mut stream = Stream::new(1, u32::MAX - 100);

        // Update should saturate at MAX
        stream.update_send_window(200);
        assert_eq!(stream.send_window, u32::MAX);
    }

    #[test]
    fn test_stream_lifecycle() {
        let mut stream = Stream::new(1, 1000);

        assert_eq!(stream.state(), StreamState::Open);
        assert!(stream.can_send());
        assert!(stream.can_recv());

        // Close send
        stream.close_send().unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
        assert!(!stream.can_send());
        assert!(stream.can_recv());

        // Close receive
        stream.close_recv().unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
        assert!(!stream.can_send());
        assert!(!stream.can_recv());
    }

    #[test]
    fn test_multiplexer_creation() {
        let mux_client = StreamMultiplexer::new(true);
        let mux_server = StreamMultiplexer::new(false);

        assert_eq!(mux_client.next_stream_id, 0); // Client uses even IDs
        assert_eq!(mux_server.next_stream_id, 1); // Server uses odd IDs
    }

    #[test]
    fn test_multiplexer_open_streams() {
        let mut mux = StreamMultiplexer::new(true);

        let id1 = mux.open_stream();
        let id2 = mux.open_stream();
        let id3 = mux.open_stream();

        assert_eq!(id1, 0);
        assert_eq!(id2, 2);
        assert_eq!(id3, 4);
        assert_eq!(mux.stream_count(), 3);
    }

    #[test]
    fn test_multiplexer_flow_control() {
        let mut mux = StreamMultiplexer::new(true);
        let stream_id = mux.open_stream();

        // Send limited by both stream and connection windows
        let data = vec![0u8; 1000];
        let queued = mux.send(stream_id, &data).unwrap();
        assert_eq!(queued, 1000);

        // Connection window decremented
        assert_eq!(mux.conn_send_window(), ZP_INITIAL_CONN_WINDOW - 1000);
    }

    #[test]
    fn test_multiplexer_conn_window_update() {
        let mut mux = StreamMultiplexer::new(true);

        // Open multiple streams to consume connection window
        // Each stream can receive up to 128KB (half its window)
        let streams: Vec<u32> = (0..5).map(|_| mux.open_stream()).collect();

        let chunk_size = ZP_INITIAL_STREAM_WINDOW / 2; // 128KB per stream
        let mut total_consumed = 0u32;

        // Receive and consume from multiple streams
        for &stream_id in &streams[0..4] {
            mux.receive(stream_id, &vec![0u8; chunk_size as usize])
                .unwrap();
            let (data, _stream_update, _conn_update) =
                mux.read(stream_id, chunk_size as usize).unwrap();
            assert_eq!(data.len(), chunk_size as usize);
            total_consumed += chunk_size;
        }

        // After consuming 512KB (4 * 128KB = half the conn window), should trigger update
        assert!(total_consumed >= ZP_INITIAL_CONN_WINDOW / 2);

        let increment = mux.generate_conn_window_update();
        assert_eq!(increment, total_consumed);
    }
}
