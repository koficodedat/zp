//! QUIC transport implementation.
//!
//! Primary transport per spec §3.1 and §3.4.
//! Uses BBR v2 congestion control (quinn default).
//!
//! ## Spec §3.4: QUIC Stream Mapping
//!
//! Direct 1:1 mapping: `zp_stream_id = QUIC_stream_id`
//!
//! Stream 0 is the **control stream** (client opens immediately after handshake):
//! - Used for: KeyUpdate, WindowUpdate, Sync-Frame, AckFrame
//! - Data frames on stream 0 → ERR_PROTOCOL_VIOLATION (0x0E)
//! - Client sends WindowUpdate(stream_id=0, increment=ZP_INITIAL_CONN_WINDOW) to open
//!
//! Stream ID allocation per RFC 9000 §2.1:
//! - Client streams: 0, 4, 8, 12... (even, bidirectional)
//! - Server streams: 1, 5, 9, 13... (odd, bidirectional)
//! - Unidirectional streams rejected with STREAM_STATE_ERROR
//!
//! No EncryptedRecord wrapper (QUIC provides native encryption).

use crate::{Error, Result};
use quinn::{ClientConfig, Endpoint, ServerConfig, VarInt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use zp_core::session::{HandshakeMode, Role};
use zp_core::stream::ZP_INITIAL_CONN_WINDOW;
use zp_core::{Frame, Session};

#[cfg(test)]
mod tests;

/// QUIC transport endpoint (client or server).
///
/// Manages QUIC endpoint configuration, connections, and integrates with zp protocol engine.
///
/// # Example
///
/// ```no_run
/// use zp_transport::quic::QuicEndpoint;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Server
/// let server = QuicEndpoint::server("127.0.0.1:4433").await?;
/// let conn = server.accept().await?;
///
/// // Client
/// let client = QuicEndpoint::client()?;
/// let conn = client.connect("127.0.0.1:4433", "localhost").await?;
/// # Ok(())
/// # }
/// ```
pub struct QuicEndpoint {
    endpoint: Endpoint,
    mode: EndpointMode,
}

/// Endpoint mode (client or server).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointMode {
    Client,
    Server,
}

impl QuicEndpoint {
    /// Create a client endpoint.
    ///
    /// Client endpoints initiate connections and open even-numbered streams (0, 4, 8, ...).
    ///
    /// # Errors
    ///
    /// Returns error if endpoint creation fails.
    pub fn client() -> Result<Self> {
        let mut endpoint = Endpoint::client("[::]:0".parse().unwrap()).map_err(|e| {
            Error::ConnectionFailed(format!("Failed to create client endpoint: {}", e))
        })?;

        // Configure client with default settings (BBR v2 is quinn default)
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerification))
            .with_no_client_auth();

        let mut transport = quinn::TransportConfig::default();
        // Allow up to 100 concurrent streams per spec recommendation
        transport.max_concurrent_bidi_streams(VarInt::from_u32(100));
        transport.max_concurrent_uni_streams(VarInt::from_u32(0)); // Reject unidirectional per spec §3.4

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| Error::ConnectionFailed(format!("Crypto config error: {}", e)))?,
        ));
        client_config.transport_config(Arc::new(transport));

        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            mode: EndpointMode::Client,
        })
    }

    /// Create a server endpoint.
    ///
    /// Server endpoints accept connections and open odd-numbered streams (1, 5, 9, ...).
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address to bind to (e.g., "0.0.0.0:4433")
    ///
    /// # Errors
    ///
    /// Returns error if endpoint creation or binding fails.
    pub async fn server(addr: &str) -> Result<Self> {
        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| Error::ConnectionFailed(format!("Invalid address: {}", e)))?;

        // Generate self-signed certificate for development
        // TODO: Use real certificates for production
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(|e| {
            Error::ConnectionFailed(format!("Certificate generation failed: {}", e))
        })?;
        let cert_der = cert.cert.der().to_vec();
        let priv_key = cert.key_pair.serialize_der();

        let cert_chain = vec![rustls::pki_types::CertificateDer::from(cert_der)];
        let priv_key = rustls::pki_types::PrivatePkcs8KeyDer::from(priv_key);

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, priv_key.into())
            .map_err(|e| Error::ConnectionFailed(format!("Certificate error: {}", e)))?;
        server_crypto.max_early_data_size = 0; // Disable 0-RTT for security

        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(VarInt::from_u32(100));
        transport.max_concurrent_uni_streams(VarInt::from_u32(0)); // Reject unidirectional per spec §3.4

        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| Error::ConnectionFailed(format!("Crypto config error: {}", e)))?,
        ));
        server_config.transport_config(Arc::new(transport));

        let endpoint = Endpoint::server(server_config, addr)
            .map_err(|e| Error::ConnectionFailed(format!("Server bind failed: {}", e)))?;

        Ok(Self {
            endpoint,
            mode: EndpointMode::Server,
        })
    }

    /// Get the local address this endpoint is bound to.
    ///
    /// # Errors
    ///
    /// Returns error if endpoint is not bound (client mode without connection).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|e| Error::ConnectionFailed(format!("No local address: {}", e)))
    }

    /// Connect to a remote server (client only).
    ///
    /// Establishes QUIC connection and initializes control stream (stream 0).
    ///
    /// # Arguments
    ///
    /// * `addr` - Remote server address (e.g., "192.168.1.100:4433")
    /// * `server_name` - Expected server name for TLS verification
    ///
    /// # Errors
    ///
    /// Returns error if not a client, connection fails, or control stream initialization fails.
    pub async fn connect(&self, addr: &str, server_name: &str) -> Result<QuicConnection> {
        if self.mode != EndpointMode::Client {
            return Err(Error::ConnectionFailed("Only client can connect".into()));
        }

        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| Error::ConnectionFailed(format!("Invalid address: {}", e)))?;

        let connecting = self
            .endpoint
            .connect(addr, server_name)
            .map_err(|e| Error::ConnectionFailed(format!("Connect failed: {}", e)))?;

        let connection = connecting
            .await
            .map_err(|e| Error::ConnectionFailed(format!("Connection handshake failed: {}", e)))?;

        // Initialize control stream (stream 0) per spec §3.4
        QuicConnection::from_client(connection).await
    }

    /// Accept incoming connection (server only).
    ///
    /// Waits for incoming QUIC connection from client.
    ///
    /// # Errors
    ///
    /// Returns error if not a server or connection acceptance fails.
    pub async fn accept(&self) -> Result<QuicConnection> {
        if self.mode != EndpointMode::Server {
            return Err(Error::ConnectionFailed("Only server can accept".into()));
        }

        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| Error::ConnectionFailed("Endpoint closed".into()))?;

        let connection = incoming
            .await
            .map_err(|e| Error::ConnectionFailed(format!("Connection handshake failed: {}", e)))?;

        // Wait for client to open control stream (stream 0)
        QuicConnection::from_server(connection).await
    }

    /// Close the endpoint and all connections.
    pub fn close(&self) {
        self.endpoint.close(VarInt::from_u32(0), b"shutdown");
    }
}

/// QUIC connection with integrated zp session.
///
/// Manages:
/// - Control stream (stream 0) for protocol control frames
/// - Data streams (4+) for application data
/// - zp session state machine integration
pub struct QuicConnection {
    connection: quinn::Connection,
    session: Arc<RwLock<Session>>,
    control_stream: Arc<RwLock<Option<QuicStream>>>,
}

impl QuicConnection {
    /// Initialize connection from client side.
    ///
    /// Opens control stream (stream 0) and sends initial WindowUpdate.
    async fn from_client(connection: quinn::Connection) -> Result<Self> {
        // Default to Stranger Mode (TOFU)
        let session = Session::new(Role::Client, HandshakeMode::Stranger);

        // Open control stream (stream 0) per spec §3.4
        let (send, recv) = connection.open_bi().await.map_err(|e| {
            Error::ConnectionFailed(format!("Failed to open control stream: {}", e))
        })?;

        let mut control_stream = QuicStream::new(0, send, recv, true);

        // Send initial WindowUpdate per spec §3.4
        // WindowUpdate(stream_id=0, increment=ZP_INITIAL_CONN_WINDOW)
        let window_update = Frame::WindowUpdate {
            stream_id: 0,
            window_increment: ZP_INITIAL_CONN_WINDOW as u64,
        };
        control_stream.send_frame(&window_update).await?;

        Ok(Self {
            connection,
            session: Arc::new(RwLock::new(session)),
            control_stream: Arc::new(RwLock::new(Some(control_stream))),
        })
    }

    /// Initialize connection from server side.
    ///
    /// Waits for client to open control stream (stream 0).
    async fn from_server(connection: quinn::Connection) -> Result<Self> {
        // Default to Stranger Mode (TOFU)
        let session = Session::new(Role::Server, HandshakeMode::Stranger);

        // Wait for client to open control stream (stream 0)
        let (send, recv) = connection.accept_bi().await.map_err(|e| {
            Error::ConnectionFailed(format!("Failed to accept control stream: {}", e))
        })?;

        let mut control_stream = QuicStream::new(0, send, recv, true);

        // Send initial WindowUpdate per spec §3.4
        let window_update = Frame::WindowUpdate {
            stream_id: 0,
            window_increment: ZP_INITIAL_CONN_WINDOW as u64,
        };
        control_stream.send_frame(&window_update).await?;

        Ok(Self {
            connection,
            session: Arc::new(RwLock::new(session)),
            control_stream: Arc::new(RwLock::new(Some(control_stream))),
        })
    }

    /// Open a new data stream.
    ///
    /// Stream IDs are allocated according to spec §3.4:
    /// - Client: 4, 8, 12, ... (even, skipping 0 which is control)
    /// - Server: 1, 5, 9, 13, ... (odd)
    ///
    /// # Errors
    ///
    /// Returns error if stream opening fails.
    pub async fn open_stream(&self) -> Result<QuicStream> {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| Error::ConnectionFailed(format!("Failed to open stream: {}", e)))?;

        // Stream ID is allocated by QUIC automatically
        // quinn guarantees: client gets even IDs (0, 4, 8...), server gets odd IDs (1, 5, 9...)
        let stream_id = u64::from(send.id()); // Get the QUIC stream ID

        Ok(QuicStream::new(stream_id, send, recv, false))
    }

    /// Accept incoming stream from peer.
    ///
    /// # Errors
    ///
    /// Returns error if stream acceptance fails.
    pub async fn accept_stream(&self) -> Result<QuicStream> {
        let (send, recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|e| Error::ConnectionFailed(format!("Failed to accept stream: {}", e)))?;

        let stream_id = u64::from(send.id());

        // Validate stream ID is not 0 (control stream already initialized)
        if stream_id == 0 {
            return Err(Error::Protocol(zp_core::Error::StreamClosed));
        }

        Ok(QuicStream::new(stream_id, send, recv, false))
    }

    /// Get reference to session.
    pub fn session(&self) -> Arc<RwLock<Session>> {
        self.session.clone()
    }

    /// Get reference to control stream.
    pub fn control_stream(&self) -> Arc<RwLock<Option<QuicStream>>> {
        self.control_stream.clone()
    }

    /// Close the connection.
    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.connection.close(VarInt::from_u32(error_code), reason);
    }
}

/// QUIC stream wrapper for control and data streams.
///
/// ## Control Stream (stream 0):
/// - Control frames only: KeyUpdate, WindowUpdate, Sync-Frame, AckFrame
/// - Data frames rejected with ERR_PROTOCOL_VIOLATION (0x0E)
///
/// ## Data Streams (4+):
/// - Application data via DataFrame
/// - Normal flow control applies
pub struct QuicStream {
    stream_id: u64,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    is_control: bool,
}

impl QuicStream {
    /// Create new stream wrapper.
    fn new(
        stream_id: u64,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        is_control: bool,
    ) -> Self {
        Self {
            stream_id,
            send,
            recv,
            is_control,
        }
    }

    /// Get stream ID (matches QUIC stream ID per spec §3.4).
    pub fn id(&self) -> u64 {
        self.stream_id
    }

    /// Check if this is the control stream.
    pub fn is_control(&self) -> bool {
        self.is_control
    }

    /// Send a frame on this stream.
    ///
    /// # Errors
    ///
    /// Returns `ERR_PROTOCOL_VIOLATION` if sending DataFrame on control stream (stream 0).
    /// Returns error if frame serialization or send fails.
    pub async fn send_frame(&mut self, frame: &Frame) -> Result<()> {
        // Enforce control stream restriction per spec §3.4
        if self.is_control && matches!(frame, Frame::DataFrame { .. }) {
            return Err(Error::Protocol(zp_core::Error::ProtocolViolation(
                "DataFrame not allowed on control stream (stream 0)".into(),
            )));
        }

        let data = frame.serialize().map_err(Error::Protocol)?;

        self.send
            .write_all(&data)
            .await
            .map_err(|e| Error::Io(e.into()))?;

        Ok(())
    }

    /// Receive a frame from this stream.
    ///
    /// Reads data from QUIC stream, parses frame, and validates control stream restrictions.
    ///
    /// # Errors
    ///
    /// Returns error if read fails or frame parsing fails.
    pub async fn recv_frame(&mut self) -> Result<Option<Frame>> {
        // Read enough bytes to parse frame
        // TODO: Implement proper frame length detection
        let mut buf = vec![0u8; 4096];
        let n = self
            .recv
            .read(&mut buf)
            .await
            .map_err(|e| Error::Io(e.into()))?;

        // quinn's read returns Option<usize>
        match n {
            None => return Ok(None),    // Stream closed (FIN received)
            Some(0) => return Ok(None), // EOF
            Some(bytes_read) => buf.truncate(bytes_read),
        }

        let frame = Frame::parse(&buf).map_err(Error::Protocol)?;

        // Enforce control stream restriction per spec §3.4
        if self.is_control && matches!(frame, Frame::DataFrame { .. }) {
            return Err(Error::Protocol(zp_core::Error::ProtocolViolation(
                "DataFrame not allowed on control stream (stream 0)".into(),
            )));
        }

        Ok(Some(frame))
    }

    /// Close the stream for sending (send FIN).
    pub async fn close_send(&mut self) -> Result<()> {
        self.send
            .finish()
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        Ok(())
    }
}

/// Skip certificate verification for development.
///
/// **WARNING:** This is insecure. Use real certificate verification in production.
#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> core::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> core::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> core::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
