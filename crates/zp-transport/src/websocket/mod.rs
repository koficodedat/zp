//! WebSocket transport implementation.
//!
//! Browser fallback transport per spec Appendix D.
//! Uses subprotocol identifier `zp.v1`.
//!
//! ## Spec Appendix D: WebSocket Subprotocol
//!
//! **Message Format:**
//! - All messages are binary WebSocket frames
//! - Each WebSocket message contains exactly one zp frame
//! - During handshake: frame type determined by magic number (§3.3.10)
//! - Post-handshake: messages contain EncryptedRecord (§3.3.13) or plaintext ErrorFrame
//! - Frame disambiguation per §3.3.13
//!
//! **Connection Lifecycle:**
//! 1. Client initiates WebSocket with `Sec-WebSocket-Protocol: zp.v1`
//! 2. Server confirms with same header
//! 3. Client sends ClientHello as first binary message
//! 4. Handshake proceeds as per §4.2/§4.3
//! 5. Data and control frames exchanged per §3.3.10

use crate::{Error, Result};
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_tungstenite::{
    accept_hdr_async, connect_async,
    tungstenite::{
        client::IntoClientRequest,
        handshake::server::{Callback, ErrorResponse, Request, Response},
        protocol::Message,
    },
    MaybeTlsStream, WebSocketStream,
};
use zp_core::session::{HandshakeMode, Role};
use zp_core::{Frame, Session};

#[cfg(test)]
mod tests;

/// WebSocket subprotocol identifier per spec Appendix D.
const ZP_WEBSOCKET_SUBPROTOCOL: &str = "zp.v1";

/// Callback for WebSocket handshake to check/set subprotocol.
struct SubprotocolCallback;

impl Callback for SubprotocolCallback {
    fn on_request(
        self,
        request: &Request,
        response: Response,
    ) -> std::result::Result<Response, ErrorResponse> {
        // Check if client requested zp.v1 subprotocol
        let protocols = request
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !protocols.contains(ZP_WEBSOCKET_SUBPROTOCOL) {
            return Err(ErrorResponse::new(Some(format!(
                "Client must request subprotocol '{}'",
                ZP_WEBSOCKET_SUBPROTOCOL
            ))));
        }

        // Accept with zp.v1 subprotocol
        let mut response = response;
        response.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            ZP_WEBSOCKET_SUBPROTOCOL.parse().unwrap(),
        );

        Ok(response)
    }
}

/// WebSocket transport endpoint (client or server).
///
/// Manages WebSocket endpoint configuration, connections, and integrates with zp protocol engine.
///
/// # Example
///
/// ```no_run
/// use zp_transport::websocket::WebSocketEndpoint;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// // Server
/// let server = WebSocketEndpoint::server("127.0.0.1:8080").await?;
/// let conn = server.accept().await?;
///
/// // Client
/// let client = WebSocketEndpoint::client()?;
/// let conn = client.connect("ws://127.0.0.1:8080").await?;
/// # Ok(())
/// # }
/// ```
pub struct WebSocketEndpoint {
    listener: Option<TcpListener>,
    mode: EndpointMode,
}

/// Endpoint mode (client or server).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointMode {
    Client,
    Server,
}

impl WebSocketEndpoint {
    /// Create a client endpoint.
    ///
    /// Client endpoints initiate connections.
    ///
    /// # Errors
    ///
    /// Returns error if endpoint creation fails.
    pub fn client() -> Result<Self> {
        Ok(Self {
            listener: None,
            mode: EndpointMode::Client,
        })
    }

    /// Create a server endpoint.
    ///
    /// Server endpoints accept connections.
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address to bind to (e.g., "0.0.0.0:8080")
    ///
    /// # Errors
    ///
    /// Returns error if endpoint creation or binding fails.
    pub async fn server(addr: &str) -> Result<Self> {
        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| Error::ConnectionFailed(format!("Invalid address: {}", e)))?;

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("Server bind failed: {}", e)))?;

        Ok(Self {
            listener: Some(listener),
            mode: EndpointMode::Server,
        })
    }

    /// Get the local address this endpoint is bound to.
    ///
    /// # Errors
    ///
    /// Returns error if endpoint is not bound (client mode without connection).
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .as_ref()
            .ok_or_else(|| Error::ConnectionFailed("Client has no local address".into()))?
            .local_addr()
            .map_err(|e| Error::ConnectionFailed(format!("No local address: {}", e)))
    }

    /// Connect to a remote server (client only).
    ///
    /// Establishes WebSocket connection with subprotocol `zp.v1`.
    ///
    /// # Arguments
    ///
    /// * `url` - WebSocket URL (e.g., "ws://192.168.1.100:8080")
    ///
    /// # Errors
    ///
    /// Returns error if not a client, connection fails, or subprotocol negotiation fails.
    pub async fn connect(&self, url: &str) -> Result<WebSocketConnection> {
        if self.mode != EndpointMode::Client {
            return Err(Error::ConnectionFailed("Only client can connect".into()));
        }

        // Connect with zp.v1 subprotocol
        let request = url
            .into_client_request()
            .map_err(|e| Error::ConnectionFailed(format!("Invalid URL: {}", e)))?;

        let mut request = request;
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            ZP_WEBSOCKET_SUBPROTOCOL.parse().unwrap(),
        );

        let (ws_stream, response) = connect_async(request)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("WebSocket handshake failed: {}", e)))?;

        // Verify subprotocol
        let subprotocol = response
            .headers()
            .get("Sec-WebSocket-Protocol")
            .and_then(|v| v.to_str().ok());

        if subprotocol != Some(ZP_WEBSOCKET_SUBPROTOCOL) {
            return Err(Error::ConnectionFailed(format!(
                "Server did not accept subprotocol '{}', got: {:?}",
                ZP_WEBSOCKET_SUBPROTOCOL, subprotocol
            )));
        }

        // Initialize connection
        WebSocketConnection::from_client(ws_stream).await
    }

    /// Accept incoming connection (server only).
    ///
    /// Waits for incoming WebSocket connection from client.
    ///
    /// # Errors
    ///
    /// Returns error if not a server or connection acceptance fails.
    pub async fn accept(&self) -> Result<WebSocketConnection> {
        if self.mode != EndpointMode::Server {
            return Err(Error::ConnectionFailed("Only server can accept".into()));
        }

        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| Error::ConnectionFailed("No listener".into()))?;

        let (tcp_stream, _addr) = listener
            .accept()
            .await
            .map_err(|e| Error::ConnectionFailed(format!("TCP accept failed: {}", e)))?;

        // Perform WebSocket handshake with subprotocol check
        let callback = SubprotocolCallback;
        let ws_stream = accept_hdr_async(tcp_stream, callback)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("WebSocket handshake failed: {}", e)))?;

        // Initialize connection
        WebSocketConnection::from_server(ws_stream).await
    }
}

/// WebSocket stream wrapper to handle both TLS and plain TCP.
enum WsStreamWrapper {
    Tls(WebSocketStream<MaybeTlsStream<TcpStream>>),
    Plain(WebSocketStream<TcpStream>),
}

/// WebSocket connection with integrated zp session.
///
/// Manages:
/// - Binary WebSocket frames
/// - EncryptedRecord wrapping for post-handshake frames
/// - zp session state machine integration
pub struct WebSocketConnection {
    ws_stream: Arc<RwLock<WsStreamWrapper>>,
    session: Arc<RwLock<Session>>,
}

impl WebSocketConnection {
    /// Initialize connection from client side.
    async fn from_client(ws_stream: WebSocketStream<MaybeTlsStream<TcpStream>>) -> Result<Self> {
        // Default to Stranger Mode (TOFU)
        let session = Session::new(Role::Client, HandshakeMode::Stranger);

        Ok(Self {
            ws_stream: Arc::new(RwLock::new(WsStreamWrapper::Tls(ws_stream))),
            session: Arc::new(RwLock::new(session)),
        })
    }

    /// Initialize connection from server side.
    async fn from_server(ws_stream: WebSocketStream<TcpStream>) -> Result<Self> {
        // Default to Stranger Mode (TOFU)
        let session = Session::new(Role::Server, HandshakeMode::Stranger);

        Ok(Self {
            ws_stream: Arc::new(RwLock::new(WsStreamWrapper::Plain(ws_stream))),
            session: Arc::new(RwLock::new(session)),
        })
    }

    /// Send a frame on this connection.
    ///
    /// During handshake: sends frame directly as binary WebSocket message.
    /// Post-handshake: wraps frame in EncryptedRecord (spec §3.3.13).
    ///
    /// # Errors
    ///
    /// Returns error if frame serialization or send fails.
    pub async fn send_frame(&self, frame: &Frame) -> Result<()> {
        // Check if session is established
        let session_established = self.session.read().await.is_established();

        // Determine if frame should be plaintext or encrypted
        let is_handshake_or_error = matches!(
            frame,
            Frame::ClientHello { .. }
                | Frame::ServerHello { .. }
                | Frame::ClientFinish { .. }
                | Frame::KnownHello { .. }
                | Frame::KnownResponse { .. }
                | Frame::KnownFinish { .. }
                | Frame::ErrorFrame { .. }
        );

        let data = if !session_established || is_handshake_or_error {
            // Before session established OR handshake/error frames: send as plaintext
            frame.serialize().map_err(Error::Protocol)?
        } else {
            // Post-handshake data frames: wrap in EncryptedRecord per spec §3.3.13
            let mut session = self.session.write().await;
            let encrypted = session.encrypt_frame(frame).map_err(Error::Protocol)?;
            drop(session); // Release session lock before serialization
            encrypted.serialize().map_err(Error::Protocol)?
        };

        let mut ws = self.ws_stream.write().await;
        match &mut *ws {
            WsStreamWrapper::Tls(stream) => stream
                .send(Message::Binary(data))
                .await
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?,
            WsStreamWrapper::Plain(stream) => stream
                .send(Message::Binary(data))
                .await
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?,
        }

        Ok(())
    }

    /// Receive a frame from this connection.
    ///
    /// Reads binary WebSocket message and parses frame.
    /// Handles EncryptedRecord unwrapping for post-handshake frames.
    ///
    /// # Errors
    ///
    /// Returns error if read fails or frame parsing fails.
    pub async fn recv_frame(&self) -> Result<Option<Frame>> {
        let mut ws = self.ws_stream.write().await;

        let msg = match &mut *ws {
            WsStreamWrapper::Tls(stream) => stream
                .next()
                .await
                .ok_or_else(|| Error::ConnectionFailed("WebSocket closed".into()))?
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?,
            WsStreamWrapper::Plain(stream) => stream
                .next()
                .await
                .ok_or_else(|| Error::ConnectionFailed("WebSocket closed".into()))?
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?,
        };

        drop(ws); // Release WS lock before session operations

        match msg {
            Message::Binary(data) => {
                // Parse frame (handles both plaintext and EncryptedRecord)
                let frame = Frame::parse(&data).map_err(Error::Protocol)?;

                // Check if this is an EncryptedRecord that needs decryption
                if matches!(frame, Frame::EncryptedRecord { .. }) {
                    let mut session = self.session.write().await;
                    let decrypted = session.decrypt_record(&frame).map_err(Error::Protocol)?;
                    Ok(Some(decrypted))
                } else {
                    // Plaintext frame (handshake or ErrorFrame)
                    Ok(Some(frame))
                }
            }
            Message::Close(_) => Ok(None),
            _ => Err(Error::Protocol(zp_core::Error::ProtocolViolation(
                "WebSocket: Only binary frames allowed per spec Appendix D".into(),
            ))),
        }
    }

    /// Get reference to session.
    pub fn session(&self) -> Arc<RwLock<Session>> {
        self.session.clone()
    }

    /// Close the connection.
    pub async fn close(&self) -> Result<()> {
        let mut ws = self.ws_stream.write().await;
        match &mut *ws {
            WsStreamWrapper::Tls(stream) => stream
                .close(None)
                .await
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?,
            WsStreamWrapper::Plain(stream) => stream
                .close(None)
                .await
                .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?,
        }
        Ok(())
    }
}
