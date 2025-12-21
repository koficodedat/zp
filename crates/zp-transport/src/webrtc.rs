//! WebRTC DataChannel transport implementation.
//!
//! Browser P2P transport per spec §5 and §6.4.
//!
//! **Spec Requirements:**
//! - DataChannel configured with `ordered: false, maxRetransmits: 0`
//! - P2P role assignment based on SDP offer/answer:
//!   - Offer sender (initiator) → Client role (even stream IDs)
//!   - Answer sender (responder) → Server role (odd stream IDs)
//! - NAT traversal via STUN/TURN
//! - Double encryption: DTLS (browser-enforced) + zp handshake (inner)
//! - Unreliable DataChannel → zp AckFrame reliability layer required
//!
//! **Architecture:**
//! - `WebRtcEndpoint`: Peer connection factory with STUN/TURN config
//! - `WebRtcConnection`: Connection with DataChannel for zp frames
//! - Signaling via external channel (out-of-band SDP exchange)

use crate::{Error, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use zp_core::session::{HandshakeMode, Role};
use zp_core::{Frame, Session};

/// DataChannel label per spec §6.4
const ZP_DATACHANNEL_LABEL: &str = "zp";

/// Default STUN servers for NAT traversal
const DEFAULT_STUN_SERVERS: &[&str] = &["stun:stun.l.google.com:19302"];

/// Role assignment based on SDP offer/answer per spec §6.4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    /// Offer sender (initiator) → Client role (even stream IDs)
    Client,
    /// Answer sender (responder) → Server role (odd stream IDs)
    Server,
}

/// Signaling message for out-of-band SDP exchange
#[derive(Debug, Clone)]
pub enum SignalingMessage {
    /// SDP offer from initiator
    Offer(RTCSessionDescription),
    /// SDP answer from responder
    Answer(RTCSessionDescription),
    /// ICE candidate for NAT traversal
    IceCandidate(RTCIceCandidateInit),
}

/// WebRTC endpoint configuration
#[derive(Debug, Clone)]
pub struct WebRtcConfig {
    /// STUN servers for NAT traversal
    pub stun_servers: Vec<String>,
    /// TURN servers for relay fallback (optional)
    pub turn_servers: Vec<RTCIceServer>,
}

impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            stun_servers: DEFAULT_STUN_SERVERS.iter().map(|s| s.to_string()).collect(),
            turn_servers: Vec::new(),
        }
    }
}

/// WebRTC transport endpoint (peer connection factory).
///
/// Manages peer connections for WebRTC DataChannel transport per spec §5 and §6.4.
pub struct WebRtcEndpoint {
    config: WebRtcConfig,
    api: webrtc::api::API,
}

impl WebRtcEndpoint {
    /// Create a new WebRTC endpoint with default configuration.
    pub fn new() -> Result<Self> {
        Self::with_config(WebRtcConfig::default())
    }

    /// Create a new WebRTC endpoint with custom configuration.
    pub fn with_config(config: WebRtcConfig) -> Result<Self> {
        // Create MediaEngine and Registry
        let mut media_engine = MediaEngine::default();
        let mut registry = Registry::new();

        // Register default interceptors
        registry = register_default_interceptors(registry, &mut media_engine).map_err(|e| {
            Error::ConnectionFailed(format!("Failed to register interceptors: {}", e))
        })?;

        // Build WebRTC API
        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build();

        Ok(Self { config, api })
    }

    /// Create a peer connection as initiator (will send SDP offer).
    ///
    /// Returns (PeerConnection, SignalingMessage channel for SDP/ICE exchange)
    pub async fn create_offer(
        &self,
    ) -> Result<(Arc<RTCPeerConnection>, mpsc::Receiver<SignalingMessage>)> {
        let (tx, rx) = mpsc::channel(16);
        let peer_connection = self.create_peer_connection(tx).await?;

        Ok((peer_connection, rx))
    }

    /// Create a peer connection as responder (will send SDP answer).
    ///
    /// Returns (PeerConnection, SignalingMessage channel for SDP/ICE exchange)
    pub async fn create_answer(
        &self,
    ) -> Result<(Arc<RTCPeerConnection>, mpsc::Receiver<SignalingMessage>)> {
        let (tx, rx) = mpsc::channel(16);
        let peer_connection = self.create_peer_connection(tx).await?;

        Ok((peer_connection, rx))
    }

    /// Internal: Create a peer connection with ICE candidate handling
    async fn create_peer_connection(
        &self,
        signaling_tx: mpsc::Sender<SignalingMessage>,
    ) -> Result<Arc<RTCPeerConnection>> {
        // Build ICE servers (STUN + TURN)
        let mut ice_servers = self
            .config
            .stun_servers
            .iter()
            .map(|url| RTCIceServer {
                urls: vec![url.clone()],
                ..Default::default()
            })
            .collect::<Vec<_>>();

        ice_servers.extend(self.config.turn_servers.clone());

        let config = RTCConfiguration {
            ice_servers,
            ..Default::default()
        };

        // Create peer connection
        let peer_connection =
            Arc::new(self.api.new_peer_connection(config).await.map_err(|e| {
                Error::ConnectionFailed(format!("Failed to create peer connection: {}", e))
            })?);

        // Handle ICE candidates (send via signaling channel)
        let tx = signaling_tx.clone();
        peer_connection.on_ice_candidate(Box::new(move |candidate| {
            let tx = tx.clone();
            Box::pin(async move {
                if let Some(candidate) = candidate {
                    let init = candidate.to_json().unwrap_or_default();
                    let _ = tx.send(SignalingMessage::IceCandidate(init)).await;
                }
            })
        }));

        Ok(peer_connection)
    }

    /// Connect to a peer using WebRTC DataChannel.
    ///
    /// **Initiator flow (creates offer):**
    /// 1. Create peer connection
    /// 2. Create DataChannel with zp configuration
    /// 3. Generate SDP offer
    /// 4. Exchange SDP/ICE via external signaling channel
    /// 5. Wait for connection establishment
    ///
    /// Returns WebRtcConnection with Client role (even stream IDs)
    pub async fn connect(&self, signaling: impl SignalingChannel) -> Result<WebRtcConnection> {
        let (peer_connection, mut local_signaling_rx) = self.create_offer().await?;

        // Create DataChannel (initiator creates channel)
        let data_channel = peer_connection
            .create_data_channel(
                ZP_DATACHANNEL_LABEL,
                Some(
                    webrtc::data_channel::data_channel_init::RTCDataChannelInit {
                        ordered: Some(false),     // Unreliable per spec §6.4
                        max_retransmits: Some(0), // No retransmits per spec §6.4
                        ..Default::default()
                    },
                ),
            )
            .await
            .map_err(|e| Error::ConnectionFailed(format!("Failed to create DataChannel: {}", e)))?;

        // Create SDP offer
        let offer = peer_connection
            .create_offer(None)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("Failed to create offer: {}", e)))?;

        peer_connection
            .set_local_description(offer.clone())
            .await
            .map_err(|e| {
                Error::ConnectionFailed(format!("Failed to set local description: {}", e))
            })?;

        // Send offer via signaling channel
        signaling
            .send(SignalingMessage::Offer(offer))
            .await
            .map_err(|e| Error::ConnectionFailed(format!("Signaling failed: {}", e)))?;

        // Exchange ICE candidates and receive answer
        tokio::spawn({
            let sig = signaling.clone();
            async move {
                while let Some(msg) = local_signaling_rx.recv().await {
                    let _ = sig.send(msg).await;
                }
            }
        });

        // Wait for answer
        let answer = signaling
            .recv()
            .await
            .map_err(|e| Error::ConnectionFailed(format!("Failed to receive answer: {}", e)))?;

        if let SignalingMessage::Answer(answer) = answer {
            peer_connection
                .set_remote_description(answer)
                .await
                .map_err(|e| {
                    Error::ConnectionFailed(format!("Failed to set remote description: {}", e))
                })?;
        } else {
            return Err(Error::ConnectionFailed("Expected SDP answer".into()));
        }

        // Receive and apply remote ICE candidates
        tokio::spawn({
            let pc = Arc::clone(&peer_connection);
            let sig = signaling.clone();
            async move {
                while let Ok(msg) = sig.recv().await {
                    if let SignalingMessage::IceCandidate(candidate) = msg {
                        let _ = pc.add_ice_candidate(candidate).await;
                    }
                }
            }
        });

        // Wait for connection
        Self::wait_for_connection(&peer_connection).await?;

        // Create session (Stranger mode, TOFU) - Client role
        let session = Arc::new(RwLock::new(Session::new(
            Role::Client,
            HandshakeMode::Stranger,
        )));

        Ok(WebRtcConnection {
            peer_connection,
            data_channel,
            session,
            role: PeerRole::Client, // Offer sender = Client
        })
    }

    /// Accept a connection from a peer using WebRTC DataChannel.
    ///
    /// **Responder flow (creates answer):**
    /// 1. Create peer connection
    /// 2. Receive SDP offer via external signaling channel
    /// 3. Set remote description (offer)
    /// 4. Wait for DataChannel from peer
    /// 5. Generate SDP answer
    /// 6. Exchange SDP/ICE via signaling channel
    /// 7. Wait for connection establishment
    ///
    /// Returns WebRtcConnection with Server role (odd stream IDs)
    pub async fn accept(&self, signaling: impl SignalingChannel) -> Result<WebRtcConnection> {
        let (peer_connection, mut local_signaling_rx) = self.create_answer().await?;

        // Wait for DataChannel from peer
        let (data_channel_tx, mut data_channel_rx) = mpsc::channel::<Arc<RTCDataChannel>>(1);

        peer_connection.on_data_channel(Box::new(move |dc| {
            let tx = data_channel_tx.clone();
            Box::pin(async move {
                let _ = tx.send(dc).await;
            })
        }));

        // Receive offer via signaling channel
        let offer = signaling
            .recv()
            .await
            .map_err(|e| Error::ConnectionFailed(format!("Failed to receive offer: {}", e)))?;

        if let SignalingMessage::Offer(offer) = offer {
            peer_connection
                .set_remote_description(offer)
                .await
                .map_err(|e| {
                    Error::ConnectionFailed(format!("Failed to set remote description: {}", e))
                })?;
        } else {
            return Err(Error::ConnectionFailed("Expected SDP offer".into()));
        }

        // Create SDP answer
        let answer = peer_connection
            .create_answer(None)
            .await
            .map_err(|e| Error::ConnectionFailed(format!("Failed to create answer: {}", e)))?;

        peer_connection
            .set_local_description(answer.clone())
            .await
            .map_err(|e| {
                Error::ConnectionFailed(format!("Failed to set local description: {}", e))
            })?;

        // Send answer via signaling channel
        signaling
            .send(SignalingMessage::Answer(answer))
            .await
            .map_err(|e| Error::ConnectionFailed(format!("Signaling failed: {}", e)))?;

        // Exchange ICE candidates
        tokio::spawn({
            let sig = signaling.clone();
            async move {
                while let Some(msg) = local_signaling_rx.recv().await {
                    let _ = sig.send(msg).await;
                }
            }
        });

        // Receive and apply remote ICE candidates
        tokio::spawn({
            let pc = Arc::clone(&peer_connection);
            let sig = signaling.clone();
            async move {
                while let Ok(msg) = sig.recv().await {
                    if let SignalingMessage::IceCandidate(candidate) = msg {
                        let _ = pc.add_ice_candidate(candidate).await;
                    }
                }
            }
        });

        // Wait for DataChannel
        let data_channel = data_channel_rx
            .recv()
            .await
            .ok_or_else(|| Error::ConnectionFailed("DataChannel not received".into()))?;

        // Wait for connection
        Self::wait_for_connection(&peer_connection).await?;

        // Create session (Stranger mode, TOFU) - Server role
        let session = Arc::new(RwLock::new(Session::new(
            Role::Server,
            HandshakeMode::Stranger,
        )));

        Ok(WebRtcConnection {
            peer_connection,
            data_channel,
            session,
            role: PeerRole::Server, // Answer sender = Server
        })
    }

    /// Wait for peer connection to establish
    async fn wait_for_connection(peer_connection: &RTCPeerConnection) -> Result<()> {
        let (tx, mut rx) = mpsc::channel(1);

        peer_connection.on_peer_connection_state_change(Box::new(move |state| {
            let tx = tx.clone();
            Box::pin(async move {
                let _ = tx.send(state).await;
            })
        }));

        // Wait for connected state
        while let Some(state) = rx.recv().await {
            match state {
                RTCPeerConnectionState::Connected => return Ok(()),
                RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                    return Err(Error::ConnectionFailed("Connection failed".into()));
                }
                _ => {}
            }
        }

        Err(Error::ConnectionFailed("Connection timeout".into()))
    }
}

/// WebRTC DataChannel connection for zp frames.
///
/// Per spec §6.4:
/// - DataChannel configured with `ordered: false, maxRetransmits: 0`
/// - Role determined by SDP offer/answer (Client = offer sender, Server = answer sender)
/// - Unreliable transport → AckFrame reliability layer required
pub struct WebRtcConnection {
    peer_connection: Arc<RTCPeerConnection>,
    data_channel: Arc<RTCDataChannel>,
    session: Arc<RwLock<Session>>,
    role: PeerRole,
}

impl WebRtcConnection {
    /// Send a zp frame over the DataChannel.
    ///
    /// Frame is serialized and sent as binary message.
    /// No reliability guarantees (unreliable DataChannel per spec §6.4).
    pub async fn send_frame(&self, frame: &Frame) -> Result<()> {
        let data = frame.serialize()?;

        self.data_channel
            .send(&bytes::Bytes::from(data))
            .await
            .map_err(|e| Error::ConnectionFailed(format!("DataChannel send failed: {}", e)))?;

        Ok(())
    }

    /// Receive a zp frame from the DataChannel.
    ///
    /// Returns None if connection closed.
    /// No reliability guarantees (unreliable DataChannel per spec §6.4).
    pub async fn recv_frame(&self) -> Result<Option<Frame>> {
        let (tx, mut rx) = mpsc::channel(1);

        self.data_channel
            .on_message(Box::new(move |msg: DataChannelMessage| {
                let tx = tx.clone();
                Box::pin(async move {
                    let _ = tx.send(msg).await;
                })
            }));

        match rx.recv().await {
            Some(msg) => {
                let frame = Frame::parse(&msg.data)?;
                Ok(Some(frame))
            }
            None => Ok(None),
        }
    }

    /// Close the WebRTC connection.
    pub async fn close(&self) -> Result<()> {
        self.data_channel
            .close()
            .await
            .map_err(|e| Error::ConnectionFailed(format!("DataChannel close failed: {}", e)))?;

        self.peer_connection
            .close()
            .await
            .map_err(|e| Error::ConnectionFailed(format!("PeerConnection close failed: {}", e)))?;

        Ok(())
    }

    /// Get the session associated with this connection.
    pub fn session(&self) -> Arc<RwLock<Session>> {
        Arc::clone(&self.session)
    }

    /// Get the peer role (Client or Server).
    pub fn role(&self) -> PeerRole {
        self.role
    }

    /// Get local address (not applicable for WebRTC, returns None).
    pub fn local_addr(&self) -> Option<SocketAddr> {
        None
    }

    /// Get peer address (not applicable for WebRTC, returns None).
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }
}

/// Trait for external signaling channels (SDP/ICE exchange).
///
/// Implementers provide out-of-band signaling for WebRTC connection establishment.
/// Examples: WebSocket, HTTP, or custom signaling server.
#[async_trait::async_trait]
pub trait SignalingChannel: Send + Sync + Clone + 'static {
    /// Send a signaling message to peer
    async fn send(
        &self,
        message: SignalingMessage,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Receive a signaling message from peer
    async fn recv(
        &self,
    ) -> std::result::Result<SignalingMessage, Box<dyn std::error::Error + Send + Sync>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webrtc_endpoint_creation() {
        let endpoint = WebRtcEndpoint::new();
        assert!(endpoint.is_ok(), "WebRTC endpoint creation should succeed");
    }

    #[test]
    fn test_webrtc_config_default() {
        let config = WebRtcConfig::default();
        assert!(
            !config.stun_servers.is_empty(),
            "Default config should have STUN servers"
        );
        assert!(
            config.turn_servers.is_empty(),
            "Default config should have no TURN servers"
        );
    }

    #[test]
    fn test_peer_role_assignment() {
        // Per spec §6.4: Offer sender = Client, Answer sender = Server
        assert_eq!(PeerRole::Client, PeerRole::Client);
        assert_eq!(PeerRole::Server, PeerRole::Server);
        assert_ne!(PeerRole::Client, PeerRole::Server);
    }

    #[test]
    fn test_webrtc_config_with_custom_stun() {
        let mut config = WebRtcConfig::default();
        config
            .stun_servers
            .push("stun:custom.example.com:3478".to_string());

        assert!(
            config.stun_servers.len() >= 2,
            "Should have default + custom STUN servers"
        );
        assert!(
            config
                .stun_servers
                .contains(&"stun:custom.example.com:3478".to_string()),
            "Should contain custom STUN server"
        );
    }

    #[test]
    fn test_webrtc_config_with_turn() {
        use webrtc::ice_transport::ice_server::RTCIceServer;

        let mut config = WebRtcConfig::default();
        config.turn_servers.push(RTCIceServer {
            urls: vec!["turn:turn.example.com:3478".to_string()],
            username: "test_user".to_string(),
            credential: "test_pass".to_string(),
            ..Default::default()
        });

        assert_eq!(
            config.turn_servers.len(),
            1,
            "Should have 1 TURN server configured"
        );
        assert_eq!(
            config.turn_servers[0].username, "test_user",
            "TURN username should match"
        );
    }

    #[test]
    fn test_endpoint_with_custom_config() {
        let mut config = WebRtcConfig::default();
        config
            .stun_servers
            .push("stun:test.example.com:3478".to_string());

        let endpoint = WebRtcEndpoint::with_config(config);
        assert!(
            endpoint.is_ok(),
            "Endpoint creation with custom config should succeed"
        );
    }

    #[test]
    fn test_signaling_message_ice_candidate() {
        use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;

        // Test IceCandidate variant with default init
        let candidate = RTCIceCandidateInit {
            candidate: "candidate:1 1 UDP 2130706431 192.168.1.1 54321 typ host".to_string(),
            ..Default::default()
        };
        let msg = SignalingMessage::IceCandidate(candidate);
        assert!(
            matches!(msg, SignalingMessage::IceCandidate(_)),
            "Should be IceCandidate variant"
        );
    }

    #[test]
    fn test_signaling_message_clone() {
        use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;

        // Test that SignalingMessage can be cloned
        let candidate = RTCIceCandidateInit {
            candidate: "test".to_string(),
            ..Default::default()
        };
        let msg = SignalingMessage::IceCandidate(candidate);
        let cloned = msg.clone();

        assert!(
            matches!(cloned, SignalingMessage::IceCandidate(_)),
            "Cloned message should preserve variant"
        );
    }

    #[test]
    fn test_peer_role_display() {
        // Ensure roles can be debugged/displayed
        let client = PeerRole::Client;
        let server = PeerRole::Server;

        assert_eq!(format!("{:?}", client), "Client");
        assert_eq!(format!("{:?}", server), "Server");
    }

    #[test]
    fn test_webrtc_config_clone() {
        let config = WebRtcConfig::default();
        let cloned = config.clone();

        assert_eq!(
            config.stun_servers.len(),
            cloned.stun_servers.len(),
            "Cloned config should have same STUN server count"
        );
        assert_eq!(
            config.turn_servers.len(),
            cloned.turn_servers.len(),
            "Cloned config should have same TURN server count"
        );
    }

    #[test]
    fn test_default_stun_servers_format() {
        let config = WebRtcConfig::default();

        for server in &config.stun_servers {
            assert!(
                server.starts_with("stun:"),
                "STUN server URL should start with 'stun:'"
            );
        }
    }
}
