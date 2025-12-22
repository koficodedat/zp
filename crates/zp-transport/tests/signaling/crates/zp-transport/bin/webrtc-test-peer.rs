//! Standalone WebRTC test peer for Docker container testing.
//!
//! Runs inside Docker container to simulate a separate WebRTC peer.
//!
//! **Environment Variables:**
//! - `SIGNALING_URL` - HTTP signaling server URL (required)
//! - `SESSION_ID` - Session ID for signaling (required)
//! - `PEER_ROLE` - Either "client" or "server" (default: "server")
//! - `STUN_SERVER` - STUN server URL (default: stun:stun.l.google.com:19302)

use std::env;
use std::error::Error;
use std::sync::Once;
use zp_transport::webrtc::{SignalingChannel, SignalingMessage, WebRtcConfig, WebRtcEndpoint};

// Embedded HTTP signaling client (can't import from tests)
mod http_signaling {
    use async_trait::async_trait;
    use reqwest::Client;
    use serde_json;
    use std::error::Error;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use zp_transport::webrtc::{SignalingChannel, SignalingMessage};

    #[derive(Clone)]
    pub struct HttpSignalingChannel {
        client: Client,
        server_url: String,
        session_id: String,
        sent_offer: Arc<Mutex<bool>>,
        sent_answer: Arc<Mutex<bool>>,
    }

    impl HttpSignalingChannel {
        pub fn new(server_url: String, session_id: String) -> Self {
            Self {
                client: Client::new(),
                server_url,
                session_id,
                sent_offer: Arc::new(Mutex::new(false)),
                sent_answer: Arc::new(Mutex::new(false)),
            }
        }

        fn serialize_message(
            &self,
            message: &SignalingMessage,
        ) -> Result<String, Box<dyn Error + Send + Sync>> {
            match message {
                SignalingMessage::Offer(sdp) => Ok(serde_json::json!({
                    "type": "offer",
                    "sdp": serde_json::to_string(sdp)?
                })
                .to_string()),
                SignalingMessage::Answer(sdp) => Ok(serde_json::json!({
                    "type": "answer",
                    "sdp": serde_json::to_string(sdp)?
                })
                .to_string()),
                SignalingMessage::IceCandidate(candidate) => Ok(serde_json::json!({
                    "type": "ice",
                    "candidate": serde_json::to_string(candidate)?
                })
                .to_string()),
            }
        }

        fn deserialize_message(
            &self,
            json: &str,
        ) -> Result<SignalingMessage, Box<dyn Error + Send + Sync>> {
            let value: serde_json::Value = serde_json::from_str(json)?;

            match value["type"].as_str() {
                Some("offer") => {
                    let sdp = serde_json::from_str(value["sdp"].as_str().unwrap())?;
                    Ok(SignalingMessage::Offer(sdp))
                }
                Some("answer") => {
                    let sdp = serde_json::from_str(value["sdp"].as_str().unwrap())?;
                    Ok(SignalingMessage::Answer(sdp))
                }
                Some("ice") => {
                    let candidate = serde_json::from_str(value["candidate"].as_str().unwrap())?;
                    Ok(SignalingMessage::IceCandidate(candidate))
                }
                _ => Err("Unknown message type".into()),
            }
        }
    }

    #[async_trait]
    impl SignalingChannel for HttpSignalingChannel {
        async fn send(
            &self,
            message: SignalingMessage,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            let message_json = self.serialize_message(&message)?;

            let endpoint = match &message {
                SignalingMessage::Offer(_) => {
                    *self.sent_offer.lock().await = true;
                    format!("{}/session/{}/offer", self.server_url, self.session_id)
                }
                SignalingMessage::Answer(_) => {
                    *self.sent_answer.lock().await = true;
                    format!("{}/session/{}/answer", self.server_url, self.session_id)
                }
                SignalingMessage::IceCandidate(_) => {
                    format!("{}/session/{}/ice", self.server_url, self.session_id)
                }
            };

            let body = serde_json::json!({"message": message_json});

            self.client
                .post(&endpoint)
                .json(&body)
                .send()
                .await?
                .error_for_status()?;

            Ok(())
        }

        async fn recv(&self) -> Result<SignalingMessage, Box<dyn Error + Send + Sync>> {
            loop {
                // Try to get offer (only if we didn't send one)
                if !*self.sent_offer.lock().await {
                    if let Ok(response) = self
                        .client
                        .get(&format!(
                            "{}/session/{}/offer",
                            self.server_url, self.session_id
                        ))
                        .send()
                        .await
                    {
                        if response.status().is_success() {
                            let body: serde_json::Value = response.json().await?;
                            if let Some(message_json) = body["message"].as_str() {
                                return self.deserialize_message(message_json);
                            }
                        }
                    }
                }

                // Try to get answer (only if we didn't send one)
                if !*self.sent_answer.lock().await {
                    if let Ok(response) = self
                        .client
                        .get(&format!(
                            "{}/session/{}/answer",
                            self.server_url, self.session_id
                        ))
                        .send()
                        .await
                    {
                        if response.status().is_success() {
                            let body: serde_json::Value = response.json().await?;
                            if let Some(message_json) = body["message"].as_str() {
                                return self.deserialize_message(message_json);
                            }
                        }
                    }
                }

                // Try to get ICE candidates (always poll for ICE)
                if let Ok(response) = self
                    .client
                    .get(&format!(
                        "{}/session/{}/ice",
                        self.server_url, self.session_id
                    ))
                    .send()
                    .await
                {
                    if response.status().is_success() {
                        let body: serde_json::Value = response.json().await?;
                        if let Some(message_json) = body["message"].as_str() {
                            return self.deserialize_message(message_json);
                        }
                        // If message is null, no candidates available - continue polling
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        }
    }
}

use http_signaling::HttpSignalingChannel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Read configuration from environment
    let signaling_url =
        env::var("SIGNALING_URL").expect("SIGNALING_URL environment variable required");

    let session_id = env::var("SESSION_ID").expect("SESSION_ID environment variable required");

    let peer_role = env::var("PEER_ROLE").unwrap_or_else(|_| "server".to_string());

    let stun_server = env::var("STUN_SERVER")
        .unwrap_or_else(|_| "stun:stun.l.google.com:19302".to_string());

    println!("🔧 WebRTC Test Peer starting:");
    println!("   Role: {}", peer_role);
    println!("   Signaling: {}", signaling_url);
    println!("   Session: {}", session_id);
    println!("   STUN: {}", stun_server);

    // Initialize crypto provider (required for rustls)
    static CRYPTO_INIT: Once = Once::new();
    CRYPTO_INIT.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install default crypto provider");
    });

    // Create WebRTC config
    let config = WebRtcConfig {
        stun_servers: vec![stun_server],
        turn_servers: Vec::new(),
    };

    let endpoint = WebRtcEndpoint::with_config(config).expect("Failed to create WebRTC endpoint");

    let signaling = HttpSignalingChannel::new(signaling_url, session_id, peer_role.clone());

    match peer_role.as_str() {
        "client" => {
            println!("📡 Connecting to server peer...");
            let _connection = endpoint.connect(signaling).await?;
            println!("✅ Client connection established!");

            // Keep connection alive for test duration
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
        "server" => {
            println!("📡 Accepting connection as server...");
            let _connection = endpoint.accept(signaling).await?;
            println!("✅ Server connection established!");

            // Keep connection alive for test duration
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        }
        _ => {
            return Err(format!("Invalid PEER_ROLE: {}", peer_role).into());
        }
    }

    Ok(())
}
