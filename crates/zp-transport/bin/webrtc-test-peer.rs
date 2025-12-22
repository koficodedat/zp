//! Standalone WebRTC test peer binary for Docker-based testing.
//!
//! Reads configuration from environment variables and runs as client or server.

use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let signaling_url =
        env::var("SIGNALING_URL").expect("SIGNALING_URL environment variable required");

    let session_id = env::var("SESSION_ID").expect("SESSION_ID environment variable required");

    let peer_role = env::var("PEER_ROLE").unwrap_or_else(|_| "server".to_string());

    let stun_server =
        env::var("STUN_SERVER").unwrap_or_else(|_| "stun:stun.l.google.com:19302".to_string());

    eprintln!("🔧 WebRTC Test Peer starting:");
    eprintln!("   Role: {}", peer_role);
    eprintln!("   Signaling: {}", signaling_url);
    eprintln!("   Session: {}", session_id);
    eprintln!("   STUN: {}", stun_server);

    // Initialize crypto provider
    use std::sync::Once;
    static CRYPTO_INIT: Once = Once::new();
    CRYPTO_INIT.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install default crypto provider");
    });

    // Create WebRTC config
    use zp_transport::webrtc::WebRtcConfig;
    let config = WebRtcConfig {
        stun_servers: vec![stun_server],
        turn_servers: Vec::new(),
    };

    use zp_transport::webrtc::WebRtcEndpoint;
    let endpoint = WebRtcEndpoint::with_config(config).expect("Failed to create WebRTC endpoint");

    // Create HTTP signaling channel
    // This would need to be imported from tests, but that's not allowed
    // Instead, we'll need to move the signaling code to a shared location
    // For now, let's create a minimal implementation here

    use async_trait::async_trait;
    use reqwest::Client;
    use std::error::Error;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use zp_transport::webrtc::{SignalingChannel, SignalingMessage};

    #[derive(Clone)]
    struct HttpSignalingChannel {
        client: Client,
        server_url: String,
        session_id: String,
        peer_role: String, // "client" or "server"
        sent_offer: Arc<Mutex<bool>>,
        sent_answer: Arc<Mutex<bool>>,
        received_offer: Arc<Mutex<bool>>,
        received_answer: Arc<Mutex<bool>>,
    }

    impl HttpSignalingChannel {
        fn new(server_url: String, session_id: String, peer_role: String) -> Self {
            Self {
                client: Client::new(),
                server_url,
                session_id,
                peer_role,
                sent_offer: Arc::new(Mutex::new(false)),
                sent_answer: Arc::new(Mutex::new(false)),
                received_offer: Arc::new(Mutex::new(false)),
                received_answer: Arc::new(Mutex::new(false)),
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
                    format!(
                        "{}/session/{}/ice?role={}",
                        self.server_url, self.session_id, self.peer_role
                    )
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
                // Try to get offer (only if we didn't send one AND haven't received one)
                let sent_offer = *self.sent_offer.lock().await;
                let received_offer = *self.received_offer.lock().await;
                if !sent_offer && !received_offer {
                    if let Ok(response) = self
                        .client
                        .get(format!(
                            "{}/session/{}/offer",
                            self.server_url, self.session_id
                        ))
                        .send()
                        .await
                    {
                        if response.status().is_success() {
                            let body: serde_json::Value = response.json().await?;
                            if let Some(message_json) = body["message"].as_str() {
                                *self.received_offer.lock().await = true;
                                return self.deserialize_message(message_json);
                            }
                        }
                    }
                }

                // Try to get answer (only if we didn't send one AND haven't received one)
                let sent_answer = *self.sent_answer.lock().await;
                let received_answer = *self.received_answer.lock().await;
                if !sent_answer && !received_answer {
                    if let Ok(response) = self
                        .client
                        .get(format!(
                            "{}/session/{}/answer",
                            self.server_url, self.session_id
                        ))
                        .send()
                        .await
                    {
                        if response.status().is_success() {
                            let body: serde_json::Value = response.json().await?;
                            if let Some(message_json) = body["message"].as_str() {
                                *self.received_answer.lock().await = true;
                                return self.deserialize_message(message_json);
                            }
                        }
                    }
                }

                if let Ok(response) = self
                    .client
                    .get(format!(
                        "{}/session/{}/ice?role={}",
                        self.server_url, self.session_id, self.peer_role
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

    let signaling = HttpSignalingChannel::new(signaling_url, session_id, peer_role.clone());

    // Run as client or server
    match peer_role.as_str() {
        "client" => {
            eprintln!("📡 Connecting as client...");
            let connection = endpoint.connect(signaling).await?;
            eprintln!("✅ Client connection established!");
            eprintln!("   Role: {:?}", connection.role());

            // Keep connection alive for 60 seconds
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            eprintln!("✅ Client test peer completed successfully");
        }
        "server" => {
            eprintln!("📡 Accepting connection as server...");
            let connection = endpoint.accept(signaling).await?;
            eprintln!("✅ Server connection established!");
            eprintln!("   Role: {:?}", connection.role());

            // Keep connection alive for 60 seconds
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
            eprintln!("✅ Server test peer completed successfully");
        }
        _ => {
            return Err(format!("Invalid PEER_ROLE: {}", peer_role).into());
        }
    }

    Ok(())
}
