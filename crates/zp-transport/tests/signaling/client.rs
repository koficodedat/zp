//! HTTP signaling client for WebRTC peer coordination.
//!
//! Implements SignalingChannel trait over HTTP for cross-machine/container testing.

use async_trait::async_trait;
use reqwest::Client;
use std::error::Error;
use zp_transport::webrtc::{SignalingChannel, SignalingMessage};

use std::sync::Arc;
use tokio::sync::Mutex;

/// HTTP-based signaling channel
#[derive(Clone)]
pub struct HttpSignalingChannel {
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
    /// Create new HTTP signaling channel
    ///
    /// **server_url**: e.g. "http://127.0.0.1:8080"
    /// **session_id**: Unique session identifier (shared between peers)
    /// **peer_role**: "client" or "server" - determines which ICE candidate queue to use
    pub fn new(server_url: String, session_id: String, peer_role: String) -> Self {
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

    /// Create a new session on the signaling server and return session ID
    pub async fn create_session(server_url: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
        let client = Client::new();
        let response = client
            .post(format!("{}/session", server_url))
            .send()
            .await?
            .error_for_status()?;

        let session_response: serde_json::Value = response.json().await?;
        let session_id = session_response["session_id"]
            .as_str()
            .ok_or("Missing session_id in response")?
            .to_string();

        Ok(session_id)
    }

    /// Serialize SignalingMessage to JSON
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

    /// Deserialize JSON to SignalingMessage
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
    async fn send(&self, message: SignalingMessage) -> Result<(), Box<dyn Error + Send + Sync>> {
        let message_json = self.serialize_message(&message)?;

        // Determine endpoint and track sent message type
        let msg_type = match &message {
            SignalingMessage::Offer(_) => "OFFER",
            SignalingMessage::Answer(_) => "ANSWER",
            SignalingMessage::IceCandidate(_) => "ICE",
        };
        eprintln!("[SIGNALING] Sending {}", msg_type);

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

        // Send message wrapped in {"message": "..."} body
        let body = serde_json::json!({"message": message_json});

        eprintln!("[HTTP SIGNALING] 📤 POST {} ({})", endpoint, msg_type);
        let _response = self
            .client
            .post(&endpoint)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        eprintln!("[HTTP SIGNALING] ✅ POST {} succeeded", msg_type);

        Ok(())
    }

    async fn recv(&self) -> Result<SignalingMessage, Box<dyn Error + Send + Sync>> {
        eprintln!("[HTTP SIGNALING] 🔄 recv() called - entering polling loop");
        // Poll for messages (don't poll for message types we've sent)
        loop {
            eprintln!("[HTTP SIGNALING] 🔁 Loop iteration starting");

            // Try to get offer (only if we didn't send one AND haven't received one)
            let sent_offer = *self.sent_offer.lock().await;
            let received_offer = *self.received_offer.lock().await;
            let should_poll_offer = !sent_offer && !received_offer;
            eprintln!(
                "[HTTP SIGNALING] 🔍 Checking offer: should_poll={} (sent={}, received={})",
                should_poll_offer, sent_offer, received_offer
            );
            if should_poll_offer {
                if let Ok(response) = self
                    .client
                    .get(format!(
                        "{}/session/{}/offer",
                        self.server_url, self.session_id
                    ))
                    .send()
                    .await
                {
                    eprintln!(
                        "[HTTP SIGNALING] 📨 Offer poll response: {}",
                        response.status()
                    );
                    if response.status().is_success() {
                        let body: serde_json::Value = response.json().await?;
                        if let Some(message_json) = body["message"].as_str() {
                            eprintln!("[HTTP SIGNALING] ✅ Found OFFER - marking as received and returning it");
                            *self.received_offer.lock().await = true;
                            return self.deserialize_message(message_json);
                        } else {
                            eprintln!("[HTTP SIGNALING] ⏳ No offer available yet");
                        }
                    }
                }
            }

            // Try to get answer (only if we didn't send one AND haven't received one)
            let sent_answer = *self.sent_answer.lock().await;
            let received_answer = *self.received_answer.lock().await;
            let should_poll_answer = !sent_answer && !received_answer;
            eprintln!(
                "[HTTP SIGNALING] 🔍 Checking answer: should_poll={} (sent={}, received={})",
                should_poll_answer, sent_answer, received_answer
            );
            if should_poll_answer {
                if let Ok(response) = self
                    .client
                    .get(format!(
                        "{}/session/{}/answer",
                        self.server_url, self.session_id
                    ))
                    .send()
                    .await
                {
                    eprintln!(
                        "[HTTP SIGNALING] 📨 Answer poll response: {}",
                        response.status()
                    );
                    if response.status().is_success() {
                        let body: serde_json::Value = response.json().await?;
                        if let Some(message_json) = body["message"].as_str() {
                            eprintln!("[HTTP SIGNALING] ✅ Found ANSWER - marking as received and returning it");
                            *self.received_answer.lock().await = true;
                            return self.deserialize_message(message_json);
                        } else {
                            eprintln!("[HTTP SIGNALING] ⏳ No answer available yet");
                        }
                    }
                }
            }

            // Try to get ICE candidates (always poll for ICE)
            let ice_url = format!(
                "{}/session/{}/ice?role={}",
                self.server_url, self.session_id, self.peer_role
            );
            eprintln!("[HTTP SIGNALING] 🔍 Polling for ICE: GET {}", ice_url);

            if let Ok(response) = self.client.get(&ice_url).send().await {
                let status = response.status();
                eprintln!("[HTTP SIGNALING] 📨 ICE poll response: {}", status);

                if response.status().is_success() {
                    let body: serde_json::Value = response.json().await?;
                    eprintln!("[HTTP SIGNALING] 📦 ICE response body: {:?}", body);

                    if let Some(message_json) = body["message"].as_str() {
                        eprintln!("[HTTP SIGNALING] 📥 Received ICE candidate from server");
                        return self.deserialize_message(message_json);
                    } else {
                        eprintln!(
                            "[HTTP SIGNALING] ⏳ No ICE candidates available yet (message is null)"
                        );
                    }
                    // If message is null, no candidates available - continue polling
                } else {
                    eprintln!(
                        "[HTTP SIGNALING] ❌ ICE poll failed with status: {}",
                        status
                    );
                }
            } else {
                eprintln!("[HTTP SIGNALING] ❌ ICE poll request failed (network error)");
            }

            // Wait before polling again
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }
}
