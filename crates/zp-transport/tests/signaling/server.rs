//! HTTP signaling server for WebRTC test coordination.
//!
//! Enables SDP/ICE exchange between peers on different machines/containers.
//!
//! **API:**
//! - POST /session → Create session, returns session_id
//! - POST /session/{id}/offer → Store SDP offer
//! - GET /session/{id}/offer → Retrieve SDP offer
//! - POST /session/{id}/answer → Store SDP answer
//! - GET /session/{id}/answer → Retrieve SDP answer
//! - POST /session/{id}/ice → Add ICE candidate
//! - GET /session/{id}/ice → Poll for ICE candidates

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Signaling session state
#[derive(Debug, Clone)]
pub struct Session {
    #[allow(dead_code)]
    pub id: String,
    pub offer: Option<String>,
    pub answer: Option<String>,
    /// ICE candidates from client (for server to consume)
    pub client_ice_candidates: Vec<String>,
    /// ICE candidates from server (for client to consume)
    pub server_ice_candidates: Vec<String>,
}

/// Shared state for all sessions
pub type Sessions = Arc<RwLock<HashMap<String, Session>>>;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    pub session_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageBody {
    pub message: String,
}

/// Create a new signaling session
pub async fn create_session(sessions: Sessions) -> Result<String, String> {
    let session_id = uuid::Uuid::new_v4().to_string();
    let session = Session {
        id: session_id.clone(),
        offer: None,
        answer: None,
        client_ice_candidates: Vec::new(),
        server_ice_candidates: Vec::new(),
    };

    sessions.write().await.insert(session_id.clone(), session);
    Ok(session_id)
}

/// Store message (offer/answer/ice)
pub async fn store_message(
    sessions: Sessions,
    session_id: String,
    message: String,
    message_type: &str,
) -> Result<(), String> {
    let mut sessions = sessions.write().await;
    let session = sessions
        .get_mut(&session_id)
        .ok_or_else(|| "Session not found".to_string())?;

    match message_type {
        "offer" => session.offer = Some(message),
        "answer" => session.answer = Some(message),
        _ => return Err(format!("Unknown message type: {}", message_type)),
    }
    Ok(())
}

/// Get message (offer/answer) with polling
pub async fn get_message(
    sessions: Sessions,
    session_id: String,
    message_type: &str,
) -> Result<String, String> {
    // Poll for up to 30 seconds
    for _ in 0..60 {
        let sessions = sessions.read().await;
        if let Some(session) = sessions.get(&session_id) {
            let message = match message_type {
                "offer" => session.offer.as_ref(),
                "answer" => session.answer.as_ref(),
                _ => return Err(format!("Unknown message type: {}", message_type)),
            };
            if let Some(msg) = message {
                return Ok(msg.clone());
            }
        }
        drop(sessions);
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }
    Err(format!("{} not available (timeout)", message_type))
}

/// Store ICE candidate from a peer to the appropriate queue
pub async fn store_ice_candidate(
    sessions: Sessions,
    session_id: String,
    candidate: String,
    peer_role: &str,
) -> Result<(), String> {
    let mut sessions = sessions.write().await;
    let session = sessions
        .get_mut(&session_id)
        .ok_or_else(|| "Session not found".to_string())?;

    // Store in the appropriate queue based on who sent it
    match peer_role {
        "client" => session.client_ice_candidates.push(candidate),
        "server" => session.server_ice_candidates.push(candidate),
        _ => return Err(format!("Invalid peer role: {}", peer_role)),
    }
    Ok(())
}

/// Pop next unconsumed ICE candidate from the OTHER peer's queue
/// Client pops from server queue, server pops from client queue
pub async fn pop_ice_candidate(
    sessions: Sessions,
    session_id: String,
    peer_role: &str,
) -> Result<Option<String>, String> {
    let mut sessions = sessions.write().await;
    let session = sessions
        .get_mut(&session_id)
        .ok_or_else(|| "Session not found".to_string())?;

    eprintln!("[SERVER QUEUE] 🔍 pop_ice_candidate for role={}", peer_role);
    eprintln!(
        "[SERVER QUEUE]    client_queue.len = {}, server_queue.len = {}",
        session.client_ice_candidates.len(),
        session.server_ice_candidates.len()
    );

    // Pop from the OTHER peer's queue (client reads from server, server reads from client)
    let queue = match peer_role {
        "client" => {
            eprintln!("[SERVER QUEUE]    Reading from server_queue (client is popping)");
            &mut session.server_ice_candidates
        }
        "server" => {
            eprintln!("[SERVER QUEUE]    Reading from client_queue (server is popping)");
            &mut session.client_ice_candidates
        }
        _ => return Err(format!("Invalid peer role: {}", peer_role)),
    };

    if queue.is_empty() {
        eprintln!("[SERVER QUEUE] ⏳ Queue is empty");
        Ok(None)
    } else {
        let candidate = queue.remove(0);
        eprintln!(
            "[SERVER QUEUE] ✅ Popped candidate, {} remaining in queue",
            queue.len()
        );
        Ok(Some(candidate))
    }
}
