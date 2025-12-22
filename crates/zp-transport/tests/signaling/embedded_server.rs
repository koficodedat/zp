//! Embedded HTTP signaling server for WebRTC tests.
//!
//! Zero-config server that auto-starts on a random port for test isolation.

use super::server::*;
use serde::Deserialize;
use std::net::SocketAddr;
use warp::Filter;

#[derive(Debug, Deserialize)]
struct RoleQuery {
    role: String, // "client" or "server"
}

/// Start signaling server on a random available port
///
/// Returns (server_url, shutdown_tx)
pub async fn start_server(
) -> Result<(String, tokio::sync::oneshot::Sender<()>), Box<dyn std::error::Error>> {
    let sessions = Sessions::default();

    // POST /session - Create new session
    let create_session_route = warp::path!("session")
        .and(warp::post())
        .and(with_sessions(sessions.clone()))
        .and_then(handle_create_session);

    // POST /session/{id}/offer - Store offer
    let store_offer_route = warp::path!("session" / String / "offer")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_sessions(sessions.clone()))
        .and_then(handle_store_offer);

    // GET /session/{id}/offer - Get offer
    let get_offer_route = warp::path!("session" / String / "offer")
        .and(warp::get())
        .and(with_sessions(sessions.clone()))
        .and_then(handle_get_offer);

    // POST /session/{id}/answer - Store answer
    let store_answer_route = warp::path!("session" / String / "answer")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_sessions(sessions.clone()))
        .and_then(handle_store_answer);

    // GET /session/{id}/answer - Get answer
    let get_answer_route = warp::path!("session" / String / "answer")
        .and(warp::get())
        .and(with_sessions(sessions.clone()))
        .and_then(handle_get_answer);

    // POST /session/{id}/ice?role=client|server - Add ICE candidate
    let add_ice_route = warp::path!("session" / String / "ice")
        .and(warp::post())
        .and(warp::query::<RoleQuery>())
        .and(warp::body::json())
        .and(with_sessions(sessions.clone()))
        .and_then(handle_add_ice);

    // GET /session/{id}/ice?role=client|server - Get ICE candidates
    let get_ice_route = warp::path!("session" / String / "ice")
        .and(warp::get())
        .and(warp::query::<RoleQuery>())
        .and(with_sessions(sessions.clone()))
        .and_then(handle_get_ice);

    let routes = create_session_route
        .or(store_offer_route)
        .or(get_offer_route)
        .or(store_answer_route)
        .or(get_answer_route)
        .or(add_ice_route)
        .or(get_ice_route);

    // Bind to random port (ephemeral port selection)
    let addr: SocketAddr = ([127, 0, 0, 1], 0).into();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let (addr, server) = warp::serve(routes).bind_with_graceful_shutdown(addr, async move {
        shutdown_rx.await.ok();
    });

    // Spawn server task
    tokio::spawn(server);

    let server_url = format!("http://{}", addr);
    Ok((server_url, shutdown_tx))
}

fn with_sessions(
    sessions: Sessions,
) -> impl Filter<Extract = (Sessions,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || sessions.clone())
}

// Handler functions

async fn handle_create_session(sessions: Sessions) -> Result<impl warp::Reply, warp::Rejection> {
    match create_session(sessions).await {
        Ok(session_id) => {
            let response = CreateSessionResponse { session_id };
            Ok(warp::reply::json(&response))
        }
        Err(e) => {
            // Return 500 with error message
            Err(warp::reject::custom(ServerError(e)))
        }
    }
}

async fn handle_store_offer(
    session_id: String,
    body: MessageBody,
    sessions: Sessions,
) -> Result<impl warp::Reply, warp::Rejection> {
    match store_message(sessions, session_id, body.message, "offer").await {
        Ok(_) => Ok(warp::reply::with_status("OK", warp::http::StatusCode::OK)),
        Err(e) => Err(warp::reject::custom(ServerError(e))),
    }
}

async fn handle_get_offer(
    session_id: String,
    sessions: Sessions,
) -> Result<impl warp::Reply, warp::Rejection> {
    match get_message(sessions, session_id, "offer").await {
        Ok(message) => {
            let response = MessageBody { message };
            Ok(warp::reply::json(&response))
        }
        Err(e) => Err(warp::reject::custom(ServerError(e))),
    }
}

async fn handle_store_answer(
    session_id: String,
    body: MessageBody,
    sessions: Sessions,
) -> Result<impl warp::Reply, warp::Rejection> {
    match store_message(sessions, session_id, body.message, "answer").await {
        Ok(_) => Ok(warp::reply::with_status("OK", warp::http::StatusCode::OK)),
        Err(e) => Err(warp::reject::custom(ServerError(e))),
    }
}

async fn handle_get_answer(
    session_id: String,
    sessions: Sessions,
) -> Result<impl warp::Reply, warp::Rejection> {
    match get_message(sessions, session_id, "answer").await {
        Ok(message) => {
            let response = MessageBody { message };
            Ok(warp::reply::json(&response))
        }
        Err(e) => Err(warp::reject::custom(ServerError(e))),
    }
}

async fn handle_add_ice(
    session_id: String,
    query: RoleQuery,
    body: MessageBody,
    sessions: Sessions,
) -> Result<impl warp::Reply, warp::Rejection> {
    eprintln!(
        "[SIGNALING SERVER] 📥 POST /session/{}/ice?role={}",
        session_id, query.role
    );
    match store_ice_candidate(sessions, session_id.clone(), body.message, &query.role).await {
        Ok(_) => {
            eprintln!(
                "[SIGNALING SERVER] ✅ Stored ICE candidate for role={}",
                query.role
            );
            Ok(warp::reply::with_status("OK", warp::http::StatusCode::OK))
        }
        Err(e) => {
            eprintln!("[SIGNALING SERVER] ❌ Failed to store ICE: {}", e);
            Err(warp::reject::custom(ServerError(e)))
        }
    }
}

async fn handle_get_ice(
    session_id: String,
    query: RoleQuery,
    sessions: Sessions,
) -> Result<impl warp::Reply, warp::Rejection> {
    eprintln!(
        "[SIGNALING SERVER] 🔍 GET /session/{}/ice?role={}",
        session_id, query.role
    );
    match pop_ice_candidate(sessions, session_id.clone(), &query.role).await {
        Ok(Some(message)) => {
            eprintln!(
                "[SIGNALING SERVER] 📤 Returning ICE candidate for role={}",
                query.role
            );
            // Return single ICE candidate wrapped in MessageBody
            let response = MessageBody { message };
            Ok(warp::reply::json(&response))
        }
        Ok(None) => {
            eprintln!(
                "[SIGNALING SERVER] ⏳ No ICE candidates available for role={}",
                query.role
            );
            // No candidates available - return 204 No Content
            Ok(warp::reply::json(&serde_json::json!({"message": null})))
        }
        Err(e) => {
            eprintln!("[SIGNALING SERVER] ❌ Failed to get ICE: {}", e);
            Err(warp::reject::custom(ServerError(e)))
        }
    }
}

// Custom error type for warp
#[derive(Debug)]
struct ServerError(#[allow(dead_code)] String);

impl warp::reject::Reject for ServerError {}
