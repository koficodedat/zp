//! Standalone WebRTC test peer for Docker-based testing.
//!
//! Can be run as either client or server peer.

use super::client::HttpSignalingChannel;
use std::env;
use zp_transport::webrtc::WebRtcEndpoint;

/// Run as WebRTC peer (client or server)
///
/// Environment variables:
/// - SIGNALING_URL: HTTP signaling server URL
/// - SESSION_ID: Session ID for signaling
/// - PEER_ROLE: "client" or "server"
/// - STUN_SERVER: Optional STUN server (default: stun:stun.l.google.com:19302)
pub async fn run_test_peer() -> Result<(), Box<dyn std::error::Error>> {
    let signaling_url =
        env::var("SIGNALING_URL").expect("SIGNALING_URL environment variable required");

    let session_id = env::var("SESSION_ID").expect("SESSION_ID environment variable required");

    let peer_role = env::var("PEER_ROLE").unwrap_or_else(|_| "server".to_string());

    let stun_server =
        env::var("STUN_SERVER").unwrap_or_else(|_| "stun:stun.l.google.com:19302".to_string());

    eprintln!("🔧 Test peer starting:");
    eprintln!("   Role: {}", peer_role);
    eprintln!("   Signaling: {}", signaling_url);
    eprintln!("   Session: {}", session_id);
    eprintln!("   STUN: {}", stun_server);

    // Initialize crypto
    use std::sync::Once;
    static CRYPTO_INIT: Once = Once::new();
    CRYPTO_INIT.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install default crypto provider");
    });

    // Create WebRTC config
    let config = zp_transport::webrtc::WebRtcConfig {
        stun_servers: vec![stun_server],
        turn_servers: Vec::new(),
    };

    let endpoint = WebRtcEndpoint::with_config(config).expect("Failed to create WebRTC endpoint");

    let signaling = HttpSignalingChannel::new(signaling_url, session_id, peer_role.clone());

    // Run as client or server
    match peer_role.as_str() {
        "client" => {
            eprintln!("📡 Connecting as client...");
            let connection = endpoint.connect(signaling).await?;
            eprintln!("✅ Client connection established!");
            eprintln!("   Role: {:?}", connection.role());

            // Keep connection alive for 10 seconds
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            eprintln!("✅ Client test peer completed successfully");
        }
        "server" => {
            eprintln!("📡 Accepting connection as server...");
            let connection = endpoint.accept(signaling).await?;
            eprintln!("✅ Server connection established!");
            eprintln!("   Role: {:?}", connection.role());

            // Keep connection alive for 10 seconds
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
            eprintln!("✅ Server test peer completed successfully");
        }
        _ => {
            return Err(format!("Invalid PEER_ROLE: {}", peer_role).into());
        }
    }

    Ok(())
}
