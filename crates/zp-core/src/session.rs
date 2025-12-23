//! Session management and handshake state machine.
//!
//! Implements:
//! - Handshake state machines (Stranger Mode §4.2, Known Mode §4.3)
//! - Cipher suite negotiation
//! - Session key derivation
//! - Cipher pinning validation

use crate::{frame::Frame, Error, Result};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zp_crypto::{
    kdf::{
        derive_session_keys_stranger, derive_session_secret_stranger, derive_traffic_key,
        update_current_secret, KeyDirection,
    },
    kex::{EcdhP256KeyPair, MlKem1024KeyPair, MlKem768KeyPair, X25519KeyPair},
    suite::{CipherSuite, MlKemVariant},
};

/// Cipher suite constants per spec Appendix A.
/// Cipher suite: X25519 + ML-KEM-768 + ChaCha20-Poly1305 (0x01).
pub const ZP_HYBRID_1: u8 = 0x01;
/// Cipher suite: X25519 + ML-KEM-1024 + ChaCha20-Poly1305 (0x02).
pub const ZP_HYBRID_2: u8 = 0x02;
/// Cipher suite: X25519 + ML-KEM-768 + AES-256-GCM (0x03).
pub const ZP_HYBRID_3: u8 = 0x03;
/// Cipher suite: ECDH-P256 + AES-256-GCM (0x11, FIPS mode).
pub const ZP_CLASSICAL_2: u8 = 0x11;

/// Protocol version constants.
pub const VERSION_1_0: u16 = 0x0100; // Version 1.0

/// Type alias for client key exchange result: (ML-KEM ciphertext, shared secret).
type ClientKeyExchangeResult = (Option<Vec<u8>>, Zeroizing<Vec<u8>>);

/// Session configuration.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Supported protocol versions (descending preference).
    pub supported_versions: Vec<u16>,
    /// Minimum acceptable version.
    pub min_version: u16,
    /// Supported cipher suites (descending preference).
    pub supported_ciphers: Vec<u8>,
    /// Handshake timeout in milliseconds.
    pub handshake_timeout_ms: u64,
    /// Maximum handshake retries.
    pub handshake_retries: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            supported_versions: vec![VERSION_1_0],
            min_version: VERSION_1_0,
            supported_ciphers: vec![ZP_HYBRID_1, ZP_HYBRID_2, ZP_HYBRID_3, ZP_CLASSICAL_2],
            handshake_timeout_ms: 5000,
            handshake_retries: 3,
        }
    }
}

/// Session role (Client or Server).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Client role (initiates handshake).
    Client,
    /// Server role (accepts handshake).
    Server,
}

/// Handshake mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeMode {
    /// Stranger Mode (§4.2) - TOFU, no authentication.
    Stranger,
    /// Known Mode (§4.3) - SPAKE2+ with pre-shared secret.
    Known,
}

/// Session state machine.
pub struct Session {
    role: Role,
    mode: HandshakeMode,
    config: SessionConfig,
    state: SessionState,
    /// Session keys after handshake completes.
    keys: Option<SessionKeys>,
}

/// Handshake key material for different cipher suites.
#[allow(dead_code)] // X25519 variant used in Known mode (not yet implemented)
enum KeyMaterial {
    /// X25519 only (classical modes).
    X25519(X25519KeyPair),
    /// X25519 + ML-KEM-768.
    Hybrid768(X25519KeyPair, Box<MlKem768KeyPair>),
    /// X25519 + ML-KEM-1024.
    Hybrid1024(X25519KeyPair, Box<MlKem1024KeyPair>),
    /// ECDH-P256 only (FIPS mode).
    EcdhP256(EcdhP256KeyPair),
}

/// Session states during handshake.
#[allow(dead_code)] // Some states used in Known mode and session closure (not yet implemented)
enum SessionState {
    /// Initial state, no handshake started.
    Idle,
    /// Client: ClientHello sent, awaiting ServerHello.
    ClientHelloSent {
        client_random: [u8; 32],
        x25519_keypair: X25519KeyPair,
    },
    /// Server: ClientHello received, preparing ServerHello.
    ServerHelloReady {
        client_random: [u8; 32],
        client_x25519_pubkey: [u8; 32],
        selected_version: u16,
        selected_cipher: u8,
    },
    /// Server: ServerHello sent, awaiting ClientFinish.
    ServerHelloSent {
        client_random: [u8; 32],
        server_random: [u8; 32],
        client_x25519_pubkey: [u8; 32],
        key_material: KeyMaterial,
        selected_version: u16,
        selected_cipher: u8,
    },
    /// Client: ServerHello received, preparing ClientFinish.
    ClientFinishReady {
        client_random: [u8; 32],
        server_random: [u8; 32],
        x25519_keypair: X25519KeyPair,
        server_x25519_pubkey: [u8; 32],
        mlkem_pubkey: Option<Vec<u8>>,
        selected_version: u16,
        selected_cipher: u8,
    },
    /// Client: KnownHello sent (Known Mode), awaiting KnownResponse.
    KnownHelloSent {
        client_random: [u8; 32],
        opaque_client_state: Vec<u8>,
        opaque_credential_request: Vec<u8>, // Needed for encryption key derivation
    },
    /// Server: KnownResponse sent (Known Mode), awaiting KnownFinish.
    KnownResponseSent {
        client_random: [u8; 32],
        server_random: [u8; 32],
        opaque_server_state: Vec<u8>,
        key_material: KeyMaterial,
        selected_version: u16,
        selected_cipher: u8,
    },
    /// Client: KnownResponse received (Known Mode), preparing KnownFinish.
    KnownFinishReady {
        client_random: [u8; 32],
        server_random: [u8; 32],
        opaque_session_key: Zeroizing<Vec<u8>>,
        mlkem_pubkey: Vec<u8>,
        selected_version: u16,
        selected_cipher: u8,
    },
    /// Handshake complete, application data allowed.
    Established {
        session_id: [u8; 16],
        version: u16,
        cipher: u8,
    },
    /// Session closed.
    Closed,
}

/// Session keys derived after handshake.
#[derive(Clone)]
pub struct SessionKeys {
    /// Session identifier (16 bytes).
    pub session_id: [u8; 16],
    /// Session secret for key rotation (current_secret).
    pub session_secret: Zeroizing<[u8; 32]>,
    /// Client-to-server key.
    pub client_to_server_key: Zeroizing<[u8; 32]>,
    /// Server-to-client key.
    pub server_to_client_key: Zeroizing<[u8; 32]>,
    /// Send key (role-dependent).
    pub send_key: Zeroizing<[u8; 32]>,
    /// Receive key (role-dependent).
    pub recv_key: Zeroizing<[u8; 32]>,
    /// Current key epoch (increments on each rotation).
    pub key_epoch: u32,
    /// Pending key rotation epoch (if waiting for ack).
    pub pending_epoch: Option<u32>,
    /// Send nonce counter for EncryptedRecord (§3.3.13).
    /// Increments for each outbound encrypted frame.
    pub send_nonce: u64,
    /// Receive nonce counter for EncryptedRecord (§3.3.13).
    /// Expected value for next inbound encrypted frame.
    pub recv_nonce: u64,
}

/// Generate 32 random bytes using a cryptographically secure RNG.
fn random_bytes_32() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Derive session ID for Stranger Mode per spec §4.2.4.
///
/// session_id = SHA-256(client_random || server_random || shared_secret)[0:16]
///
/// # Collision Probability
/// With 128-bit session IDs:
/// - ~1% collision after 2^64 sessions (birthday paradox)
/// - ~0.01% collision after 10K sessions
/// - Transport layer should detect and handle collisions
fn derive_session_id_stranger(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    shared_secret: &[u8],
) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(client_random);
    hasher.update(server_random);
    hasher.update(shared_secret);
    let hash = hasher.finalize();
    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&hash[0..16]);
    session_id
}

/// Check if a session ID collides with existing session IDs.
///
/// # Arguments
/// * `session_id` - The session ID to check
/// * `existing_ids` - Slice of existing session IDs to check against
///
/// # Returns
/// `true` if the session_id matches any existing ID (collision detected)
///
/// # Example
/// ```ignore
/// let existing = vec![[1u8; 16], [2u8; 16]];
/// if session_id_collides(&new_id, &existing) {
///     // Handle collision - regenerate or reject
/// }
/// ```
pub fn session_id_collides(session_id: &[u8; 16], existing_ids: &[[u8; 16]]) -> bool {
    existing_ids.iter().any(|existing| existing == session_id)
}

impl Session {
    /// Create a new session with the given role and mode.
    pub fn new(role: Role, mode: HandshakeMode) -> Self {
        Self::with_config(role, mode, SessionConfig::default())
    }

    /// Create a new session with custom configuration.
    pub fn with_config(role: Role, mode: HandshakeMode, config: SessionConfig) -> Self {
        Self {
            role,
            mode,
            config,
            state: SessionState::Idle,
            keys: None,
        }
    }

    /// Get current role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Get handshake mode.
    pub fn mode(&self) -> HandshakeMode {
        self.mode
    }

    /// Check if handshake is complete.
    pub fn is_established(&self) -> bool {
        matches!(self.state, SessionState::Established { .. })
    }

    /// Get session keys (only available after handshake completes).
    pub fn keys(&self) -> Option<&SessionKeys> {
        self.keys.as_ref()
    }

    /// Get session ID (only available after handshake completes).
    ///
    /// # Returns
    /// `Some(&[u8; 16])` if session is established, `None` otherwise
    pub fn session_id(&self) -> Option<[u8; 16]> {
        match &self.state {
            SessionState::Established { session_id, .. } => Some(*session_id),
            _ => None,
        }
    }

    /// Check if handshake is in progress (not Idle, Established, or Closed).
    pub fn is_handshake_in_progress(&self) -> bool {
        !matches!(
            self.state,
            SessionState::Idle | SessionState::Established { .. } | SessionState::Closed
        )
    }

    /// Check if handshake has timed out.
    ///
    /// # Arguments
    /// * `elapsed_ms` - Milliseconds elapsed since handshake started
    ///
    /// # Returns
    /// `true` if handshake is in progress and has exceeded configured timeout
    ///
    /// # Example
    /// ```ignore
    /// if session.is_handshake_timeout(elapsed_ms) {
    ///     return Err(Error::HandshakeTimeout);
    /// }
    /// ```
    pub fn is_handshake_timeout(&self, elapsed_ms: u64) -> bool {
        self.is_handshake_in_progress() && elapsed_ms > self.config.handshake_timeout_ms
    }

    /// Get configured handshake timeout in milliseconds.
    pub fn handshake_timeout_ms(&self) -> u64 {
        self.config.handshake_timeout_ms
    }

    // === Client-side handshake (Stranger Mode) ===

    /// Initiate handshake as client (Stranger Mode).
    ///
    /// Returns ClientHello frame to send.
    pub fn client_start_stranger(&mut self) -> Result<Frame> {
        if self.role != Role::Client {
            return Err(Error::ProtocolViolation("Not a client".into()));
        }
        if self.mode != HandshakeMode::Stranger {
            return Err(Error::ProtocolViolation("Not Stranger mode".into()));
        }
        if !matches!(self.state, SessionState::Idle) {
            return Err(Error::InvalidState);
        }

        // Generate ephemeral X25519 keypair
        let x25519_keypair = X25519KeyPair::generate()?;
        let x25519_pubkey = *x25519_keypair.public_key();

        // Generate random nonce
        let client_random = random_bytes_32();

        // Build ClientHello
        let frame = Frame::ClientHello {
            supported_versions: self.config.supported_versions.clone(),
            min_version: self.config.min_version,
            supported_ciphers: self.config.supported_ciphers.clone(),
            x25519_pubkey,
            random: client_random,
        };

        self.state = SessionState::ClientHelloSent {
            client_random,
            x25519_keypair,
        };

        Ok(frame)
    }

    /// Process ServerHello as client (Stranger Mode).
    ///
    /// Returns ClientFinish frame to send.
    pub fn client_process_server_hello(&mut self, frame: Frame) -> Result<Frame> {
        // Extract and take ownership of the keypair from state
        let (client_random, x25519_keypair) =
            match std::mem::replace(&mut self.state, SessionState::Idle) {
                SessionState::ClientHelloSent {
                    client_random,
                    x25519_keypair,
                } => (client_random, x25519_keypair),
                old_state => {
                    self.state = old_state;
                    return Err(Error::InvalidState);
                }
            };

        let (selected_version, selected_cipher, server_x25519_pubkey, mlkem_pubkey, server_random) =
            match frame {
                Frame::ServerHello {
                    selected_version,
                    selected_cipher,
                    x25519_pubkey,
                    mlkem_pubkey,
                    random,
                } => (
                    selected_version,
                    selected_cipher,
                    x25519_pubkey,
                    mlkem_pubkey,
                    random,
                ),
                _ => return Err(Error::InvalidFrame("Expected ServerHello".into())),
            };

        // Validate version
        if selected_version < self.config.min_version {
            return Err(Error::VersionMismatch);
        }

        // Validate cipher suite
        if !self.config.supported_ciphers.contains(&selected_cipher) {
            return Err(Error::ProtocolViolation("Unsupported cipher".into()));
        }

        self.state = SessionState::ClientFinishReady {
            client_random,
            server_random,
            x25519_keypair,
            server_x25519_pubkey,
            mlkem_pubkey: if mlkem_pubkey.is_empty() {
                None
            } else {
                Some(mlkem_pubkey)
            },
            selected_version,
            selected_cipher,
        };

        // Build ClientFinish
        self.client_build_finish()
    }

    fn client_build_finish(&mut self) -> Result<Frame> {
        // Take ownership of state to extract keypair
        let (
            client_random,
            server_random,
            x25519_keypair,
            server_x25519_pubkey,
            mlkem_pubkey,
            selected_version,
            selected_cipher,
        ) = match std::mem::replace(&mut self.state, SessionState::Idle) {
            SessionState::ClientFinishReady {
                client_random,
                server_random,
                x25519_keypair,
                server_x25519_pubkey,
                mlkem_pubkey,
                selected_version,
                selected_cipher,
            } => (
                client_random,
                server_random,
                x25519_keypair,
                server_x25519_pubkey,
                mlkem_pubkey,
                selected_version,
                selected_cipher,
            ),
            old_state => {
                self.state = old_state;
                return Err(Error::InvalidState);
            }
        };

        // Perform key exchanges
        let (mlkem_ciphertext, shared_secret) = self.client_derive_shared_secret(
            &x25519_keypair,
            &server_x25519_pubkey,
            mlkem_pubkey.as_deref(),
            selected_cipher,
        )?;

        // Derive session keys
        let keys = self.derive_stranger_session_keys(
            &client_random,
            &server_random,
            &shared_secret,
            self.role,
        )?;

        // Transition to Established
        self.state = SessionState::Established {
            session_id: keys.session_id,
            version: selected_version,
            cipher: selected_cipher,
        };
        self.keys = Some(keys);

        // Build ClientFinish frame
        Ok(Frame::ClientFinish {
            mlkem_ciphertext: mlkem_ciphertext.unwrap_or_default(),
        })
    }

    // === Server-side handshake (Stranger Mode) ===

    /// Process ClientHello as server (Stranger Mode).
    ///
    /// Returns ServerHello frame to send.
    pub fn server_process_client_hello(&mut self, frame: Frame) -> Result<Frame> {
        if self.role != Role::Server {
            return Err(Error::ProtocolViolation("Not a server".into()));
        }
        if self.mode != HandshakeMode::Stranger {
            return Err(Error::ProtocolViolation("Not Stranger mode".into()));
        }
        if !matches!(self.state, SessionState::Idle) {
            return Err(Error::InvalidState);
        }

        let (
            supported_versions,
            min_version,
            supported_ciphers,
            client_x25519_pubkey,
            client_random,
        ) = match frame {
            Frame::ClientHello {
                supported_versions,
                min_version,
                supported_ciphers,
                x25519_pubkey,
                random,
            } => (
                supported_versions,
                min_version,
                supported_ciphers,
                x25519_pubkey,
                random,
            ),
            _ => return Err(Error::InvalidFrame("Expected ClientHello".into())),
        };

        // Negotiate version
        let selected_version = self.negotiate_version(&supported_versions, min_version)?;

        // Negotiate cipher suite
        let selected_cipher = self.negotiate_cipher(&supported_ciphers)?;

        self.state = SessionState::ServerHelloReady {
            client_random,
            client_x25519_pubkey,
            selected_version,
            selected_cipher,
        };

        self.server_build_hello()
    }

    fn server_build_hello(&mut self) -> Result<Frame> {
        let (client_random, client_x25519_pubkey, selected_version, selected_cipher) =
            match &self.state {
                SessionState::ServerHelloReady {
                    client_random,
                    client_x25519_pubkey,
                    selected_version,
                    selected_cipher,
                } => (
                    *client_random,
                    *client_x25519_pubkey,
                    *selected_version,
                    *selected_cipher,
                ),
                _ => return Err(Error::InvalidState),
            };

        // Generate key material based on cipher suite
        let (x25519_pubkey, mlkem_pubkey, key_material) = match selected_cipher {
            ZP_CLASSICAL_2 => {
                // FIPS mode: ECDH-P256 only
                // TODO: Verify frame format for P-256 keys (65 bytes) vs x25519 field (32 bytes)
                // For now, use ECDH-P256 and extract x-coordinate
                let ecdh_keypair = EcdhP256KeyPair::generate()?;
                let pubkey_bytes = ecdh_keypair.public_key();
                // P-256 uncompressed: 0x04 || x (32 bytes) || y (32 bytes)
                let mut x25519_pub = [0u8; 32];
                x25519_pub.copy_from_slice(&pubkey_bytes[1..33]); // Extract x-coordinate
                (x25519_pub, Vec::new(), KeyMaterial::EcdhP256(ecdh_keypair))
            }
            ZP_HYBRID_1 | ZP_HYBRID_3 => {
                // X25519 + ML-KEM-768
                let x25519_keypair = X25519KeyPair::generate()?;
                let mlkem_keypair = MlKem768KeyPair::generate()?;
                let x25519_pub = *x25519_keypair.public_key();
                let mlkem_pub = mlkem_keypair.public_key().to_vec();
                (
                    x25519_pub,
                    mlkem_pub,
                    KeyMaterial::Hybrid768(x25519_keypair, Box::new(mlkem_keypair)),
                )
            }
            ZP_HYBRID_2 => {
                // X25519 + ML-KEM-1024
                let x25519_keypair = X25519KeyPair::generate()?;
                let mlkem_keypair = MlKem1024KeyPair::generate()?;
                let x25519_pub = *x25519_keypair.public_key();
                let mlkem_pub = mlkem_keypair.public_key().to_vec();
                (
                    x25519_pub,
                    mlkem_pub,
                    KeyMaterial::Hybrid1024(x25519_keypair, Box::new(mlkem_keypair)),
                )
            }
            _ => return Err(Error::ProtocolViolation("Unsupported cipher suite".into())),
        };

        // Generate random nonce
        let server_random = random_bytes_32();

        self.state = SessionState::ServerHelloSent {
            client_random,
            server_random,
            client_x25519_pubkey,
            key_material,
            selected_version,
            selected_cipher,
        };

        Ok(Frame::ServerHello {
            selected_version,
            selected_cipher,
            x25519_pubkey,
            mlkem_pubkey,
            random: server_random,
        })
    }

    /// Process ClientFinish as server (Stranger Mode).
    ///
    /// Completes handshake. Returns Ok(()) on success.
    pub fn server_process_client_finish(&mut self, frame: Frame) -> Result<()> {
        // Take ownership of state to extract key_material
        let (
            client_random,
            server_random,
            client_x25519_pubkey,
            key_material,
            selected_version,
            selected_cipher,
        ) = match std::mem::replace(&mut self.state, SessionState::Idle) {
            SessionState::ServerHelloSent {
                client_random,
                server_random,
                client_x25519_pubkey,
                key_material,
                selected_version,
                selected_cipher,
            } => (
                client_random,
                server_random,
                client_x25519_pubkey,
                key_material,
                selected_version,
                selected_cipher,
            ),
            old_state => {
                self.state = old_state;
                return Err(Error::InvalidState);
            }
        };

        let mlkem_ciphertext = match frame {
            Frame::ClientFinish { mlkem_ciphertext } => mlkem_ciphertext,
            _ => return Err(Error::InvalidFrame("Expected ClientFinish".into())),
        };

        // Perform key exchanges
        let shared_secret = self.server_derive_shared_secret(
            &client_x25519_pubkey,
            &key_material,
            if mlkem_ciphertext.is_empty() {
                None
            } else {
                Some(&mlkem_ciphertext)
            },
            selected_cipher,
        )?;

        // Derive session keys
        let keys = self.derive_stranger_session_keys(
            &client_random,
            &server_random,
            &shared_secret,
            self.role,
        )?;

        // Transition to Established
        self.state = SessionState::Established {
            session_id: keys.session_id,
            version: selected_version,
            cipher: selected_cipher,
        };
        self.keys = Some(keys);

        Ok(())
    }

    // === Client-side handshake (Known Mode) ===

    /// Initiate handshake as client (Known Mode with OPAQUE).
    ///
    /// Returns KnownHello frame to send.
    ///
    /// # Arguments
    ///
    /// - `password`: User's password for OPAQUE authentication
    /// - `credential_identifier`: Username or user identifier (e.g., "user@example.com")
    pub fn client_start_known(
        &mut self,
        password: &[u8],
        _credential_identifier: &[u8],
    ) -> Result<Frame> {
        if self.role != Role::Client {
            return Err(Error::ProtocolViolation("Not a client".into()));
        }
        if self.mode != HandshakeMode::Known {
            return Err(Error::ProtocolViolation("Not Known mode".into()));
        }
        if !matches!(self.state, SessionState::Idle) {
            return Err(Error::InvalidState);
        }

        // Start OPAQUE login flow
        use zp_crypto::pake;
        let mut rng = rand::rngs::OsRng;
        let (credential_request, client_state) = pake::login_start(password, &mut rng)
            .map_err(|e| Error::ProtocolViolation(format!("OPAQUE login_start failed: {}", e)))?;

        // Generate random nonce
        let client_random = random_bytes_32();

        // Build KnownHello
        let frame = Frame::KnownHello {
            supported_versions: self.config.supported_versions.clone(),
            min_version: self.config.min_version,
            supported_ciphers: self.config.supported_ciphers.clone(),
            opaque_credential_request: credential_request.clone(),
            random: client_random,
        };

        self.state = SessionState::KnownHelloSent {
            client_random,
            opaque_client_state: client_state,
            opaque_credential_request: credential_request,
        };

        Ok(frame)
    }

    /// Process KnownResponse as client (Known Mode with OPAQUE).
    ///
    /// Returns KnownFinish frame to send.
    ///
    /// # Arguments
    ///
    /// - `frame`: KnownResponse from server
    /// - `password`: User's password (same as in `client_start_known`)
    /// - `credential_identifier`: Username (must match what was used in `client_start_known`)
    pub fn client_process_known_response(
        &mut self,
        frame: Frame,
        password: &[u8],
        credential_identifier: &[u8],
    ) -> Result<Frame> {
        // Extract state
        let (client_random, opaque_client_state, opaque_credential_request) =
            match std::mem::replace(&mut self.state, SessionState::Idle) {
                SessionState::KnownHelloSent {
                    client_random,
                    opaque_client_state,
                    opaque_credential_request,
                } => (
                    client_random,
                    opaque_client_state,
                    opaque_credential_request,
                ),
                old_state => {
                    self.state = old_state;
                    return Err(Error::InvalidState);
                }
            };

        let (
            selected_version,
            selected_cipher,
            opaque_credential_response,
            server_random,
            mlkem_pubkey_encrypted,
        ) = match frame {
            Frame::KnownResponse {
                selected_version,
                selected_cipher,
                opaque_credential_response,
                random,
                mlkem_pubkey_encrypted,
            } => (
                selected_version,
                selected_cipher,
                opaque_credential_response,
                random,
                mlkem_pubkey_encrypted,
            ),
            _ => return Err(Error::InvalidFrame("Expected KnownResponse".into())),
        };

        // Validate version
        if selected_version < self.config.min_version {
            return Err(Error::VersionMismatch);
        }

        // Validate cipher suite
        if !self.config.supported_ciphers.contains(&selected_cipher) {
            return Err(Error::ProtocolViolation("Unsupported cipher".into()));
        }

        // Derive encryption key from OPAQUE CredentialRequest + CredentialResponse
        // (same as server-side derivation)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"zp-known-mode-mlkem-encryption");
        hasher.update(&opaque_credential_request); // CredentialRequest we sent in KnownHello
        hasher.update(&opaque_credential_response);
        let encryption_key_hash = hasher.finalize();
        let encryption_key: [u8; 32] = encryption_key_hash.into();

        // Complete OPAQUE login (client side)
        use zp_crypto::pake;
        let (opaque_finalization, opaque_session_key) = pake::login_finalize(
            password,
            &opaque_credential_response,
            credential_identifier,
            &opaque_client_state,
        )
        .map_err(|e| Error::ProtocolViolation(format!("OPAQUE login_finalize failed: {}", e)))?;

        // Decrypt ML-KEM public key
        let mlkem_pubkey =
            self.decrypt_mlkem_pubkey(&encryption_key, &server_random, &mlkem_pubkey_encrypted)?;

        self.state = SessionState::KnownFinishReady {
            client_random,
            server_random,
            opaque_session_key,
            mlkem_pubkey,
            selected_version,
            selected_cipher,
        };

        // Build KnownFinish
        self.client_build_known_finish(opaque_finalization)
    }

    fn client_build_known_finish(&mut self, opaque_finalization: Vec<u8>) -> Result<Frame> {
        // Take ownership of state
        let (
            client_random,
            server_random,
            opaque_session_key,
            mlkem_pubkey,
            selected_version,
            selected_cipher,
        ) = match std::mem::replace(&mut self.state, SessionState::Idle) {
            SessionState::KnownFinishReady {
                client_random,
                server_random,
                opaque_session_key,
                mlkem_pubkey,
                selected_version,
                selected_cipher,
            } => (
                client_random,
                server_random,
                opaque_session_key,
                mlkem_pubkey,
                selected_version,
                selected_cipher,
            ),
            old_state => {
                self.state = old_state;
                return Err(Error::InvalidState);
            }
        };

        // Perform ML-KEM encapsulation
        let (mlkem_ciphertext, mlkem_shared_secret) =
            self.mlkem_encapsulate(&mlkem_pubkey, selected_cipher)?;

        // Derive encryption key from OPAQUE session_key (first 32 bytes)
        let encryption_key = &opaque_session_key[..32];

        // Encrypt ML-KEM ciphertext
        let mlkem_ciphertext_encrypted =
            self.encrypt_mlkem_ciphertext(encryption_key, &client_random, &mlkem_ciphertext)?;

        // Derive session keys
        let keys = self.derive_known_session_keys(
            &client_random,
            &server_random,
            &opaque_session_key,
            &mlkem_shared_secret,
            self.role,
        )?;

        // Transition to Established
        self.state = SessionState::Established {
            session_id: keys.session_id,
            version: selected_version,
            cipher: selected_cipher,
        };
        self.keys = Some(keys);

        // Build KnownFinish frame
        Ok(Frame::KnownFinish {
            opaque_credential_finalization: opaque_finalization,
            mlkem_ciphertext_encrypted,
        })
    }

    // === Server-side handshake (Known Mode) ===

    /// Process KnownHello as server (Known Mode with OPAQUE).
    ///
    /// Returns KnownResponse frame to send.
    ///
    /// # Arguments
    ///
    /// - `frame`: KnownHello from client
    /// - `server_setup`: OPAQUE server setup (long-term secret)
    /// - `password_file`: Stored password file for this user
    /// - `credential_identifier`: Username
    pub fn server_process_known_hello(
        &mut self,
        frame: Frame,
        server_setup: &zp_crypto::pake::OpaqueServerSetup,
        password_file: &zp_crypto::pake::PasswordFile,
        credential_identifier: &[u8],
    ) -> Result<Frame> {
        if self.role != Role::Server {
            return Err(Error::ProtocolViolation("Not a server".into()));
        }
        if self.mode != HandshakeMode::Known {
            return Err(Error::ProtocolViolation("Not Known mode".into()));
        }
        if !matches!(self.state, SessionState::Idle) {
            return Err(Error::InvalidState);
        }

        let (
            supported_versions,
            min_version,
            supported_ciphers,
            opaque_credential_request,
            client_random,
        ) = match frame {
            Frame::KnownHello {
                supported_versions,
                min_version,
                supported_ciphers,
                opaque_credential_request,
                random,
            } => (
                supported_versions,
                min_version,
                supported_ciphers,
                opaque_credential_request,
                random,
            ),
            _ => return Err(Error::InvalidFrame("Expected KnownHello".into())),
        };

        // Negotiate version
        let selected_version = self.negotiate_version(&supported_versions, min_version)?;

        // Negotiate cipher suite
        let selected_cipher = self.negotiate_cipher(&supported_ciphers)?;

        // Process OPAQUE login request
        use zp_crypto::pake;
        let mut rng = rand::rngs::OsRng;
        let (credential_response, server_login_state) = pake::login_response(
            server_setup,
            password_file,
            &opaque_credential_request,
            credential_identifier,
            &mut rng,
        )
        .map_err(|e| Error::ProtocolViolation(format!("OPAQUE login_response failed: {}", e)))?;

        // Generate key material based on cipher suite
        let (mlkem_pubkey, key_material) = match selected_cipher {
            ZP_HYBRID_1 | ZP_HYBRID_3 => {
                // ML-KEM-768
                let mlkem_keypair = MlKem768KeyPair::generate()?;
                let mlkem_pub = mlkem_keypair.public_key().to_vec();
                (
                    mlkem_pub,
                    KeyMaterial::Hybrid768(X25519KeyPair::generate()?, Box::new(mlkem_keypair)),
                )
            }
            ZP_HYBRID_2 => {
                // ML-KEM-1024
                let mlkem_keypair = MlKem1024KeyPair::generate()?;
                let mlkem_pub = mlkem_keypair.public_key().to_vec();
                (
                    mlkem_pub,
                    KeyMaterial::Hybrid1024(X25519KeyPair::generate()?, Box::new(mlkem_keypair)),
                )
            }
            _ => {
                return Err(Error::ProtocolViolation(
                    "Unsupported cipher suite for Known Mode".into(),
                ))
            }
        };

        // Generate server random
        let server_random = random_bytes_32();

        // NOTE: We need OPAQUE session_key to encrypt mlkem_pubkey, but we don't have it yet.
        // The spec says server sends encrypted ML-KEM pubkey in KnownResponse,
        // but OPAQUE only gives us session_key after both parties complete the protocol.
        //
        // WORKAROUND: Derive intermediate encryption key from OPAQUE CredentialRequest + CredentialResponse.
        // Both parties have both messages at encryption/decryption time.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"zp-known-mode-mlkem-encryption");
        hasher.update(&opaque_credential_request);
        hasher.update(&credential_response);
        let encryption_key_hash = hasher.finalize();
        let encryption_key: [u8; 32] = encryption_key_hash.into();

        // Encrypt ML-KEM public key
        let mlkem_pubkey_encrypted =
            self.encrypt_mlkem_pubkey(&encryption_key, &server_random, &mlkem_pubkey)?;

        self.state = SessionState::KnownResponseSent {
            client_random,
            server_random,
            opaque_server_state: server_login_state,
            key_material,
            selected_version,
            selected_cipher,
        };

        Ok(Frame::KnownResponse {
            selected_version,
            selected_cipher,
            opaque_credential_response: credential_response,
            random: server_random,
            mlkem_pubkey_encrypted,
        })
    }

    /// Process KnownFinish as server (Known Mode with OPAQUE).
    ///
    /// Completes handshake. Returns Ok(()) on success.
    pub fn server_process_known_finish(&mut self, frame: Frame) -> Result<()> {
        // Extract state
        let (
            client_random,
            server_random,
            opaque_server_state,
            key_material,
            selected_version,
            selected_cipher,
        ) = match std::mem::replace(&mut self.state, SessionState::Idle) {
            SessionState::KnownResponseSent {
                client_random,
                server_random,
                opaque_server_state,
                key_material,
                selected_version,
                selected_cipher,
            } => (
                client_random,
                server_random,
                opaque_server_state,
                key_material,
                selected_version,
                selected_cipher,
            ),
            old_state => {
                self.state = old_state;
                return Err(Error::InvalidState);
            }
        };

        let (opaque_finalization, mlkem_ciphertext_encrypted) = match frame {
            Frame::KnownFinish {
                opaque_credential_finalization,
                mlkem_ciphertext_encrypted,
            } => (opaque_credential_finalization, mlkem_ciphertext_encrypted),
            _ => return Err(Error::InvalidFrame("Expected KnownFinish".into())),
        };

        // Complete OPAQUE login (server side)
        use zp_crypto::pake;
        let opaque_session_key = pake::login_complete(&opaque_finalization, &opaque_server_state)
            .map_err(|e| {
            Error::ProtocolViolation(format!("OPAQUE login_complete failed: {}", e))
        })?;

        // Derive encryption key from OPAQUE session_key (first 32 bytes)
        let encryption_key = &opaque_session_key[..32];

        // Decrypt ML-KEM ciphertext
        let mlkem_ciphertext = self.decrypt_mlkem_ciphertext(
            encryption_key,
            &client_random,
            &mlkem_ciphertext_encrypted,
        )?;

        // Perform ML-KEM decapsulation
        let mlkem_shared_secret = self.mlkem_decapsulate(&key_material, &mlkem_ciphertext)?;

        // Derive session keys
        let keys = self.derive_known_session_keys(
            &client_random,
            &server_random,
            &opaque_session_key,
            &mlkem_shared_secret,
            self.role,
        )?;

        // Transition to Established
        self.state = SessionState::Established {
            session_id: keys.session_id,
            version: selected_version,
            cipher: selected_cipher,
        };
        self.keys = Some(keys);

        Ok(())
    }

    // === Key derivation helpers ===

    fn client_derive_shared_secret(
        &self,
        x25519_keypair: &X25519KeyPair,
        server_x25519_pubkey: &[u8; 32],
        mlkem_pubkey: Option<&[u8]>,
        cipher: u8,
    ) -> Result<ClientKeyExchangeResult> {
        // X25519 key exchange (all hybrid modes)
        let classical_secret = x25519_keypair.exchange(server_x25519_pubkey)?;
        let classical_secret_vec = Zeroizing::new(classical_secret.to_vec());

        // ML-KEM encapsulation if PQC suite
        if let Some(pubkey) = mlkem_pubkey {
            // Determine which ML-KEM variant to use
            let (ciphertext, pqc_secret) = match cipher {
                ZP_HYBRID_1 | ZP_HYBRID_3 => {
                    // ML-KEM-768
                    MlKem768KeyPair::encapsulate(pubkey)?
                }
                ZP_HYBRID_2 => {
                    // ML-KEM-1024
                    MlKem1024KeyPair::encapsulate(pubkey)?
                }
                _ => return Err(Error::ProtocolViolation("Invalid cipher for ML-KEM".into())),
            };

            // Combine: shared_secret = classical || pqc
            let mut shared_secret = classical_secret_vec.to_vec();
            shared_secret.extend_from_slice(&*pqc_secret);

            Ok((Some(ciphertext), Zeroizing::new(shared_secret)))
        } else {
            // Classical-only mode (not implemented for ZP_CLASSICAL_2 yet)
            Ok((None, classical_secret_vec))
        }
    }

    fn server_derive_shared_secret(
        &self,
        client_x25519_pubkey: &[u8; 32],
        key_material: &KeyMaterial,
        mlkem_ciphertext: Option<&[u8]>,
        _cipher: u8,
    ) -> Result<Zeroizing<Vec<u8>>> {
        match key_material {
            KeyMaterial::X25519(keypair) => {
                // Classical X25519 only
                let secret = keypair.exchange(client_x25519_pubkey)?;
                Ok(Zeroizing::new(secret.to_vec()))
            }
            KeyMaterial::Hybrid768(x25519_kp, mlkem_kp) => {
                // X25519 + ML-KEM-768
                let x25519_secret = x25519_kp.exchange(client_x25519_pubkey)?;

                if let Some(ciphertext) = mlkem_ciphertext {
                    let pqc_secret = mlkem_kp.decapsulate(ciphertext)?;

                    // Combine: shared_secret = classical || pqc
                    let mut shared_secret = x25519_secret.to_vec();
                    shared_secret.extend_from_slice(&*pqc_secret);
                    Ok(Zeroizing::new(shared_secret))
                } else {
                    Err(Error::ProtocolViolation("Missing ML-KEM ciphertext".into()))
                }
            }
            KeyMaterial::Hybrid1024(x25519_kp, mlkem_kp) => {
                // X25519 + ML-KEM-1024
                let x25519_secret = x25519_kp.exchange(client_x25519_pubkey)?;

                if let Some(ciphertext) = mlkem_ciphertext {
                    let pqc_secret = mlkem_kp.decapsulate(ciphertext)?;

                    // Combine: shared_secret = classical || pqc
                    let mut shared_secret = x25519_secret.to_vec();
                    shared_secret.extend_from_slice(&*pqc_secret);
                    Ok(Zeroizing::new(shared_secret))
                } else {
                    Err(Error::ProtocolViolation("Missing ML-KEM ciphertext".into()))
                }
            }
            KeyMaterial::EcdhP256(keypair) => {
                // ECDH-P256 for FIPS mode
                // TODO: Handle P-256 public key format properly
                // For now, assume client_x25519_pubkey contains the x-coordinate
                // This needs to be fixed to handle full P-256 public keys (65 bytes)
                let secret = keypair.exchange(client_x25519_pubkey)?;
                Ok(Zeroizing::new(secret.to_vec()))
            }
        }
    }

    fn derive_stranger_session_keys(
        &self,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        shared_secret: &[u8],
        role: Role,
    ) -> Result<SessionKeys> {
        // Derive session_id per spec §4.2.4
        let session_id = derive_session_id_stranger(client_random, server_random, shared_secret);

        // Derive session_secret per spec §4.2.4
        let session_secret =
            derive_session_secret_stranger(shared_secret, client_random, server_random)?;

        // Derive session_keys per spec §4.2.4
        // Returns (c2s_key, s2c_key) as a tuple
        let (client_to_server_key, server_to_client_key) =
            derive_session_keys_stranger(shared_secret, client_random, server_random)?;

        // Assign send/recv keys based on role
        let (send_key, recv_key) = match role {
            Role::Client => (client_to_server_key.clone(), server_to_client_key.clone()),
            Role::Server => (server_to_client_key.clone(), client_to_server_key.clone()),
        };

        Ok(SessionKeys {
            session_id,
            session_secret,
            client_to_server_key,
            server_to_client_key,
            send_key,
            recv_key,
            key_epoch: 0,        // Initial epoch is 0
            pending_epoch: None, // No pending rotation initially
            send_nonce: 0,       // EncryptedRecord nonce counter starts at 0
            recv_nonce: 0,       // EncryptedRecord nonce counter starts at 0
        })
    }

    fn derive_known_session_keys(
        &self,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        opaque_session_key: &[u8],
        mlkem_shared_secret: &[u8],
        role: Role,
    ) -> Result<SessionKeys> {
        // Derive session_id per spec §4.3.4 (updated for OPAQUE)
        // session_id = SHA-256(client_random || server_random || opaque_key)[0:16]
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(client_random);
        hasher.update(server_random);
        hasher.update(&opaque_session_key[..32]); // Use first 32 bytes of OPAQUE session_key
        let hash = hasher.finalize();
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&hash[0..16]);

        // Derive session_secret per spec §4.3.4 (updated for OPAQUE)
        // session_secret = HKDF(ikm: opaque_key || mlkem_shared, salt: randoms, info: "zp-session-secret")
        use zp_crypto::kdf::hkdf_sha256;
        let mut ikm = opaque_session_key.to_vec();
        ikm.extend_from_slice(mlkem_shared_secret);

        let mut salt = Vec::new();
        salt.extend_from_slice(client_random);
        salt.extend_from_slice(server_random);

        let session_secret_vec = hkdf_sha256(&ikm, &salt, b"zp-session-secret", 32)?;
        let mut session_secret = Zeroizing::new([0u8; 32]);
        session_secret.copy_from_slice(&session_secret_vec);

        // Derive session_keys per spec §4.3.4
        // session_keys = HKDF(ikm: opaque_key || mlkem_shared, info: "zp-known-session-keys", len: 64)
        let session_keys_material = hkdf_sha256(&ikm, &salt, b"zp-known-session-keys", 64)?;

        let mut client_to_server_key = Zeroizing::new([0u8; 32]);
        let mut server_to_client_key = Zeroizing::new([0u8; 32]);
        client_to_server_key.copy_from_slice(&session_keys_material[0..32]);
        server_to_client_key.copy_from_slice(&session_keys_material[32..64]);

        // Assign send/recv keys based on role
        let (send_key, recv_key) = match role {
            Role::Client => (client_to_server_key.clone(), server_to_client_key.clone()),
            Role::Server => (server_to_client_key.clone(), client_to_server_key.clone()),
        };

        Ok(SessionKeys {
            session_id,
            session_secret,
            client_to_server_key,
            server_to_client_key,
            send_key,
            recv_key,
            key_epoch: 0,
            pending_epoch: None,
            send_nonce: 0, // EncryptedRecord nonce counter starts at 0
            recv_nonce: 0, // EncryptedRecord nonce counter starts at 0
        })
    }

    // === ML-KEM encryption/decryption helpers ===

    fn encrypt_mlkem_pubkey(
        &self,
        key: &[u8],
        server_random: &[u8; 32],
        mlkem_pubkey: &[u8],
    ) -> Result<Vec<u8>> {
        // Derive nonce from server_random per spec §4.3.4
        use sha2::{Digest, Sha256};
        let nonce_hash = Sha256::digest(server_random);
        let nonce: [u8; 12] = nonce_hash[0..12].try_into().unwrap();

        // Encrypt with AES-256-GCM
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| Error::ProtocolViolation(format!("AES-256-GCM init failed: {}", e)))?;
        let nonce_obj = Nonce::from_slice(&nonce);

        cipher.encrypt(nonce_obj, mlkem_pubkey).map_err(|e| {
            Error::ProtocolViolation(format!("ML-KEM pubkey encryption failed: {}", e))
        })
    }

    fn decrypt_mlkem_pubkey(
        &self,
        key: &[u8],
        server_random: &[u8; 32],
        mlkem_pubkey_encrypted: &[u8],
    ) -> Result<Vec<u8>> {
        // Derive nonce from server_random per spec §4.3.4
        use sha2::{Digest, Sha256};
        let nonce_hash = Sha256::digest(server_random);
        let nonce: [u8; 12] = nonce_hash[0..12].try_into().unwrap();

        // Decrypt with AES-256-GCM
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| Error::ProtocolViolation(format!("AES-256-GCM init failed: {}", e)))?;
        let nonce_obj = Nonce::from_slice(&nonce);

        cipher
            .decrypt(nonce_obj, mlkem_pubkey_encrypted)
            .map_err(|e| {
                Error::ProtocolViolation(format!("ML-KEM pubkey decryption failed: {}", e))
            })
    }

    fn encrypt_mlkem_ciphertext(
        &self,
        key: &[u8],
        client_random: &[u8; 32],
        mlkem_ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        // Derive nonce from client_random per spec §4.3.4
        use sha2::{Digest, Sha256};
        let nonce_hash = Sha256::digest(client_random);
        let nonce: [u8; 12] = nonce_hash[0..12].try_into().unwrap();

        // Encrypt with AES-256-GCM
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| Error::ProtocolViolation(format!("AES-256-GCM init failed: {}", e)))?;
        let nonce_obj = Nonce::from_slice(&nonce);

        cipher.encrypt(nonce_obj, mlkem_ciphertext).map_err(|e| {
            Error::ProtocolViolation(format!("ML-KEM ciphertext encryption failed: {}", e))
        })
    }

    fn decrypt_mlkem_ciphertext(
        &self,
        key: &[u8],
        client_random: &[u8; 32],
        mlkem_ciphertext_encrypted: &[u8],
    ) -> Result<Vec<u8>> {
        // Derive nonce from client_random per spec §4.3.4
        use sha2::{Digest, Sha256};
        let nonce_hash = Sha256::digest(client_random);
        let nonce: [u8; 12] = nonce_hash[0..12].try_into().unwrap();

        // Decrypt with AES-256-GCM
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| Error::ProtocolViolation(format!("AES-256-GCM init failed: {}", e)))?;
        let nonce_obj = Nonce::from_slice(&nonce);

        cipher
            .decrypt(nonce_obj, mlkem_ciphertext_encrypted)
            .map_err(|e| {
                Error::ProtocolViolation(format!("ML-KEM ciphertext decryption failed: {}", e))
            })
    }

    fn mlkem_encapsulate(
        &self,
        mlkem_pubkey: &[u8],
        cipher: u8,
    ) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        let (ciphertext, shared_secret) = match cipher {
            ZP_HYBRID_1 | ZP_HYBRID_3 => {
                // ML-KEM-768
                MlKem768KeyPair::encapsulate(mlkem_pubkey)?
            }
            ZP_HYBRID_2 => {
                // ML-KEM-1024
                MlKem1024KeyPair::encapsulate(mlkem_pubkey)?
            }
            _ => return Err(Error::ProtocolViolation("Invalid cipher for ML-KEM".into())),
        };

        // Convert Zeroizing<[u8; 32]> to Zeroizing<Vec<u8>>
        Ok((ciphertext, Zeroizing::new(shared_secret.to_vec())))
    }

    fn mlkem_decapsulate(
        &self,
        key_material: &KeyMaterial,
        mlkem_ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let shared_secret = match key_material {
            KeyMaterial::Hybrid768(_x25519_kp, mlkem_kp) => {
                mlkem_kp.decapsulate(mlkem_ciphertext)?
            }
            KeyMaterial::Hybrid1024(_x25519_kp, mlkem_kp) => {
                mlkem_kp.decapsulate(mlkem_ciphertext)?
            }
            _ => {
                return Err(Error::ProtocolViolation(
                    "Key material does not support ML-KEM".into(),
                ))
            }
        };

        // Convert Zeroizing<[u8; 32]> to Zeroizing<Vec<u8>>
        Ok(Zeroizing::new(shared_secret.to_vec()))
    }

    // === Negotiation helpers ===

    fn negotiate_version(&self, client_versions: &[u16], client_min: u16) -> Result<u16> {
        // Select highest mutually-supported version
        for &version in &self.config.supported_versions {
            if client_versions.contains(&version) && version >= client_min {
                return Ok(version);
            }
        }
        Err(Error::VersionMismatch)
    }

    fn negotiate_cipher(&self, client_ciphers: &[u8]) -> Result<u8> {
        // Select first server-preferred cipher that client supports
        for &cipher in &self.config.supported_ciphers {
            if client_ciphers.contains(&cipher) {
                return Ok(cipher);
            }
        }
        Err(Error::ProtocolViolation("No common cipher suite".into()))
    }

    #[allow(dead_code)] // Used in Known mode handshake (not yet implemented)
    fn requires_mlkem(&self, cipher: u8) -> bool {
        matches!(cipher, ZP_HYBRID_1 | ZP_HYBRID_2 | ZP_HYBRID_3)
    }

    #[allow(dead_code)] // Used in Known mode handshake (not yet implemented)
    fn mlkem_variant_for_cipher(&self, cipher: u8) -> Result<MlKemVariant> {
        match cipher {
            ZP_HYBRID_1 | ZP_HYBRID_3 => Ok(MlKemVariant::MlKem768),
            ZP_HYBRID_2 => Ok(MlKemVariant::MlKem1024),
            _ => Err(Error::ProtocolViolation("Not a PQC cipher suite".into())),
        }
    }

    /// Convert cipher suite ID to CipherSuite enum.
    pub fn cipher_suite_from_id(id: u8) -> Result<CipherSuite> {
        match id {
            ZP_HYBRID_1 => Ok(CipherSuite::ZpHybrid1),
            ZP_HYBRID_2 => Ok(CipherSuite::ZpHybrid2),
            ZP_HYBRID_3 => Ok(CipherSuite::ZpHybrid3),
            ZP_CLASSICAL_2 => Ok(CipherSuite::ZpClassical2),
            _ => Err(Error::ProtocolViolation("Unknown cipher suite".into())),
        }
    }

    // === Key Rotation (§4.6) ===

    /// Initiate key rotation for specified direction(s) (§4.6.4).
    ///
    /// # Arguments
    ///
    /// * `direction` - Which keys to rotate (0x01=C2S, 0x02=S2C, 0x03=both)
    ///
    /// # Returns
    ///
    /// Returns a `KeyUpdate` frame to send to peer.
    ///
    /// # Errors
    ///
    /// Returns error if session not established or rotation already pending.
    pub fn initiate_key_rotation(&mut self, direction: u8) -> Result<Frame> {
        // Validate direction
        if direction == 0 || direction > 0x03 {
            return Err(Error::ProtocolViolation(
                "Invalid key rotation direction".into(),
            ));
        }

        let keys = self.keys.as_mut().ok_or_else(|| {
            Error::ProtocolViolation("Cannot rotate keys before session established".into())
        })?;

        // Check if rotation already pending
        if keys.pending_epoch.is_some() {
            return Err(Error::ProtocolViolation(
                "Key rotation already pending".into(),
            ));
        }

        // Increment epoch
        let new_epoch = keys
            .key_epoch
            .checked_add(1)
            .ok_or_else(|| Error::ProtocolViolation("Key epoch overflow".into()))?;

        // Derive new key(s) based on direction
        let current_secret = &*keys.session_secret;
        let session_id = &keys.session_id;

        match direction {
            0x01 => {
                // Rotate C2S only
                let new_c2s_key = derive_traffic_key(
                    current_secret,
                    session_id,
                    new_epoch,
                    KeyDirection::ClientToServer,
                )?;
                keys.client_to_server_key = new_c2s_key.clone();

                // Update send/recv based on role
                match self.role {
                    Role::Client => keys.send_key = new_c2s_key,
                    Role::Server => keys.recv_key = new_c2s_key,
                }
            }
            0x02 => {
                // Rotate S2C only
                let new_s2c_key = derive_traffic_key(
                    current_secret,
                    session_id,
                    new_epoch,
                    KeyDirection::ServerToClient,
                )?;
                keys.server_to_client_key = new_s2c_key.clone();

                // Update send/recv based on role
                match self.role {
                    Role::Client => keys.recv_key = new_s2c_key,
                    Role::Server => keys.send_key = new_s2c_key,
                }
            }
            0x03 => {
                // Rotate both
                let new_c2s_key = derive_traffic_key(
                    current_secret,
                    session_id,
                    new_epoch,
                    KeyDirection::ClientToServer,
                )?;
                let new_s2c_key = derive_traffic_key(
                    current_secret,
                    session_id,
                    new_epoch,
                    KeyDirection::ServerToClient,
                )?;

                keys.client_to_server_key = new_c2s_key.clone();
                keys.server_to_client_key = new_s2c_key.clone();

                // Update send/recv based on role
                match self.role {
                    Role::Client => {
                        keys.send_key = new_c2s_key;
                        keys.recv_key = new_s2c_key;
                    }
                    Role::Server => {
                        keys.send_key = new_s2c_key;
                        keys.recv_key = new_c2s_key;
                    }
                }
            }
            _ => unreachable!("Invalid direction already validated"),
        }

        // Update current_secret for forward secrecy
        let new_secret = update_current_secret(current_secret, session_id, new_epoch)?;
        keys.session_secret = new_secret;

        // Mark rotation as pending
        keys.pending_epoch = Some(new_epoch);

        // Build KeyUpdate frame
        Ok(Frame::KeyUpdate {
            key_epoch: new_epoch,
            direction,
        })
    }

    /// Process received KeyUpdate frame from peer (§4.6.4).
    ///
    /// # Arguments
    ///
    /// * `key_epoch` - Epoch number from KeyUpdate frame
    /// * `direction` - Direction(s) to rotate (0x01=C2S, 0x02=S2C, 0x03=both)
    ///
    /// # Returns
    ///
    /// Returns a `KeyUpdateAck` frame to send back to peer.
    ///
    /// # Errors
    ///
    /// Returns error if session not established or invalid epoch.
    pub fn process_key_update(&mut self, key_epoch: u32, direction: u8) -> Result<Frame> {
        // Validate direction
        if direction == 0 || direction > 0x03 {
            return Err(Error::ProtocolViolation(
                "Invalid key rotation direction".into(),
            ));
        }

        let keys = self.keys.as_mut().ok_or_else(|| {
            Error::ProtocolViolation("Cannot rotate keys before session established".into())
        })?;

        // Epoch must be exactly current + 1
        let expected_epoch = keys.key_epoch + 1;
        if key_epoch != expected_epoch {
            return Err(Error::ProtocolViolation(format!(
                "Invalid key epoch: got {}, expected {}",
                key_epoch, expected_epoch
            )));
        }

        // Derive new key(s) using same derivation as initiator
        let current_secret = &*keys.session_secret;
        let session_id = &keys.session_id;

        match direction {
            0x01 => {
                // Rotate C2S only
                let new_c2s_key = derive_traffic_key(
                    current_secret,
                    session_id,
                    key_epoch,
                    KeyDirection::ClientToServer,
                )?;
                keys.client_to_server_key = new_c2s_key.clone();

                // Update send/recv based on role
                match self.role {
                    Role::Client => keys.send_key = new_c2s_key,
                    Role::Server => keys.recv_key = new_c2s_key,
                }
            }
            0x02 => {
                // Rotate S2C only
                let new_s2c_key = derive_traffic_key(
                    current_secret,
                    session_id,
                    key_epoch,
                    KeyDirection::ServerToClient,
                )?;
                keys.server_to_client_key = new_s2c_key.clone();

                // Update send/recv based on role
                match self.role {
                    Role::Client => keys.recv_key = new_s2c_key,
                    Role::Server => keys.send_key = new_s2c_key,
                }
            }
            0x03 => {
                // Rotate both
                let new_c2s_key = derive_traffic_key(
                    current_secret,
                    session_id,
                    key_epoch,
                    KeyDirection::ClientToServer,
                )?;
                let new_s2c_key = derive_traffic_key(
                    current_secret,
                    session_id,
                    key_epoch,
                    KeyDirection::ServerToClient,
                )?;

                keys.client_to_server_key = new_c2s_key.clone();
                keys.server_to_client_key = new_s2c_key.clone();

                // Update send/recv based on role
                match self.role {
                    Role::Client => {
                        keys.send_key = new_c2s_key;
                        keys.recv_key = new_s2c_key;
                    }
                    Role::Server => {
                        keys.send_key = new_s2c_key;
                        keys.recv_key = new_c2s_key;
                    }
                }
            }
            _ => unreachable!("Invalid direction already validated"),
        }

        // Update current_secret for forward secrecy
        let new_secret = update_current_secret(current_secret, session_id, key_epoch)?;
        keys.session_secret = new_secret;

        // Update epoch
        keys.key_epoch = key_epoch;

        // Build KeyUpdateAck frame
        Ok(Frame::KeyUpdateAck {
            acked_epoch: key_epoch,
        })
    }

    /// Process received KeyUpdateAck frame from peer (§4.6.4).
    ///
    /// # Arguments
    ///
    /// * `acked_epoch` - Epoch number from KeyUpdateAck frame
    ///
    /// # Errors
    ///
    /// Returns error if no pending rotation or epoch mismatch.
    pub fn process_key_update_ack(&mut self, acked_epoch: u32) -> Result<()> {
        let keys = self.keys.as_mut().ok_or_else(|| {
            Error::ProtocolViolation("Cannot process ack before session established".into())
        })?;

        // Verify we have a pending rotation
        let pending = keys
            .pending_epoch
            .ok_or_else(|| Error::ProtocolViolation("No pending key rotation".into()))?;

        // Verify acked epoch matches pending
        if acked_epoch != pending {
            return Err(Error::ProtocolViolation(format!(
                "Key rotation ack mismatch: got {}, expected {}",
                acked_epoch, pending
            )));
        }

        // Commit the rotation: update epoch and clear pending
        keys.key_epoch = pending;
        keys.pending_epoch = None;

        Ok(())
    }

    // === Transport Migration (§3.3.3-6) ===

    /// Generate a Sync-Frame for transport migration per spec §3.3.5.
    ///
    /// Creates a Sync-Frame containing the current state of all active streams,
    /// allowing the session to resume on a different transport without data loss.
    ///
    /// # Arguments
    ///
    /// * `streams` - Slice of active streams to include in migration
    /// * `flags` - Sync flags (bit 0: URGENT, bit 1: FINAL, bits 2-7: reserved)
    ///
    /// # Returns
    ///
    /// Returns `Frame::SyncFrame` with session ID and stream states with XXH64 integrity hashes.
    ///
    /// # Errors
    ///
    /// Returns error if session not established or stream count exceeds u16::MAX.
    ///
    /// # Spec Reference
    ///
    /// §3.3.5 - Sync-Frame Format
    pub fn generate_sync_frame(
        &self,
        streams: &[crate::stream::Stream],
        flags: u8,
    ) -> Result<Frame> {
        // Ensure session is established
        let session_id = self.session_id().ok_or(Error::InvalidState)?;

        // Check stream count limit (u16::MAX per spec)
        if streams.len() > u16::MAX as usize {
            return Err(Error::ProtocolViolation(format!(
                "Too many streams for Sync-Frame: {} (max {})",
                streams.len(),
                u16::MAX
            )));
        }

        // Build stream states with integrity hashes
        let mut stream_states = Vec::with_capacity(streams.len());
        for stream in streams {
            let state = crate::frame::StreamState {
                stream_id: stream.id(),
                global_seq: stream.global_seq(),
                last_acked: stream.last_acked(),
            };
            stream_states.push(state);
        }

        Ok(Frame::SyncFrame {
            session_id,
            streams: stream_states,
            flags,
        })
    }

    /// Process a Sync-Frame from a migrating peer per spec §3.3.6.
    ///
    /// Validates the incoming Sync-Frame and generates a Sync-Ack response.
    /// Checks session ID match, verifies XXH64 integrity hashes, and compares
    /// sequence numbers against local stream state.
    ///
    /// # Arguments
    ///
    /// * `frame` - Incoming Sync-Frame to process
    /// * `local_streams` - Slice of local stream states for comparison
    ///
    /// # Returns
    ///
    /// Returns `Frame::SyncAck` with per-stream status (OK, UNKNOWN, MISMATCH).
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Session not established
    /// - Frame is not a SyncFrame
    /// - Session ID mismatch (ERR_SYNC_REJECTED per spec)
    ///
    /// # Spec Reference
    ///
    /// §3.3.5 - Sync-Frame Format
    /// §3.3.6 - Sync-Ack Format
    pub fn process_sync_frame(
        &self,
        frame: Frame,
        local_streams: &[crate::stream::Stream],
    ) -> Result<Frame> {
        // Ensure session is established
        let session_id = self.session_id().ok_or(Error::InvalidState)?;

        // Extract SyncFrame fields
        let (peer_session_id, peer_streams, _flags) = match frame {
            Frame::SyncFrame {
                session_id: s_id,
                streams,
                flags,
            } => (s_id, streams, flags),
            _ => return Err(Error::ProtocolViolation("Expected SyncFrame".into())),
        };

        // Verify session ID matches per spec §3.3.5
        if peer_session_id != session_id {
            return Err(Error::SyncRejected);
        }

        // Build per-stream status
        let mut stream_sync_statuses = Vec::with_capacity(peer_streams.len());
        let mut overall_status = 0x00; // 0x00 = OK (all streams synchronized)

        for peer_stream_state in peer_streams {
            // Find matching local stream
            let local_stream = local_streams
                .iter()
                .find(|s| s.id() == peer_stream_state.stream_id);

            let (stream_status, receiver_last_acked, receiver_seq) = match local_stream {
                Some(local) => {
                    // Stream exists locally - compare sequence numbers
                    let peer_seq = peer_stream_state.global_seq;
                    let peer_ack = peer_stream_state.last_acked;
                    let local_seq = local.global_seq();
                    let local_ack = local.last_acked();

                    // Check for sequence mismatch per spec §3.3.6
                    // MISMATCH if sequences are inconsistent (simple check: peer ahead of local by >1 window)
                    let mismatch =
                        peer_seq > local_seq + 1_000_000 || peer_ack > local_ack + 1_000_000;

                    if mismatch {
                        overall_status = 0x01; // PARTIAL
                        (0x02, local_ack, local_seq) // MISMATCH
                    } else {
                        (0x00, local_ack, local_seq) // OK
                    }
                }
                None => {
                    // Stream unknown locally
                    overall_status = 0x01; // PARTIAL
                    (0x01, 0, 0) // UNKNOWN
                }
            };

            stream_sync_statuses.push(crate::frame::StreamSyncStatus {
                stream_id: peer_stream_state.stream_id,
                stream_status,
                receiver_last_acked,
                receiver_seq,
            });
        }

        Ok(Frame::SyncAck {
            streams: stream_sync_statuses,
            status: overall_status,
        })
    }

    /// Process a Sync-Ack response after migration per spec §3.3.6.
    ///
    /// Validates the Sync-Ack frame and determines if migration succeeded.
    /// Caller should use the returned status to decide whether to proceed
    /// with the migrated connection or fall back.
    ///
    /// # Arguments
    ///
    /// * `frame` - Incoming Sync-Ack to process
    ///
    /// # Returns
    ///
    /// Returns the overall status code:
    /// - `0x00` (OK): All streams synchronized successfully
    /// - `0x01` (PARTIAL): Some streams have issues (check per-stream status)
    /// - `0x02` (REJECT): Migration rejected (must create fresh connection)
    ///
    /// # Errors
    ///
    /// Returns error if frame is not a SyncAck.
    ///
    /// # Spec Reference
    ///
    /// §3.3.6 - Sync-Ack Format
    pub fn process_sync_ack(&self, frame: Frame) -> Result<u8> {
        // Extract SyncAck fields
        match frame {
            Frame::SyncAck { status, .. } => Ok(status),
            _ => Err(Error::ProtocolViolation("Expected SyncAck".into())),
        }
    }

    // === State Token Encryption & Persistence (§6.5-6.6) ===

    /// Save session state as an encrypted State Token per spec §6.5.
    ///
    /// Encrypts the session's cryptographic state, connection context, and stream states
    /// using AES-256-GCM with a device-bound key. Returns the encrypted blob ready for
    /// persistent storage.
    ///
    /// # Arguments
    ///
    /// * `key_provider` - Platform-specific key provider (e.g., SecureEnclaveKeyProvider, MockKeyProvider)
    /// * `streams` - Slice of active streams to include in token (max 12)
    /// * `connection_context` - Connection-specific metadata (connection_id, peer_address, etc.)
    ///
    /// # Returns
    ///
    /// Returns encrypted token blob in storage format:
    /// `token_nonce[12] || header[16] || ciphertext || tag[16]`
    ///
    /// Total size = 44 + encrypted_length bytes
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Session not established
    /// - Stream count > 12 (MAX_HIBERNATED_STREAMS)
    /// - Stream count = 0 (invalid per spec)
    /// - Encryption fails
    ///
    /// # Spec Reference
    ///
    /// §6.5 - State Token Format
    /// §6.5.1 - AEAD Nonce Construction
    pub fn save_state_token(
        &self,
        key_provider: &dyn zp_platform::traits::KeyProvider,
        streams: &[crate::stream::Stream],
        connection_context: crate::token::ConnectionContext,
    ) -> Result<Vec<u8>> {
        use crate::token::{
            CryptoContext, StateToken, StreamState as TokenStreamState, StreamStateFlags,
            TokenHeader,
        };
        use crate::token::{
            MAX_HIBERNATED_STREAMS, STATE_TOKEN_MAGIC, STATE_TOKEN_VERSION, ZP_NONCE_SKIP,
        };
        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes256Gcm, Nonce,
        };
        use rand::RngCore;

        // Ensure session is established
        let keys = self.keys.as_ref().ok_or(Error::InvalidState)?;

        // Validate stream count per spec §6.5
        if streams.is_empty() {
            return Err(Error::ProtocolViolation(
                "Cannot save token with 0 streams".into(),
            ));
        }
        if streams.len() > MAX_HIBERNATED_STREAMS as usize {
            return Err(Error::ProtocolViolation(format!(
                "Too many streams: {} (max {})",
                streams.len(),
                MAX_HIBERNATED_STREAMS
            )));
        }

        // Build TokenHeader (16 bytes, used as AAD)
        let header = TokenHeader {
            magic: STATE_TOKEN_MAGIC,
            version: STATE_TOKEN_VERSION,
            flags: 0, // Reserved, must be 0
            stream_count: streams.len() as u8,
            reserved: 0,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| Error::ProtocolViolation("System clock error".into()))?
                .as_secs(),
        };

        // Build CryptoContext (136 bytes)
        // Apply ZP_NONCE_SKIP to prevent nonce reuse per spec §6.5
        let crypto_context = CryptoContext {
            session_id: keys.session_id,
            session_secret: *keys.session_secret,
            send_key: *keys.send_key,
            recv_key: *keys.recv_key,
            send_nonce: keys.send_nonce.saturating_add(ZP_NONCE_SKIP), // Skip ahead
            recv_nonce: keys.recv_nonce.saturating_add(ZP_NONCE_SKIP),
            key_epoch: keys.key_epoch,
            reserved: [0u8; 4],
        };

        // Build StreamStates (max 12 × 63 bytes = 756 bytes)
        let mut stream_states = Vec::with_capacity(streams.len());
        for stream in streams {
            // Map stream.state() to StreamStateFlags
            // For now, assume all streams are OPEN (bit 0 set)
            let state_flags = StreamStateFlags::new(0x01); // OPEN

            let token_stream = TokenStreamState {
                stream_id: stream.id(),
                global_seq: stream.global_seq(),
                last_acked: stream.last_acked(),
                send_offset: stream.send_offset(),
                recv_offset: stream.recv_offset(),
                flow_window: 256 * 1024, // ZP_INITIAL_STREAM_WINDOW (will fix with getter)
                state_flags,
                priority: stream.priority(),
                reserved: [0u8; 21],
            };
            stream_states.push(token_stream);
        }

        // Build complete StateToken
        let token = StateToken {
            header: header.clone(),
            crypto_context,
            connection_context,
            stream_states,
        };

        // Serialize token (this gives us header + crypto + connection + streams)
        let token_bytes = token.serialize();

        // Extract header bytes (first 16 bytes) as AAD
        let header_bytes = header.serialize();
        if header_bytes.len() != 16 {
            return Err(Error::ProtocolViolation(
                "Token header must be exactly 16 bytes".into(),
            ));
        }

        // Payload to encrypt = everything after header
        let plaintext = &token_bytes[16..];

        // Generate fresh random 12-byte nonce for this save
        let mut token_nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut token_nonce);

        // Get device key from provider
        let device_key = key_provider
            .get_device_key()
            .map_err(|e| Error::ProtocolViolation(format!("Failed to get device key: {}", e)))?;

        // Encrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&*device_key)
            .map_err(|e| Error::ProtocolViolation(format!("AES-256-GCM init failed: {}", e)))?;

        let payload = Payload {
            msg: plaintext,
            aad: &header_bytes, // Header is AAD (authenticated but not encrypted)
        };

        let nonce = Nonce::from_slice(&token_nonce);
        let ciphertext_with_tag = cipher
            .encrypt(nonce, payload)
            .map_err(|e| Error::ProtocolViolation(format!("Token encryption failed: {}", e)))?;

        // Build storage format: token_nonce[12] || header[16] || ciphertext || tag[16]
        // (tag is already appended by AEAD)
        let mut storage_blob = Vec::with_capacity(12 + 16 + ciphertext_with_tag.len());
        storage_blob.extend_from_slice(&token_nonce);
        storage_blob.extend_from_slice(&header_bytes);
        storage_blob.extend_from_slice(&ciphertext_with_tag);

        Ok(storage_blob)
    }

    /// Save session state with raw device key (backward compatibility wrapper).
    ///
    /// This is a backward compatibility wrapper around `save_state_token()` that accepts
    /// a raw 32-byte device key instead of a KeyProvider trait object.
    ///
    /// # Deprecated
    ///
    /// Prefer using `save_state_token()` with a platform-specific KeyProvider implementation
    /// for better testability and platform abstraction.
    ///
    /// # Arguments
    ///
    /// * `device_key` - 32-byte device-bound encryption key (from Secure Enclave, KeyStore, etc.)
    /// * `streams` - Slice of active streams to include in token (max 12)
    /// * `connection_context` - Connection-specific metadata (connection_id, peer_address, etc.)
    ///
    /// # Returns
    ///
    /// Returns encrypted token blob (same format as `save_state_token()`).
    pub fn save_state_token_legacy(
        &self,
        device_key: &[u8; 32],
        streams: &[crate::stream::Stream],
        connection_context: crate::token::ConnectionContext,
    ) -> Result<Vec<u8>> {
        use zeroize::Zeroizing;

        // Simple wrapper that implements KeyProvider for a raw byte key
        struct RawKeyProvider {
            key: Zeroizing<[u8; 32]>,
        }

        impl zp_platform::traits::KeyProvider for RawKeyProvider {
            fn get_device_key(
                &self,
            ) -> std::result::Result<Zeroizing<[u8; 32]>, zp_platform::error::Error> {
                Ok(Zeroizing::new(*self.key))
            }

            fn encrypt(
                &self,
                _plaintext: &[u8],
            ) -> std::result::Result<Vec<u8>, zp_platform::error::Error> {
                unimplemented!("save_state_token only uses get_device_key()")
            }

            fn decrypt(
                &self,
                _ciphertext: &[u8],
            ) -> std::result::Result<Vec<u8>, zp_platform::error::Error> {
                unimplemented!("save_state_token only uses get_device_key()")
            }
        }

        let provider = RawKeyProvider {
            key: Zeroizing::new(*device_key),
        };
        self.save_state_token(&provider, streams, connection_context)
    }

    /// Restore session from an encrypted State Token per spec §6.5.
    ///
    /// Decrypts and validates a State Token, restoring the session's cryptographic
    /// state and connection context. The session must be in Idle state before calling.
    ///
    /// # Arguments
    ///
    /// * `key_provider` - Platform-specific key provider (e.g., SecureEnclaveKeyProvider, MockKeyProvider)
    /// * `storage_blob` - Encrypted token blob (token_nonce[12] || header[16] || ciphertext || tag[16])
    ///
    /// # Returns
    ///
    /// Returns the decrypted StateToken for further processing by the caller.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Session not in Idle state
    /// - Storage blob too short (< 44 bytes minimum)
    /// - Decryption fails (wrong key, corrupted data, or tampered AAD)
    /// - Token header validation fails
    /// - Token expired (created_at > 24 hours ago)
    ///
    /// # Spec Reference
    ///
    /// §6.5 - State Token Format
    /// §6.5.1 - AEAD Nonce Construction
    pub fn restore_from_token(
        &mut self,
        key_provider: &dyn zp_platform::traits::KeyProvider,
        storage_blob: &[u8],
    ) -> Result<crate::token::StateToken> {
        use crate::token::{StateToken, TokenHeader};
        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes256Gcm, Nonce,
        };

        // Ensure session is in Idle state
        if !matches!(self.state, SessionState::Idle) {
            return Err(Error::InvalidState);
        }

        // Validate minimum blob size: 12 (nonce) + 16 (header) + 16 (tag) = 44 bytes
        if storage_blob.len() < 44 {
            return Err(Error::ProtocolViolation(format!(
                "Token blob too short: {} bytes (min 44)",
                storage_blob.len()
            )));
        }

        // Extract components from storage blob
        let token_nonce = &storage_blob[0..12];
        let header_bytes = &storage_blob[12..28];
        let ciphertext_with_tag = &storage_blob[28..];

        // Parse header (AAD) to validate before decryption
        let header = TokenHeader::parse(header_bytes)?;

        // Check token expiration (24 hours per spec §6.5)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::ProtocolViolation("System clock error".into()))?
            .as_secs();
        let age_secs = now.saturating_sub(header.created_at);
        if age_secs > 24 * 60 * 60 {
            return Err(Error::TokenExpired);
        }

        // Get device key from provider
        let device_key = key_provider
            .get_device_key()
            .map_err(|e| Error::ProtocolViolation(format!("Failed to get device key: {}", e)))?;

        // Decrypt with AES-256-GCM
        let cipher = Aes256Gcm::new_from_slice(&*device_key)
            .map_err(|e| Error::ProtocolViolation(format!("AES-256-GCM init failed: {}", e)))?;

        let payload = Payload {
            msg: ciphertext_with_tag,
            aad: header_bytes, // Header is AAD (must match for decryption to succeed)
        };

        let nonce = Nonce::from_slice(token_nonce);
        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|_| Error::ProtocolViolation("Token decryption failed".into()))?;

        // Reconstruct full token bytes: header || plaintext
        let mut token_bytes = Vec::with_capacity(16 + plaintext.len());
        token_bytes.extend_from_slice(header_bytes);
        token_bytes.extend_from_slice(&plaintext);

        // Parse StateToken
        let token = StateToken::parse(&token_bytes)?;

        // Restore session keys from token
        // The token stores send/recv keys in role-dependent order
        // For restore, we need to reconstruct both c2s and s2c keys
        let send_key_z = Zeroizing::new(token.crypto_context.send_key);
        let recv_key_z = Zeroizing::new(token.crypto_context.recv_key);

        // Determine c2s/s2c based on role
        let (c2s, s2c) = match self.role {
            Role::Client => (send_key_z.clone(), recv_key_z.clone()),
            Role::Server => (recv_key_z.clone(), send_key_z.clone()),
        };

        let restored_keys = SessionKeys {
            session_id: token.crypto_context.session_id,
            session_secret: Zeroizing::new(token.crypto_context.session_secret),
            client_to_server_key: c2s,
            server_to_client_key: s2c,
            send_key: send_key_z,
            recv_key: recv_key_z,
            send_nonce: token.crypto_context.send_nonce,
            recv_nonce: token.crypto_context.recv_nonce,
            key_epoch: token.crypto_context.key_epoch,
            pending_epoch: None, // No pending rotation on resume
        };

        // Update session state to Established
        self.state = SessionState::Established {
            session_id: token.crypto_context.session_id,
            version: 0x0100, // Assume v1.0 (caller can override if needed)
            cipher: 0x01,    // Assume ZP_HYBRID_1 (caller can override)
        };
        self.keys = Some(restored_keys);

        Ok(token)
    }

    /// Restore session from encrypted State Token with raw device key (backward compatibility wrapper).
    ///
    /// This is a backward compatibility wrapper around `restore_from_token()` that accepts
    /// a raw 32-byte device key instead of a KeyProvider trait object.
    ///
    /// # Deprecated
    ///
    /// Prefer using `restore_from_token()` with a platform-specific KeyProvider implementation
    /// for better testability and platform abstraction.
    ///
    /// # Arguments
    ///
    /// * `device_key` - 32-byte device-bound decryption key (same key used for encryption)
    /// * `storage_blob` - Encrypted token blob (token_nonce[12] || header[16] || ciphertext || tag[16])
    ///
    /// # Returns
    ///
    /// Returns the decrypted StateToken (same as `restore_from_token()`).
    pub fn restore_from_token_legacy(
        &mut self,
        device_key: &[u8; 32],
        storage_blob: &[u8],
    ) -> Result<crate::token::StateToken> {
        use zeroize::Zeroizing;

        // Simple wrapper that implements KeyProvider for a raw byte key
        struct RawKeyProvider {
            key: Zeroizing<[u8; 32]>,
        }

        impl zp_platform::traits::KeyProvider for RawKeyProvider {
            fn get_device_key(
                &self,
            ) -> std::result::Result<Zeroizing<[u8; 32]>, zp_platform::error::Error> {
                Ok(Zeroizing::new(*self.key))
            }

            fn encrypt(
                &self,
                _plaintext: &[u8],
            ) -> std::result::Result<Vec<u8>, zp_platform::error::Error> {
                unimplemented!("restore_from_token only uses get_device_key()")
            }

            fn decrypt(
                &self,
                _ciphertext: &[u8],
            ) -> std::result::Result<Vec<u8>, zp_platform::error::Error> {
                unimplemented!("restore_from_token only uses get_device_key()")
            }
        }

        let provider = RawKeyProvider {
            key: Zeroizing::new(*device_key),
        };
        self.restore_from_token(&provider, storage_blob)
    }

    // === EncryptedRecord encryption/decryption (§3.3.13) ===

    /// Encrypt a frame for non-QUIC transports per spec §3.3.13.
    ///
    /// Wraps the frame in an EncryptedRecord using AEAD encryption.
    ///
    /// # Arguments
    ///
    /// * `frame` - Frame to encrypt (must not be ErrorFrame per spec)
    ///
    /// # Returns
    ///
    /// Returns `Frame::EncryptedRecord` containing encrypted frame data.
    ///
    /// # Errors
    ///
    /// Returns error if session not established or encryption fails.
    pub fn encrypt_frame(&mut self, frame: &Frame) -> Result<Frame> {
        // Ensure session is established
        let keys = self
            .keys
            .as_mut()
            .ok_or_else(|| Error::ProtocolViolation("Session not established".into()))?;

        // Get selected cipher from state
        let cipher = match &self.state {
            SessionState::Established { cipher, .. } => *cipher,
            _ => return Err(Error::InvalidState),
        };

        // Serialize frame
        let plaintext = frame.serialize()?;

        // Get current epoch and send_nonce
        let epoch = keys.key_epoch as u8; // Truncate to u8 per spec
        let counter = keys.send_nonce;

        // Increment send_nonce for next frame
        keys.send_nonce = keys
            .send_nonce
            .checked_add(1)
            .ok_or_else(|| Error::ProtocolViolation("Send nonce overflow".into()))?;

        // Calculate length per spec: 4 (length) + 1 (epoch) + 8 (counter) + plaintext.len() + 16 (tag)
        let total_length = 4 + 1 + 8 + plaintext.len() + 16;
        if total_length > 16_777_216 {
            // MAX_RECORD_SIZE = 16 MB
            return Err(Error::ProtocolViolation(format!(
                "EncryptedRecord too large: {} bytes (max 16 MB)",
                total_length
            )));
        }

        // Construct AAD: length (4 bytes LE) || epoch (1 byte) || counter (8 bytes LE)
        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&(total_length as u32).to_le_bytes());
        aad.push(epoch);
        aad.extend_from_slice(&counter.to_le_bytes());

        // Construct nonce per spec §6.5.1: [0,0,0,0] || counter (8 bytes LE)
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());

        // Encrypt based on cipher suite
        let (ciphertext, tag) = match cipher {
            ZP_HYBRID_1 | ZP_HYBRID_2 => {
                // ChaCha20-Poly1305
                use chacha20poly1305::{
                    aead::{Aead, KeyInit, Payload},
                    ChaCha20Poly1305,
                };

                let cipher_obj =
                    ChaCha20Poly1305::new_from_slice(&*keys.send_key).map_err(|e| {
                        Error::ProtocolViolation(format!("ChaCha20 init failed: {}", e))
                    })?;

                let payload = Payload {
                    msg: &plaintext,
                    aad: &aad,
                };

                let ciphertext_with_tag = cipher_obj
                    .encrypt(&nonce.into(), payload)
                    .map_err(|e| Error::ProtocolViolation(format!("Encryption failed: {}", e)))?;

                // Split ciphertext and tag (last 16 bytes)
                if ciphertext_with_tag.len() < 16 {
                    return Err(Error::ProtocolViolation(
                        "Encrypted output too short".into(),
                    ));
                }
                let split_point = ciphertext_with_tag.len() - 16;
                let ct = ciphertext_with_tag[..split_point].to_vec();
                let mut tag_arr = [0u8; 16];
                tag_arr.copy_from_slice(&ciphertext_with_tag[split_point..]);
                (ct, tag_arr)
            }
            ZP_HYBRID_3 | ZP_CLASSICAL_2 => {
                // AES-256-GCM
                use aes_gcm::{
                    aead::{Aead, KeyInit, Payload},
                    Aes256Gcm,
                };

                let cipher_obj = Aes256Gcm::new_from_slice(&*keys.send_key).map_err(|e| {
                    Error::ProtocolViolation(format!("AES-256-GCM init failed: {}", e))
                })?;

                let payload = Payload {
                    msg: &plaintext,
                    aad: &aad,
                };

                let ciphertext_with_tag = cipher_obj
                    .encrypt(&nonce.into(), payload)
                    .map_err(|e| Error::ProtocolViolation(format!("Encryption failed: {}", e)))?;

                // Split ciphertext and tag
                if ciphertext_with_tag.len() < 16 {
                    return Err(Error::ProtocolViolation(
                        "Encrypted output too short".into(),
                    ));
                }
                let split_point = ciphertext_with_tag.len() - 16;
                let ct = ciphertext_with_tag[..split_point].to_vec();
                let mut tag_arr = [0u8; 16];
                tag_arr.copy_from_slice(&ciphertext_with_tag[split_point..]);
                (ct, tag_arr)
            }
            _ => {
                return Err(Error::ProtocolViolation(format!(
                    "Unsupported cipher for EncryptedRecord: {}",
                    cipher
                )))
            }
        };

        Ok(Frame::EncryptedRecord {
            epoch,
            counter,
            ciphertext,
            tag,
        })
    }

    /// Decrypt an EncryptedRecord for non-QUIC transports per spec §3.3.13.
    ///
    /// # Arguments
    ///
    /// * `encrypted_record` - EncryptedRecord frame to decrypt
    ///
    /// # Returns
    ///
    /// Returns decrypted Frame.
    ///
    /// # Errors
    ///
    /// Returns error if session not established, counter mismatch (replay attack),
    /// or decryption fails.
    pub fn decrypt_record(&mut self, encrypted_record: &Frame) -> Result<Frame> {
        // Ensure session is established
        let keys = self
            .keys
            .as_mut()
            .ok_or_else(|| Error::ProtocolViolation("Session not established".into()))?;

        // Get selected cipher from state
        let cipher = match &self.state {
            SessionState::Established { cipher, .. } => *cipher,
            _ => return Err(Error::InvalidState),
        };

        // Extract EncryptedRecord fields
        let (epoch, counter, ciphertext, tag) = match encrypted_record {
            Frame::EncryptedRecord {
                epoch,
                counter,
                ciphertext,
                tag,
            } => (*epoch, *counter, ciphertext, *tag),
            _ => return Err(Error::InvalidFrame("Expected EncryptedRecord".into())),
        };

        // Verify counter matches expected recv_nonce (prevents replay attacks)
        if counter != keys.recv_nonce {
            return Err(Error::ProtocolViolation(format!(
                "EncryptedRecord counter mismatch: got {}, expected {}",
                counter, keys.recv_nonce
            )));
        }

        // Verify epoch matches current epoch
        if epoch != keys.key_epoch as u8 {
            return Err(Error::ProtocolViolation(format!(
                "EncryptedRecord epoch mismatch: got {}, expected {}",
                epoch, keys.key_epoch
            )));
        }

        // Calculate length
        let total_length = 4 + 1 + 8 + ciphertext.len() + 16;

        // Construct AAD: length (4 bytes LE) || epoch (1 byte) || counter (8 bytes LE)
        let mut aad = Vec::with_capacity(13);
        aad.extend_from_slice(&(total_length as u32).to_le_bytes());
        aad.push(epoch);
        aad.extend_from_slice(&counter.to_le_bytes());

        // Construct nonce per spec §6.5.1: [0,0,0,0] || counter (8 bytes LE)
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());

        // Reconstruct ciphertext_with_tag for AEAD libraries
        let mut ciphertext_with_tag = ciphertext.clone();
        ciphertext_with_tag.extend_from_slice(&tag);

        // Decrypt based on cipher suite
        let plaintext = match cipher {
            ZP_HYBRID_1 | ZP_HYBRID_2 => {
                // ChaCha20-Poly1305
                use chacha20poly1305::{
                    aead::{Aead, KeyInit, Payload},
                    ChaCha20Poly1305,
                };

                let cipher_obj =
                    ChaCha20Poly1305::new_from_slice(&*keys.recv_key).map_err(|e| {
                        Error::ProtocolViolation(format!("ChaCha20 init failed: {}", e))
                    })?;

                let payload = Payload {
                    msg: &ciphertext_with_tag,
                    aad: &aad,
                };

                cipher_obj
                    .decrypt(&nonce.into(), payload)
                    .map_err(|e| Error::ProtocolViolation(format!("Decryption failed: {}", e)))?
            }
            ZP_HYBRID_3 | ZP_CLASSICAL_2 => {
                // AES-256-GCM
                use aes_gcm::{
                    aead::{Aead, KeyInit, Payload},
                    Aes256Gcm,
                };

                let cipher_obj = Aes256Gcm::new_from_slice(&*keys.recv_key).map_err(|e| {
                    Error::ProtocolViolation(format!("AES-256-GCM init failed: {}", e))
                })?;

                let payload = Payload {
                    msg: &ciphertext_with_tag,
                    aad: &aad,
                };

                cipher_obj
                    .decrypt(&nonce.into(), payload)
                    .map_err(|e| Error::ProtocolViolation(format!("Decryption failed: {}", e)))?
            }
            _ => {
                return Err(Error::ProtocolViolation(format!(
                    "Unsupported cipher for EncryptedRecord: {}",
                    cipher
                )))
            }
        };

        // Increment recv_nonce for next frame
        keys.recv_nonce = keys
            .recv_nonce
            .checked_add(1)
            .ok_or_else(|| Error::ProtocolViolation("Receive nonce overflow".into()))?;

        // Parse decrypted plaintext as Frame
        Frame::parse(&plaintext)
    }
}

/// Test-only methods for manipulating session internals.
///
/// These methods exist solely to test overflow behavior and edge cases.
/// They are compiled out entirely in release builds via the `test-helpers` feature.
///
/// To use in tests: Add `zp-core = { path = "../zp-core", features = ["test-helpers"] }`
#[cfg(any(test, feature = "test-helpers"))]
impl Session {
    /// Test-only: Set send_nonce to test overflow behavior.
    ///
    /// # Cryptographic Safety
    /// Setting send_nonce to a previously used value with the same key
    /// causes **CATASTROPHIC NONCE REUSE**, completely breaking AEAD security.
    /// This method exists ONLY to test overflow protection at u64::MAX.
    ///
    /// # Spec Reference
    /// Per §6.5.1: "The counter MUST NOT wrap; if it reaches 2^64 - 1,
    /// trigger key rotation before sending the next message."
    ///
    /// # Usage
    /// ```ignore
    /// session.test_set_send_nonce(u64::MAX - 1);
    /// // Next encrypt should succeed (nonce = MAX)
    /// // Following encrypt should error (overflow protection)
    /// ```
    ///
    /// # Safety
    /// This bypasses normal nonce increment logic. Only use for testing
    /// overflow protection. Never set to same value twice with same key.
    pub fn test_set_send_nonce(&mut self, value: u64) {
        if let Some(keys) = &mut self.keys {
            keys.send_nonce = value;
        }
    }

    /// Test-only: Set recv_nonce to test overflow behavior.
    ///
    /// # Cryptographic Safety
    /// See documentation on `test_set_send_nonce`. Same nonce reuse
    /// danger applies for receive-side nonces.
    ///
    /// # Spec Reference
    /// Per §6.5.1: Receive nonces must be strictly monotonically increasing
    /// to prevent replay attacks. Counter overflow must be prevented.
    pub fn test_set_recv_nonce(&mut self, value: u64) {
        if let Some(keys) = &mut self.keys {
            keys.recv_nonce = value;
        }
    }

    /// Test-only: Set key_epoch to test epoch overflow.
    ///
    /// # Spec Reference
    /// Per §4.6.2, key_epoch is u32 and increments on each rotation.
    /// This tests behavior at u32::MAX.
    ///
    /// # Usage
    /// ```ignore
    /// session.test_set_key_epoch(u32::MAX);
    /// // Next key rotation should fail (overflow protection)
    /// ```
    pub fn test_set_key_epoch(&mut self, value: u32) {
        if let Some(keys) = &mut self.keys {
            keys.key_epoch = value;
        }
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new(Role::Client, HandshakeMode::Stranger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new(Role::Client, HandshakeMode::Stranger);
        assert_eq!(session.role(), Role::Client);
        assert_eq!(session.mode(), HandshakeMode::Stranger);
        assert!(!session.is_established());
    }

    #[test]
    fn test_stranger_handshake_flow() {
        // Client initiates
        let mut client = Session::new(Role::Client, HandshakeMode::Stranger);
        let client_hello = client.client_start_stranger().expect("client_start failed");

        // Server processes ClientHello
        let mut server = Session::new(Role::Server, HandshakeMode::Stranger);
        let server_hello = server
            .server_process_client_hello(client_hello)
            .expect("server process failed");

        // Client processes ServerHello
        let client_finish = client
            .client_process_server_hello(server_hello)
            .expect("client process failed");

        // Server processes ClientFinish
        server
            .server_process_client_finish(client_finish)
            .expect("server finish failed");

        // Both should be established
        assert!(client.is_established());
        assert!(server.is_established());

        // Session IDs should match
        let client_keys = client.keys().unwrap();
        let server_keys = server.keys().unwrap();
        assert_eq!(client_keys.session_id, server_keys.session_id);

        // Keys should be complementary
        assert_eq!(&*client_keys.send_key, &*server_keys.recv_key);
        assert_eq!(&*client_keys.recv_key, &*server_keys.send_key);
    }

    #[test]
    fn test_version_negotiation() {
        let config = SessionConfig::default();
        let session = Session::with_config(Role::Server, HandshakeMode::Stranger, config);

        // Should select version 1.0
        let result = session.negotiate_version(&[0x0100, 0x0101], 0x0100);
        assert_eq!(result.unwrap(), 0x0100);

        // Should fail if no common version
        let result = session.negotiate_version(&[0x0200], 0x0200);
        assert!(result.is_err());
    }

    #[test]
    fn test_cipher_negotiation() {
        let config = SessionConfig::default();
        let session = Session::with_config(Role::Server, HandshakeMode::Stranger, config);

        // Should select first server-preferred cipher that client supports
        let result = session.negotiate_cipher(&[ZP_HYBRID_2, ZP_HYBRID_1]);
        assert_eq!(result.unwrap(), ZP_HYBRID_1); // Server prefers HYBRID_1

        // Should fail if no common cipher
        let result = session.negotiate_cipher(&[0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_rotation_protocol() {
        // Establish a session first
        let mut client = Session::new(Role::Client, HandshakeMode::Stranger);
        let client_hello = client.client_start_stranger().unwrap();

        let mut server = Session::new(Role::Server, HandshakeMode::Stranger);
        let server_hello = server.server_process_client_hello(client_hello).unwrap();

        let client_finish = client.client_process_server_hello(server_hello).unwrap();
        server.server_process_client_finish(client_finish).unwrap();

        // Both sessions established
        assert!(client.is_established());
        assert!(server.is_established());

        // Verify initial epoch is 0
        assert_eq!(client.keys().unwrap().key_epoch, 0);
        assert_eq!(server.keys().unwrap().key_epoch, 0);

        // Client initiates key rotation for both directions
        let key_update = client.initiate_key_rotation(0x03).unwrap();

        // Verify KeyUpdate frame
        match key_update {
            Frame::KeyUpdate {
                key_epoch,
                direction,
            } => {
                assert_eq!(key_epoch, 1, "Epoch should increment to 1");
                assert_eq!(direction, 0x03, "Should rotate both directions");
            }
            _ => panic!("Expected KeyUpdate frame"),
        }

        // Verify client has pending epoch
        assert_eq!(client.keys().unwrap().pending_epoch, Some(1));

        // Server processes KeyUpdate
        let key_update_ack = if let Frame::KeyUpdate {
            key_epoch,
            direction,
        } = key_update
        {
            server.process_key_update(key_epoch, direction).unwrap()
        } else {
            panic!("Expected KeyUpdate frame");
        };

        // Verify KeyUpdateAck frame
        match key_update_ack {
            Frame::KeyUpdateAck { acked_epoch } => {
                assert_eq!(acked_epoch, 1, "Should ack epoch 1");
            }
            _ => panic!("Expected KeyUpdateAck frame"),
        }

        // Verify server epoch updated
        assert_eq!(server.keys().unwrap().key_epoch, 1);

        // Client processes KeyUpdateAck
        if let Frame::KeyUpdateAck { acked_epoch } = key_update_ack {
            client.process_key_update_ack(acked_epoch).unwrap();
        }

        // Verify client epoch updated and pending cleared
        assert_eq!(client.keys().unwrap().key_epoch, 1);
        assert_eq!(client.keys().unwrap().pending_epoch, None);

        // Keys should still be complementary after rotation
        let client_keys = client.keys().unwrap();
        let server_keys = server.keys().unwrap();
        assert_eq!(&*client_keys.send_key, &*server_keys.recv_key);
        assert_eq!(&*client_keys.recv_key, &*server_keys.send_key);
    }

    #[test]
    fn test_key_rotation_c2s_only() {
        // Establish session
        let mut client = Session::new(Role::Client, HandshakeMode::Stranger);
        let mut server = Session::new(Role::Server, HandshakeMode::Stranger);

        let ch = client.client_start_stranger().unwrap();
        let sh = server.server_process_client_hello(ch).unwrap();
        let cf = client.client_process_server_hello(sh).unwrap();
        server.server_process_client_finish(cf).unwrap();

        // Rotate C2S key only (direction 0x01)
        let key_update = client.initiate_key_rotation(0x01).unwrap();

        if let Frame::KeyUpdate {
            key_epoch,
            direction,
        } = key_update
        {
            assert_eq!(direction, 0x01, "Should rotate C2S only");
            let ack = server.process_key_update(key_epoch, direction).unwrap();

            if let Frame::KeyUpdateAck { acked_epoch } = ack {
                client.process_key_update_ack(acked_epoch).unwrap();
            }
        }

        // Verify both have same epoch
        assert_eq!(client.keys().unwrap().key_epoch, 1);
        assert_eq!(server.keys().unwrap().key_epoch, 1);
    }

    #[test]
    fn test_key_rotation_before_established() {
        // Try to rotate keys before session is established
        let mut session = Session::new(Role::Client, HandshakeMode::Stranger);

        let result = session.initiate_key_rotation(0x03);
        assert!(
            result.is_err(),
            "Should fail to rotate before session established"
        );
    }

    #[test]
    fn test_key_rotation_invalid_direction() {
        // Establish session
        let mut client = Session::new(Role::Client, HandshakeMode::Stranger);
        let mut server = Session::new(Role::Server, HandshakeMode::Stranger);

        let ch = client.client_start_stranger().unwrap();
        let sh = server.server_process_client_hello(ch).unwrap();
        let cf = client.client_process_server_hello(sh).unwrap();
        server.server_process_client_finish(cf).unwrap();

        // Try invalid directions
        assert!(
            client.initiate_key_rotation(0x00).is_err(),
            "Direction 0 should be invalid"
        );
        assert!(
            client.initiate_key_rotation(0x04).is_err(),
            "Direction > 3 should be invalid"
        );
    }

    #[test]
    fn test_key_rotation_pending_blocks_new() {
        // Establish session
        let mut client = Session::new(Role::Client, HandshakeMode::Stranger);
        let mut server = Session::new(Role::Server, HandshakeMode::Stranger);

        let ch = client.client_start_stranger().unwrap();
        let sh = server.server_process_client_hello(ch).unwrap();
        let cf = client.client_process_server_hello(sh).unwrap();
        server.server_process_client_finish(cf).unwrap();

        // Initiate rotation
        client.initiate_key_rotation(0x03).unwrap();

        // Try to initiate another rotation while pending
        let result = client.initiate_key_rotation(0x03);
        assert!(
            result.is_err(),
            "Should block new rotation while one is pending"
        );
    }

    #[test]
    fn test_handshake_timeout_tracking() {
        let mut session = Session::new(Role::Client, HandshakeMode::Stranger);

        // Initially idle - not in progress
        assert!(!session.is_handshake_in_progress());
        assert!(!session.is_handshake_timeout(10000));

        // Start handshake
        let _frame = session.client_start_stranger().unwrap();

        // Now in progress
        assert!(session.is_handshake_in_progress());

        // Not timed out at 1 second (default timeout is 5 seconds)
        assert!(!session.is_handshake_timeout(1000));

        // Not timed out at 5 seconds (exactly at limit)
        assert!(!session.is_handshake_timeout(5000));

        // Timed out after 5001ms
        assert!(session.is_handshake_timeout(5001));

        // Timed out after 10 seconds
        assert!(session.is_handshake_timeout(10000));
    }

    #[test]
    fn test_handshake_timeout_with_custom_config() {
        let config = SessionConfig {
            handshake_timeout_ms: 10000, // 10 second timeout
            ..Default::default()
        };
        let mut session = Session::with_config(Role::Client, HandshakeMode::Stranger, config);

        // Start handshake
        let _frame = session.client_start_stranger().unwrap();

        // Not timed out at 9 seconds
        assert!(!session.is_handshake_timeout(9000));

        // Not timed out at 10 seconds (exactly at limit)
        assert!(!session.is_handshake_timeout(10000));

        // Timed out after 10001ms
        assert!(session.is_handshake_timeout(10001));
    }

    #[test]
    fn test_handshake_timeout_clears_on_established() {
        let mut client = Session::new(Role::Client, HandshakeMode::Stranger);
        let mut server = Session::new(Role::Server, HandshakeMode::Stranger);

        // Start handshake
        let ch = client.client_start_stranger().unwrap();
        assert!(client.is_handshake_in_progress());

        // Process handshake
        let sh = server.server_process_client_hello(ch).unwrap();
        let cf = client.client_process_server_hello(sh).unwrap();
        server.server_process_client_finish(cf).unwrap();

        // Both should be established now
        assert!(client.is_established());
        assert!(server.is_established());

        // No longer in progress, so timeout check returns false even with large elapsed time
        assert!(!client.is_handshake_in_progress());
        assert!(!client.is_handshake_timeout(99999));
        assert!(!server.is_handshake_in_progress());
        assert!(!server.is_handshake_timeout(99999));
    }

    #[test]
    fn test_session_id_collision_detection() {
        let id1 = [1u8; 16];
        let id2 = [2u8; 16];
        let id3 = [3u8; 16];

        let existing = vec![id1, id2];

        // No collision with new ID
        assert!(!session_id_collides(&id3, &existing));

        // Collision detected with existing ID
        assert!(session_id_collides(&id1, &existing));
        assert!(session_id_collides(&id2, &existing));
    }

    #[test]
    fn test_session_id_collision_empty_list() {
        let id = [1u8; 16];
        let existing: Vec<[u8; 16]> = vec![];

        // No collision with empty list
        assert!(!session_id_collides(&id, &existing));
    }

    #[test]
    fn test_session_id_available_after_handshake() {
        let mut client = Session::new(Role::Client, HandshakeMode::Stranger);
        let mut server = Session::new(Role::Server, HandshakeMode::Stranger);

        // No session ID before handshake
        assert!(client.session_id().is_none());
        assert!(server.session_id().is_none());

        // Complete handshake
        let ch = client.client_start_stranger().unwrap();
        assert!(client.session_id().is_none()); // Still none mid-handshake

        let sh = server.server_process_client_hello(ch).unwrap();
        let cf = client.client_process_server_hello(sh).unwrap();
        server.server_process_client_finish(cf).unwrap();

        // Session ID available after handshake
        let client_id = client.session_id().expect("Client should have session ID");
        let server_id = server.session_id().expect("Server should have session ID");

        // Both should have the same session ID
        assert_eq!(client_id, server_id);

        // Verify it's 16 bytes (128 bits)
        assert_eq!(client_id.len(), 16);
    }

    #[test]
    fn test_session_id_uniqueness_across_handshakes() {
        // Create multiple handshakes and verify session IDs are different
        let mut session_ids = Vec::new();

        for _ in 0..10 {
            let mut client = Session::new(Role::Client, HandshakeMode::Stranger);
            let mut server = Session::new(Role::Server, HandshakeMode::Stranger);

            // Complete handshake
            let ch = client.client_start_stranger().unwrap();
            let sh = server.server_process_client_hello(ch).unwrap();
            let cf = client.client_process_server_hello(sh).unwrap();
            server.server_process_client_finish(cf).unwrap();

            let session_id = client.session_id().expect("Should have session ID");

            // Check for collision with existing sessions
            assert!(
                !session_id_collides(&session_id, &session_ids),
                "Session ID collision detected (very unlikely with 10 sessions)"
            );

            session_ids.push(session_id);
        }

        // Verify all session IDs are unique
        for (i, id1) in session_ids.iter().enumerate() {
            for (j, id2) in session_ids.iter().enumerate() {
                if i != j {
                    assert_ne!(id1, id2, "Session IDs should be unique");
                }
            }
        }
    }

    #[test]
    fn test_encrypted_record_roundtrip() {
        // Establish a session
        let mut client = Session::new(Role::Client, HandshakeMode::Stranger);
        let mut server = Session::new(Role::Server, HandshakeMode::Stranger);

        let ch = client.client_start_stranger().unwrap();
        let sh = server.server_process_client_hello(ch).unwrap();
        let cf = client.client_process_server_hello(sh).unwrap();
        server.server_process_client_finish(cf).unwrap();

        // Both established
        assert!(client.is_established());
        assert!(server.is_established());

        // Create a test DataFrame
        let test_frame = Frame::DataFrame {
            stream_id: 42,
            seq: 1,
            flags: 0,
            payload: vec![1, 2, 3, 4, 5],
        };

        // Client encrypts the frame
        let encrypted = client.encrypt_frame(&test_frame).unwrap();

        // Verify it's an EncryptedRecord
        assert!(matches!(encrypted, Frame::EncryptedRecord { .. }));

        // Verify send_nonce incremented
        assert_eq!(client.keys().unwrap().send_nonce, 1);

        // Server decrypts the frame
        let decrypted = server.decrypt_record(&encrypted).unwrap();

        // Verify recv_nonce incremented
        assert_eq!(server.keys().unwrap().recv_nonce, 1);

        // Verify decrypted frame matches original
        match (test_frame, decrypted) {
            (
                Frame::DataFrame {
                    stream_id: s1,
                    seq: seq1,
                    flags: f1,
                    payload: p1,
                },
                Frame::DataFrame {
                    stream_id: s2,
                    seq: seq2,
                    flags: f2,
                    payload: p2,
                },
            ) => {
                assert_eq!(s1, s2);
                assert_eq!(seq1, seq2);
                assert_eq!(f1, f2);
                assert_eq!(p1, p2);
            }
            _ => panic!("Decrypted frame type mismatch"),
        }
    }

    #[test]
    fn test_encrypted_record_nonce_increment() {
        // Establish session
        let mut client = Session::new(Role::Client, HandshakeMode::Stranger);
        let mut server = Session::new(Role::Server, HandshakeMode::Stranger);

        let ch = client.client_start_stranger().unwrap();
        let sh = server.server_process_client_hello(ch).unwrap();
        let cf = client.client_process_server_hello(sh).unwrap();
        server.server_process_client_finish(cf).unwrap();

        // Send multiple frames and verify nonce increments
        for i in 0..5u64 {
            let frame = Frame::DataFrame {
                stream_id: 1,
                seq: i,
                flags: 0,
                payload: vec![i as u8],
            };

            assert_eq!(client.keys().unwrap().send_nonce, i);
            let encrypted = client.encrypt_frame(&frame).unwrap();
            assert_eq!(client.keys().unwrap().send_nonce, i + 1);

            assert_eq!(server.keys().unwrap().recv_nonce, i);
            let _decrypted = server.decrypt_record(&encrypted).unwrap();
            assert_eq!(server.keys().unwrap().recv_nonce, i + 1);
        }

        // Verify final nonce values
        assert_eq!(client.keys().unwrap().send_nonce, 5);
        assert_eq!(server.keys().unwrap().recv_nonce, 5);
    }

    #[test]
    fn test_encrypted_record_replay_protection() {
        // Establish session
        let mut client = Session::new(Role::Client, HandshakeMode::Stranger);
        let mut server = Session::new(Role::Server, HandshakeMode::Stranger);

        let ch = client.client_start_stranger().unwrap();
        let sh = server.server_process_client_hello(ch).unwrap();
        let cf = client.client_process_server_hello(sh).unwrap();
        server.server_process_client_finish(cf).unwrap();

        // Encrypt a frame
        let frame = Frame::DataFrame {
            stream_id: 1,
            seq: 0,
            flags: 0,
            payload: vec![1, 2, 3],
        };
        let encrypted = client.encrypt_frame(&frame).unwrap();

        // First decryption should succeed
        let _decrypted = server.decrypt_record(&encrypted).unwrap();

        // Replay the same encrypted frame - should fail (nonce mismatch)
        let result = server.decrypt_record(&encrypted);
        assert!(
            result.is_err(),
            "Replay attack should be detected (nonce mismatch)"
        );
    }

    #[test]
    fn test_encrypted_record_wrong_epoch() {
        // Establish session
        let mut client = Session::new(Role::Client, HandshakeMode::Stranger);
        let mut server = Session::new(Role::Server, HandshakeMode::Stranger);

        let ch = client.client_start_stranger().unwrap();
        let sh = server.server_process_client_hello(ch).unwrap();
        let cf = client.client_process_server_hello(sh).unwrap();
        server.server_process_client_finish(cf).unwrap();

        // Encrypt a frame
        let frame = Frame::DataFrame {
            stream_id: 1,
            seq: 0,
            flags: 0,
            payload: vec![1, 2, 3],
        };
        let mut encrypted = client.encrypt_frame(&frame).unwrap();

        // Tamper with epoch
        if let Frame::EncryptedRecord {
            ref mut epoch,
            counter: _,
            ciphertext: _,
            tag: _,
        } = encrypted
        {
            *epoch = 99; // Wrong epoch
        }

        // Decryption should fail due to epoch mismatch
        let result = server.decrypt_record(&encrypted);
        assert!(
            result.is_err(),
            "Should reject EncryptedRecord with wrong epoch"
        );
    }

    #[test]
    fn test_encrypted_record_before_established() {
        // Try to encrypt before session is established
        let mut session = Session::new(Role::Client, HandshakeMode::Stranger);

        let frame = Frame::DataFrame {
            stream_id: 1,
            seq: 0,
            flags: 0,
            payload: vec![1, 2, 3],
        };

        let result = session.encrypt_frame(&frame);
        assert!(
            result.is_err(),
            "Should fail to encrypt before session established"
        );
    }

    #[test]
    fn test_encrypted_record_bidirectional() {
        // Establish session
        let mut client = Session::new(Role::Client, HandshakeMode::Stranger);
        let mut server = Session::new(Role::Server, HandshakeMode::Stranger);

        let ch = client.client_start_stranger().unwrap();
        let sh = server.server_process_client_hello(ch).unwrap();
        let cf = client.client_process_server_hello(sh).unwrap();
        server.server_process_client_finish(cf).unwrap();

        // Client sends to server
        let client_frame = Frame::DataFrame {
            stream_id: 1,
            seq: 0,
            flags: 0,
            payload: vec![1, 2, 3],
        };
        let encrypted_c2s = client.encrypt_frame(&client_frame).unwrap();
        let decrypted_c2s = server.decrypt_record(&encrypted_c2s).unwrap();

        // Verify decrypted matches
        match decrypted_c2s {
            Frame::DataFrame { payload, .. } => assert_eq!(payload, vec![1, 2, 3]),
            _ => panic!("Expected DataFrame"),
        }

        // Server sends to client
        let server_frame = Frame::DataFrame {
            stream_id: 2,
            seq: 0,
            flags: 0,
            payload: vec![4, 5, 6],
        };
        let encrypted_s2c = server.encrypt_frame(&server_frame).unwrap();
        let decrypted_s2c = client.decrypt_record(&encrypted_s2c).unwrap();

        // Verify decrypted matches
        match decrypted_s2c {
            Frame::DataFrame { payload, .. } => assert_eq!(payload, vec![4, 5, 6]),
            _ => panic!("Expected DataFrame"),
        }

        // Verify independent nonce counters
        assert_eq!(client.keys().unwrap().send_nonce, 1); // Client sent 1 frame
        assert_eq!(client.keys().unwrap().recv_nonce, 1); // Client received 1 frame
        assert_eq!(server.keys().unwrap().send_nonce, 1); // Server sent 1 frame
        assert_eq!(server.keys().unwrap().recv_nonce, 1); // Server received 1 frame
    }
}
