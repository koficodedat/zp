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
            opaque_credential_request: credential_request,
            random: client_random,
        };

        self.state = SessionState::KnownHelloSent {
            client_random,
            opaque_client_state: client_state,
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
        let (client_random, opaque_client_state) =
            match std::mem::replace(&mut self.state, SessionState::Idle) {
                SessionState::KnownHelloSent {
                    client_random,
                    opaque_client_state,
                } => (client_random, opaque_client_state),
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

        // Complete OPAQUE login (client side)
        use zp_crypto::pake;
        let (opaque_finalization, opaque_session_key) = pake::login_finalize(
            password,
            &opaque_credential_response,
            credential_identifier,
            &opaque_client_state,
        )
        .map_err(|e| Error::ProtocolViolation(format!("OPAQUE login_finalize failed: {}", e)))?;

        // Derive encryption key from OPAQUE session_key
        // OPAQUE session_key is 64 bytes, we use first 32 bytes for AES-256-GCM
        let encryption_key = &opaque_session_key[..32];

        // Decrypt ML-KEM public key
        let mlkem_pubkey =
            self.decrypt_mlkem_pubkey(encryption_key, &server_random, &mlkem_pubkey_encrypted)?;

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
        // WORKAROUND: Derive intermediate encryption key from OPAQUE server_login_state.
        // This is secure because server_login_state contains ephemeral secrets.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"zp-known-mode-mlkem-encryption");
        hasher.update(&server_login_state);
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
}
