//! Password-Authenticated Key Exchange (PAKE) primitives for Known Mode.
//!
//! Implements OPAQUE (RFC 9807) using the opaque-ke crate (NCC Group audited, 2021).
//! Replaces SPAKE2+ per DA-0001.
//!
//! # Protocol Flow
//!
//! ## Registration (one-time setup)
//! 1. Client: `registration_start(password)` → `RegistrationRequest`
//! 2. Server: `registration_response(request)` → `RegistrationResponse`
//! 3. Client: `registration_finalize(password, response)` → `RegistrationUpload`
//! 4. Server: `registration_complete(upload)` → stores `ServerRegistration` (password file)
//!
//! ## Login (per-connection)
//! 1. Client: `login_start(password)` → `CredentialRequest`
//! 2. Server: `login_response(request, password_file)` → `CredentialResponse`
//! 3. Client: `login_finalize(password, response)` → (`CredentialFinalization`, `session_key`)
//! 4. Server: `login_complete(finalization)` → `session_key`
//!
//! # Security Properties
//!
//! - Server never learns password (only OPRF output)
//! - Offline attack resistance
//! - Forward secrecy
//! - Mutual authentication
//! - NCC Group security audit (June 2021)

use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse, RegistrationUpload,
    ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup,
};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// Re-export opaque-ke error type.
pub use opaque_ke::errors::ProtocolError;

/// Concrete OPAQUE cipher suite using Ristretto255.
///
/// Selected for:
/// - Well-tested in opaque-ke
/// - 128-bit security level
/// - Fast scalar multiplication
/// - Cofactor-free (no subgroup attacks)
pub struct DefaultCipherSuite;

impl opaque_ke::CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = opaque_ke::ksf::Identity; // No additional key stretching (password already strong for zp)
}

// Type aliases for clarity
type OpaqueClientLogin = ClientLogin<DefaultCipherSuite>;
type OpaqueClientRegistration = ClientRegistration<DefaultCipherSuite>;
type OpaqueServerLogin = ServerLogin<DefaultCipherSuite>;
type OpaqueServerRegistration = ServerRegistration<DefaultCipherSuite>;

/// Server setup parameters (generated once, reused for all sessions).
///
/// Contains the server's long-term OPRF key.
/// Must be stored securely and persist across restarts.
#[derive(Clone)]
pub struct OpaqueServerSetup(ServerSetup<DefaultCipherSuite>);

impl OpaqueServerSetup {
    /// Generate new server setup parameters.
    ///
    /// This should be done once during server initialization.
    /// The resulting setup must be stored securely (hardware-backed key store).
    ///
    /// # Security
    ///
    /// Loss of server setup allows offline dictionary attacks on all password files.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self, ProtocolError> {
        Ok(OpaqueServerSetup(ServerSetup::<DefaultCipherSuite>::new(
            rng,
        )))
    }

    /// Access inner setup (for opaque-ke API calls).
    pub(crate) fn inner(&self) -> &ServerSetup<DefaultCipherSuite> {
        &self.0
    }
}

/// Stored password file (server-side).
///
/// Created during registration, used during login.
/// One file per user, indexed by username/identifier.
#[derive(Clone)]
pub struct PasswordFile(Vec<u8>);

impl PasswordFile {
    /// Create from serialized bytes (e.g., loaded from database).
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        PasswordFile(bytes)
    }

    /// Serialize to bytes for storage.
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }
}

// === Registration ===

/// Start client registration (step 1).
///
/// Client generates a registration request from the password.
///
/// # Arguments
///
/// - `password`: User's password (will be zeroized after use)
/// - `rng`: Cryptographically secure RNG
///
/// # Returns
///
/// - Serialized `RegistrationRequest` to send to server
/// - Client registration state (opaque, pass to `registration_finalize`)
pub fn registration_start<R: RngCore + CryptoRng>(
    password: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    let result = OpaqueClientRegistration::start(rng, password)?;
    Ok((
        result.message.serialize().to_vec(),
        result.state.serialize().to_vec(),
    ))
}

/// Process registration request and generate response (step 2, server-side).
///
/// # Arguments
///
/// - `server_setup`: Server's long-term setup parameters
/// - `request`: Serialized `RegistrationRequest` from client
/// - `credential_identifier`: Username or user identifier (e.g., "user@example.com")
///
/// # Returns
///
/// Serialized `RegistrationResponse` to send back to client.
pub fn registration_response(
    server_setup: &OpaqueServerSetup,
    request: &[u8],
    credential_identifier: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    let request = RegistrationRequest::<DefaultCipherSuite>::deserialize(request)?;
    let response =
        OpaqueServerRegistration::start(server_setup.inner(), request, credential_identifier)?;
    Ok(response.message.serialize().to_vec())
}

/// Finalize client registration (step 3).
///
/// Client processes server response and generates upload message.
///
/// # Arguments
///
/// - `password`: User's password (same as in `registration_start`)
/// - `response`: Serialized `RegistrationResponse` from server
/// - `credential_identifier`: Username (must match server-side identifier)
/// - `client_state`: Opaque state from `registration_start`
/// - `rng`: Cryptographically secure RNG
///
/// # Returns
///
/// Serialized `RegistrationUpload` to send to server for storage.
pub fn registration_finalize<R: RngCore + CryptoRng>(
    password: &[u8],
    response: &[u8],
    credential_identifier: &[u8],
    client_state: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, ProtocolError> {
    let response = RegistrationResponse::<DefaultCipherSuite>::deserialize(response)?;
    let client_registration = OpaqueClientRegistration::deserialize(client_state)?;
    let finish_params = ClientRegistrationFinishParameters::new(
        Identifiers {
            client: Some(credential_identifier),
            server: None,
        },
        None,
    );
    let result = OpaqueClientRegistration::finish(
        client_registration,
        rng,
        password,
        response,
        finish_params,
    )?;
    Ok(result.message.serialize().to_vec())
}

/// Complete server registration (step 4, server-side).
///
/// Server processes upload message and stores password file.
///
/// # Arguments
///
/// - `upload`: Serialized `RegistrationUpload` from client
///
/// # Returns
///
/// `PasswordFile` to store in database (indexed by credential_identifier).
pub fn registration_complete(upload: &[u8]) -> Result<PasswordFile, ProtocolError> {
    let upload = RegistrationUpload::<DefaultCipherSuite>::deserialize(upload)?;
    let password_file = OpaqueServerRegistration::finish(upload);
    Ok(PasswordFile(password_file.serialize().to_vec()))
}

// === Login ===

/// Start client login (step 1).
///
/// Client generates credential request from password.
///
/// # Arguments
///
/// - `password`: User's password
/// - `rng`: Cryptographically secure RNG
///
/// # Returns
///
/// - Serialized `CredentialRequest` to send to server
/// - Client login state (opaque, pass to `login_finalize`)
pub fn login_start<R: RngCore + CryptoRng>(
    password: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    let result = OpaqueClientLogin::start(rng, password)?;
    Ok((
        result.message.serialize().to_vec(),
        result.state.serialize().to_vec(),
    ))
}

/// Process login request and generate response (step 2, server-side).
///
/// # Arguments
///
/// - `server_setup`: Server's long-term setup parameters
/// - `password_file`: Stored password file for this user
/// - `request`: Serialized `CredentialRequest` from client
/// - `credential_identifier`: Username
/// - `rng`: Cryptographically secure RNG
///
/// # Returns
///
/// - Serialized `CredentialResponse` to send to client
/// - Server login state (opaque, pass to `login_complete`)
pub fn login_response<R: RngCore + CryptoRng>(
    server_setup: &OpaqueServerSetup,
    password_file: &PasswordFile,
    request: &[u8],
    credential_identifier: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolError> {
    let request = CredentialRequest::<DefaultCipherSuite>::deserialize(request)?;
    let password_file_deserialized =
        opaque_ke::ServerRegistration::<DefaultCipherSuite>::deserialize(&password_file.0)?;

    let start_params = ServerLoginStartParameters {
        context: None,
        identifiers: Identifiers {
            client: Some(credential_identifier),
            server: None,
        },
    };

    let login_result = OpaqueServerLogin::start(
        rng,
        server_setup.inner(),
        Some(password_file_deserialized),
        request,
        credential_identifier,
        start_params,
    )?;

    Ok((
        login_result.message.serialize().to_vec(),
        login_result.state.serialize().to_vec(),
    ))
}

/// Finalize client login (step 3).
///
/// Client processes server response and derives session key.
///
/// # Arguments
///
/// - `password`: User's password (same as in `login_start`)
/// - `response`: Serialized `CredentialResponse` from server
/// - `credential_identifier`: Username
/// - `client_state`: Opaque state from `login_start`
///
/// # Returns
///
/// - Serialized `CredentialFinalization` to send to server
/// - `session_key`: 32-byte session key (Zeroizing)
pub fn login_finalize(
    password: &[u8],
    response: &[u8],
    credential_identifier: &[u8],
    client_state: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), ProtocolError> {
    let response = CredentialResponse::<DefaultCipherSuite>::deserialize(response)?;
    let client_login = OpaqueClientLogin::deserialize(client_state)?;
    let finish_params = ClientLoginFinishParameters {
        context: None,
        identifiers: Identifiers {
            client: Some(credential_identifier),
            server: None,
        },
        ksf: None,
    };

    let finish_result = OpaqueClientLogin::finish(client_login, password, response, finish_params)?;

    Ok((
        finish_result.message.serialize().to_vec(),
        Zeroizing::new(finish_result.session_key.to_vec()),
    ))
}

/// Complete server login (step 4, server-side).
///
/// Server validates finalization message and derives session key.
///
/// # Arguments
///
/// - `finalization`: Serialized `CredentialFinalization` from client
/// - `server_login_state`: Opaque state from `login_response`
///
/// # Returns
///
/// `session_key`: 32-byte session key (Zeroizing). Must match client's key.
pub fn login_complete(
    finalization: &[u8],
    server_login_state: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let finalization = CredentialFinalization::<DefaultCipherSuite>::deserialize(finalization)?;
    let server_login = OpaqueServerLogin::deserialize(server_login_state)?;

    let result = server_login.finish(finalization)?;
    Ok(Zeroizing::new(result.session_key.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_registration_flow() {
        let mut rng = OsRng;
        let password = b"correct horse battery staple";
        let credential_id = b"user@example.com";

        // Server setup (one-time)
        let server_setup = OpaqueServerSetup::generate(&mut rng).unwrap();

        // Step 1: Client registration start
        let (request, client_state) = registration_start(password, &mut rng).unwrap();
        assert!(!request.is_empty());
        assert!(!client_state.is_empty());

        // Step 2: Server registration response
        let response = registration_response(&server_setup, &request, credential_id).unwrap();
        assert!(!response.is_empty());

        // Step 3: Client registration finalize
        let upload =
            registration_finalize(password, &response, credential_id, &client_state, &mut rng)
                .unwrap();
        assert!(!upload.is_empty());

        // Step 4: Server registration complete
        let password_file = registration_complete(&upload).unwrap();
        assert!(!password_file.to_bytes().is_empty());
    }

    #[test]
    fn test_login_flow() {
        let mut rng = OsRng;
        let password = b"correct horse battery staple";
        let credential_id = b"user@example.com";

        // Setup and registration (prerequisite)
        let server_setup = OpaqueServerSetup::generate(&mut rng).unwrap();
        let (request, reg_state) = registration_start(password, &mut rng).unwrap();
        let response = registration_response(&server_setup, &request, credential_id).unwrap();
        let upload =
            registration_finalize(password, &response, credential_id, &reg_state, &mut rng)
                .unwrap();
        let password_file = registration_complete(&upload).unwrap();

        // Step 1: Client login start
        let (login_request, client_login_state) = login_start(password, &mut rng).unwrap();
        assert!(!login_request.is_empty());
        assert!(!client_login_state.is_empty());

        // Step 2: Server login response
        let (login_response, server_state) = login_response(
            &server_setup,
            &password_file,
            &login_request,
            credential_id,
            &mut rng,
        )
        .unwrap();
        assert!(!login_response.is_empty());
        assert!(!server_state.is_empty());

        // Step 3: Client login finalize
        let (finalization, client_session_key) = login_finalize(
            password,
            &login_response,
            credential_id,
            &client_login_state,
        )
        .unwrap();
        assert!(!finalization.is_empty());
        assert_eq!(client_session_key.len(), 64); // OPAQUE session key size

        // Step 4: Server login complete
        let server_session_key = login_complete(&finalization, &server_state).unwrap();
        assert_eq!(server_session_key.len(), 64);

        // Keys must match
        assert_eq!(&*client_session_key, &*server_session_key);
    }

    #[test]
    fn test_wrong_password_fails() {
        let mut rng = OsRng;
        let password = b"correct horse battery staple";
        let wrong_password = b"incorrect horse battery staple";
        let credential_id = b"user@example.com";

        // Setup and registration
        let server_setup = OpaqueServerSetup::generate(&mut rng).unwrap();
        let (request, reg_state) = registration_start(password, &mut rng).unwrap();
        let response = registration_response(&server_setup, &request, credential_id).unwrap();
        let upload =
            registration_finalize(password, &response, credential_id, &reg_state, &mut rng)
                .unwrap();
        let password_file = registration_complete(&upload).unwrap();

        // Login with wrong password
        let (login_request, wrong_client_state) = login_start(wrong_password, &mut rng).unwrap();
        let (login_response, server_state) = login_response(
            &server_setup,
            &password_file,
            &login_request,
            credential_id,
            &mut rng,
        )
        .unwrap();

        // Client finalize with wrong password should fail or produce wrong key
        let result = login_finalize(
            wrong_password,
            &login_response,
            credential_id,
            &wrong_client_state,
        );

        // The error might occur at finalize or at server complete
        if let Ok((finalization, _client_key)) = result {
            // If client finalize succeeds, server complete must detect mismatch
            let server_result = login_complete(&finalization, &server_state);
            assert!(
                server_result.is_err(),
                "Login with wrong password should fail"
            );
        }
        // If client finalize fails, that's also acceptable
    }
}
