use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// WebAuthn credential model for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnCredential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub public_key_algorithm: i32,
    pub signature_counter: u32,
    pub attestation_object: Option<Vec<u8>>,
    pub authenticator_data: Option<Vec<u8>>,
    pub user_handle: Option<Vec<u8>>,
    pub credential_type: String,
    pub transports: Option<Vec<String>>,
    pub aaguid: Option<Vec<u8>>,
    pub attestation_format: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub enabled: bool,
}

/// WebAuthn registration challenge for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnRegistrationChallenge {
    pub id: Uuid,
    pub user_id: Uuid,
    pub challenge: Vec<u8>,
    pub relying_party_id: String,
    pub relying_party_name: String,
    pub user_name: String,
    pub user_display_name: Option<String>,
    pub user_id_bytes: Vec<u8>,
    pub public_key_credential_parameters: Vec<WebauthnPublicKeyCredentialParameter>,
    pub authenticator_selection: Option<WebauthnAuthenticatorSelection>,
    pub attestation: Option<String>,
    pub timeout: Option<u32>,
    pub exclude_credentials: Vec<WebauthnCredentialDescriptor>,
    pub extensions: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// WebAuthn authentication challenge for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnAuthenticationChallenge {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub challenge: Vec<u8>,
    pub relying_party_id: String,
    pub allow_credentials: Vec<WebauthnCredentialDescriptor>,
    pub user_verification: Option<String>,
    pub timeout: Option<u32>,
    pub extensions: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// WebAuthn public key credential parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnPublicKeyCredentialParameter {
    pub ty: String,
    pub alg: i32,
}

/// WebAuthn authenticator selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnAuthenticatorSelection {
    pub authenticator_attachment: Option<String>,
    pub require_resident_key: bool,
    pub user_verification: String,
}

/// WebAuthn credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnCredentialDescriptor {
    pub ty: String,
    pub id: Vec<u8>,
    pub transports: Option<Vec<String>>,
}

/// WebAuthn registration response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnRegistrationResponse {
    pub id: String,
    pub raw_id: Vec<u8>,
    pub response: WebauthnAuthenticatorAttestationResponse,
    pub ty: String,
    pub extensions: Option<serde_json::Value>,
}

/// WebAuthn authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnAuthenticationResponse {
    pub id: String,
    pub raw_id: Vec<u8>,
    pub response: WebauthnAuthenticatorAssertionResponse,
    pub ty: String,
    pub extensions: Option<serde_json::Value>,
}

/// WebAuthn authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnAuthenticatorAttestationResponse {
    pub client_data_json: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

/// WebAuthn authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnAuthenticatorAssertionResponse {
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
}

/// WebAuthn session data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnSessionData {
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub relying_party_id: String,
    pub origin: String,
    pub session_type: WebauthnSessionType,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// WebAuthn session type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebauthnSessionType {
    Registration,
    Authentication,
}

/// WebAuthn policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnPolicy {
    pub id: Uuid,
    pub realm_id: Option<Uuid>,
    pub signature_algorithms: Vec<i32>,
    pub attestation_conveyance_preference: String,
    pub authenticator_attachment: Option<String>,
    pub require_resident_key: bool,
    pub user_verification_requirement: String,
    pub create_timeout: u32,
    pub avoid_same_authenticator_register: bool,
    pub acceptable_aaguids: Option<Vec<String>>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Legacy structs for backward compatibility
/// WebAuthn credential representation (legacy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredentialLegacy {
    pub id: String,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub user_handle: Vec<u8>,
    pub credential_type: String,
    pub transports: Vec<String>,
}

/// WebAuthn registration challenge (legacy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnRegistrationChallengeLegacy {
    pub challenge: String,
    pub rp: RelyingParty,
    pub user: WebAuthnUser,
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Relying party information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingParty {
    pub id: String,
    pub name: String,
}

/// WebAuthn user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnUser {
    pub id: Vec<u8>,
    pub name: String,
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyCredParam {
    pub alg: i32,
    pub typ: String,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    pub authenticator_attachment: Option<String>,
    pub require_resident_key: Option<bool>,
    pub user_verification: Option<String>,
}

/// WebAuthn authentication challenge (legacy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationChallengeLegacy {
    pub challenge: String,
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    pub user_verification: Option<String>,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    pub id: Vec<u8>,
    pub typ: String,
    pub transports: Option<Vec<String>>,
}

/// WebAuthn registration response (legacy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnRegistrationResponseLegacy {
    pub id: String,
    pub raw_id: Vec<u8>,
    pub response: AuthenticatorAttestationResponse,
    pub typ: String,
}

/// Authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

/// WebAuthn authentication response (legacy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationResponseLegacy {
    pub id: String,
    pub raw_id: Vec<u8>,
    pub response: AuthenticatorAssertionResponse,
    pub typ: String,
}

/// Authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAssertionResponse {
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
}
