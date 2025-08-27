use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// WebAuthn credential representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    pub id: String,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub user_handle: Vec<u8>,
    pub credential_type: String,
    pub transports: Vec<String>,
}

/// WebAuthn registration challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnRegistrationChallenge {
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

/// WebAuthn authentication challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationChallenge {
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

/// WebAuthn registration response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnRegistrationResponse {
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

/// WebAuthn authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationResponse {
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
