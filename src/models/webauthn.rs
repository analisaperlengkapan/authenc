use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// WebAuthn credential model for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnCredential {
    /// Unique identifier for the WebAuthn credential
    pub id: Uuid,
    /// ID of the user this credential belongs to
    pub user_id: Uuid,
    /// The credential ID from the authenticator
    pub credential_id: Vec<u8>,
    /// The public key for the credential
    pub public_key: Vec<u8>,
    /// The algorithm used for the public key
    pub public_key_algorithm: i32,
    /// Signature counter to prevent replay attacks
    pub signature_counter: u32,
    /// Attestation object from registration
    pub attestation_object: Option<Vec<u8>>,
    /// Authenticator data from registration
    pub authenticator_data: Option<Vec<u8>>,
    /// User handle from the authenticator
    pub user_handle: Option<Vec<u8>>,
    /// Type of the credential
    pub credential_type: String,
    /// Supported transports for the credential
    pub transports: Option<Vec<String>>,
    /// Authenticator AAGUID (Authenticator Attestation Global Unique Identifier)
    pub aaguid: Option<Vec<u8>>,
    /// Attestation format used
    pub attestation_format: Option<String>,
    /// ID of the device this credential is bound to
    pub device_id: Option<Uuid>,
    /// Timestamp when the credential was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the credential was last used
    pub last_used_at: Option<DateTime<Utc>>,
    /// Whether this credential is enabled
    pub enabled: bool,
}

/// WebAuthn registration challenge for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnRegistrationChallenge {
    /// Unique identifier for the registration challenge
    pub id: Uuid,
    /// ID of the user attempting registration
    pub user_id: Uuid,
    /// The challenge bytes sent to the authenticator
    pub challenge: Vec<u8>,
    /// Relying party identifier
    pub relying_party_id: String,
    /// Human-readable relying party name
    pub relying_party_name: String,
    /// Username for the WebAuthn user
    pub user_name: String,
    /// Display name for the WebAuthn user
    pub user_display_name: Option<String>,
    /// User ID bytes for the WebAuthn user
    pub user_id_bytes: Vec<u8>,
    /// Supported public key credential parameters
    pub public_key_credential_parameters: Vec<WebauthnPublicKeyCredentialParameter>,
    /// Authenticator selection criteria
    pub authenticator_selection: Option<WebauthnAuthenticatorSelection>,
    /// Attestation conveyance preference
    pub attestation: Option<String>,
    /// Timeout for the registration operation
    pub timeout: Option<u32>,
    /// Credentials to exclude from registration
    pub exclude_credentials: Vec<WebauthnCredentialDescriptor>,
    /// WebAuthn extensions
    pub extensions: Option<serde_json::Value>,
    /// Timestamp when the challenge was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the challenge expires
    pub expires_at: DateTime<Utc>,
}

/// WebAuthn authentication challenge for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnAuthenticationChallenge {
    /// Unique identifier for the authentication challenge
    pub id: Uuid,
    /// ID of the user attempting authentication (optional for discoverable credentials)
    pub user_id: Option<Uuid>,
    /// The challenge bytes sent to the authenticator
    pub challenge: Vec<u8>,
    /// Relying party identifier
    pub relying_party_id: String,
    /// List of allowed credentials for authentication
    pub allow_credentials: Vec<WebauthnCredentialDescriptor>,
    /// User verification requirement
    pub user_verification: Option<String>,
    /// Timeout for the authentication operation
    pub timeout: Option<u32>,
    /// WebAuthn extensions
    pub extensions: Option<serde_json::Value>,
    /// Timestamp when the challenge was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the challenge expires
    pub expires_at: DateTime<Utc>,
}

/// WebAuthn public key credential parameter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnPublicKeyCredentialParameter {
    /// Type of the credential (usually "public-key")
    pub ty: String,
    /// Cryptographic algorithm identifier
    pub alg: i32,
}

/// WebAuthn authenticator selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnAuthenticatorSelection {
    /// Preferred authenticator attachment modality
    pub authenticator_attachment: Option<String>,
    /// Whether a resident key is required on the authenticator
    pub require_resident_key: bool,
    /// User verification requirement for the authenticator
    pub user_verification: String,
}

/// WebAuthn credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnCredentialDescriptor {
    /// Type of the credential descriptor (usually "public-key")
    pub ty: String,
    /// Credential ID bytes
    pub id: Vec<u8>,
    /// Supported transports for the credential
    pub transports: Option<Vec<String>>,
}

/// WebAuthn registration response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnRegistrationResponse {
    /// Base64url encoded credential ID
    pub id: String,
    /// Raw credential ID bytes
    pub raw_id: Vec<u8>,
    /// Authenticator response containing attestation data
    pub response: WebauthnAuthenticatorAttestationResponse,
    /// Type of the credential (usually "public-key")
    pub ty: String,
    /// Client extensions used during registration
    pub extensions: Option<serde_json::Value>,
}

/// WebAuthn authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnAuthenticationResponse {
    /// Base64url encoded credential ID
    pub id: String,
    /// Raw credential ID bytes
    pub raw_id: Vec<u8>,
    /// Authenticator response containing assertion data
    pub response: WebauthnAuthenticatorAssertionResponse,
    /// Type of the credential (usually "public-key")
    pub ty: String,
    /// Client extensions used during authentication
    pub extensions: Option<serde_json::Value>,
}

/// WebAuthn authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnAuthenticatorAttestationResponse {
    /// JSON-serialized client data from the browser
    pub client_data_json: Vec<u8>,
    /// CBOR-encoded attestation object from the authenticator
    pub attestation_object: Vec<u8>,
}

/// WebAuthn authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnAuthenticatorAssertionResponse {
    /// JSON-serialized client data from the browser
    pub client_data_json: Vec<u8>,
    /// CBOR-encoded authenticator data from the authenticator
    pub authenticator_data: Vec<u8>,
    /// Cryptographic signature over the data
    pub signature: Vec<u8>,
    /// User handle if available (for discoverable credentials)
    pub user_handle: Option<Vec<u8>>,
}

/// WebAuthn session data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnSessionData {
    /// The challenge bytes for the WebAuthn operation
    pub challenge: Vec<u8>,
    /// ID of the user (if known)
    pub user_id: Option<Uuid>,
    /// Relying party identifier
    pub relying_party_id: String,
    /// Origin of the request
    pub origin: String,
    /// Type of WebAuthn session (registration or authentication)
    pub session_type: WebauthnSessionType,
    /// Timestamp when the session was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the session expires
    pub expires_at: DateTime<Utc>,
}

/// WebAuthn session type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WebauthnSessionType {
    /// Session for registering a new WebAuthn credential
    Registration,
    /// Session for authenticating with an existing WebAuthn credential
    Authentication,
}

/// WebAuthn policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebauthnPolicy {
    /// Unique identifier for the policy
    pub id: Uuid,
    /// ID of the realm this policy belongs to
    pub realm_id: Option<Uuid>,
    /// List of acceptable signature algorithms
    pub signature_algorithms: Vec<i32>,
    /// Attestation conveyance preference
    pub attestation_conveyance_preference: String,
    /// Preferred authenticator attachment
    pub authenticator_attachment: Option<String>,
    /// Whether resident keys are required
    pub require_resident_key: bool,
    /// User verification requirement
    pub user_verification_requirement: String,
    /// Timeout for credential creation
    pub create_timeout: u32,
    /// Whether to avoid registering the same authenticator multiple times
    pub avoid_same_authenticator_register: bool,
    /// List of acceptable authenticator AAGUIDs
    pub acceptable_aaguids: Option<Vec<String>>,
    /// Whether this policy is enabled
    pub enabled: bool,
    /// Timestamp when the policy was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the policy was last updated
    pub updated_at: DateTime<Utc>,
}

// Legacy structs for backward compatibility
/// WebAuthn credential representation (legacy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredentialLegacy {
    /// Base64url encoded credential ID
    pub id: String,
    /// Public key bytes for the credential
    pub public_key: Vec<u8>,
    /// Signature counter to prevent replay attacks
    pub sign_count: u32,
    /// User handle from the authenticator
    pub user_handle: Vec<u8>,
    /// Type of the credential
    pub credential_type: String,
    /// Supported transports for the credential
    pub transports: Vec<String>,
}

/// WebAuthn registration options (standard format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnRegistrationOptions {
    /// Base64url encoded challenge bytes
    pub challenge: String,
    /// Relying party information
    pub rp: RelyingParty,
    /// User information
    pub user: WebAuthnUser,
    /// Supported public key credential parameters
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    /// Authenticator selection criteria
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    /// Timeout in milliseconds
    pub timeout: Option<u32>,
    /// List of credentials to exclude
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    /// Attestation conveyance preference
    pub attestation: Option<String>,
    /// WebAuthn extensions
    pub extensions: Option<serde_json::Value>,
}
/// Relying party information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingParty {
    /// Unique identifier for the relying party
    pub id: String,
    /// Human-readable name of the relying party
    pub name: String,
}

/// WebAuthn user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnUser {
    /// User ID bytes
    pub id: Vec<u8>,
    /// Username for the WebAuthn user
    pub name: String,
    /// Display name for the WebAuthn user
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyCredParam {
    /// Cryptographic algorithm identifier
    pub alg: i32,
    /// Type of the credential (usually "public-key")
    pub typ: String,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    /// Preferred authenticator attachment modality
    pub authenticator_attachment: Option<String>,
    /// Whether a resident key is required
    pub require_resident_key: Option<bool>,
    /// User verification requirement
    pub user_verification: Option<String>,
}

/// WebAuthn authentication challenge (legacy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationChallengeLegacy {
    /// Base64url encoded challenge bytes
    pub challenge: String,
    /// List of allowed credentials for authentication
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    /// User verification requirement
    pub user_verification: Option<String>,
    /// WebAuthn extensions
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    /// Credential ID bytes
    pub id: Vec<u8>,
    /// Type of the credential descriptor (usually "public-key")
    pub typ: String,
    /// Supported transports for the credential
    pub transports: Option<Vec<String>>,
}

/// WebAuthn registration response (legacy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnRegistrationResponseLegacy {
    /// Base64url encoded credential ID
    pub id: String,
    /// Raw credential ID bytes
    pub raw_id: Vec<u8>,
    /// Authenticator response containing attestation data
    pub response: AuthenticatorAttestationResponse,
    /// Type of the credential (usually "public-key")
    pub typ: String,
}

/// Authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAttestationResponse {
    /// JSON-serialized client data from the browser
    pub client_data_json: Vec<u8>,
    /// CBOR-encoded attestation object from the authenticator
    pub attestation_object: Vec<u8>,
}

/// WebAuthn authentication response (legacy)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationResponseLegacy {
    /// Base64url encoded credential ID
    pub id: String,
    /// Raw credential ID bytes
    pub raw_id: Vec<u8>,
    /// Authenticator response containing assertion data
    pub response: AuthenticatorAssertionResponse,
    /// Type of the credential (usually "public-key")
    pub typ: String,
}

/// Authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAssertionResponse {
    /// JSON-serialized client data from the browser
    pub client_data_json: Vec<u8>,
    /// CBOR-encoded authenticator data from the authenticator
    pub authenticator_data: Vec<u8>,
    /// Cryptographic signature over the data
    pub signature: Vec<u8>,
    /// User handle if available (for discoverable credentials)
    pub user_handle: Option<Vec<u8>>,
}
