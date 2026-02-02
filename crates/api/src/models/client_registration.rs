use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Client Registration Request (RFC 7591)
/// Parameters for registering a new OAuth 2.0 client dynamically
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistrationRequest {
    /// Array of redirection URIs for use in redirect-based flows
    pub redirect_uris: Vec<String>,

    /// Array of OAuth 2.0 response type values that the client will use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<String>>,

    /// Array of OAuth 2.0 grant type values that the client will use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,

    /// Kind of the application (web, native)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,

    /// Array of e-mail addresses of people responsible for this client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,

    /// Name of the client to be presented to the end-user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    /// URL that references a logo for the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,

    /// URL of the home page of the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,

    /// URL that the authorization server can call to determine the client's policy
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,

    /// URL that the authorization server can call to determine the client's terms of service
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,

    /// URL for the authorization server's metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// Client's JSON Web Key Set document
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,

    /// URI using the https scheme that the authorization server can call
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sector_identifier_uri: Option<String>,

    /// Subject type requested for responses to this client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,

    /// JWS algorithm required for signing the ID Token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,

    /// JWE algorithm required for encrypting the ID Token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_alg: Option<String>,

    /// JWE algorithm required for encrypting the ID Token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_enc: Option<String>,

    /// JWS algorithm required for signing UserInfo Responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<String>,

    /// JWE algorithm required for encrypting UserInfo Responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_alg: Option<String>,

    /// JWE algorithm required for encrypting UserInfo Responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_enc: Option<String>,

    /// JWS algorithm required for signing authorization responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<String>,

    /// JWE algorithm required for encrypting authorization responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg: Option<String>,

    /// JWE algorithm required for encrypting authorization responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc: Option<String>,

    /// Requested authentication method for the token endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,

    /// JWS algorithm required for signing the JWT used to authenticate the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,

    /// Default maximum authentication age
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_max_age: Option<i32>,

    /// Boolean value specifying whether the auth_time claim in the ID Token is required
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_auth_time: Option<bool>,

    /// Default requested Authentication Context Class Reference values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_acr_values: Option<Vec<String>>,

    /// URI using the https scheme that the authorization server can call
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiate_login_uri: Option<String>,

    /// Array of request URIs that are pre-registered
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uris: Option<Vec<String>>,

    /// Additional client metadata as extension
    #[serde(flatten)]
    pub additional_metadata: HashMap<String, serde_json::Value>,
}

/// Client Registration Response (RFC 7591)
/// Response containing the registered client information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistrationResponse {
    /// OAuth 2.0 client identifier string
    pub client_id: String,

    /// Time at which the client identifier was issued
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id_issued_at: Option<i64>,

    /// OAuth 2.0 client secret string
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    /// Time at which the client secret will expire
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,

    /// Array of redirection URIs for use in redirect-based flows
    pub redirect_uris: Vec<String>,

    /// Array of OAuth 2.0 response type values that the client will use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<String>>,

    /// Array of OAuth 2.0 grant type values that the client will use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,

    /// Kind of the application (web, native)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,

    /// Array of e-mail addresses of people responsible for this client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,

    /// Name of the client to be presented to the end-user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    /// URL that references a logo for the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,

    /// URL of the home page of the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,

    /// URL that the authorization server can call to determine the client's policy
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,

    /// URL that the authorization server can call to determine the client's terms of service
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,

    /// URL for the authorization server's metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// Client's JSON Web Key Set document
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,

    /// URI using the https scheme that the authorization server can call
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sector_identifier_uri: Option<String>,

    /// Subject type requested for responses to this client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,

    /// JWS algorithm required for signing the ID Token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,

    /// JWE algorithm required for encrypting the ID Token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_alg: Option<String>,

    /// JWE algorithm required for encrypting the ID Token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_enc: Option<String>,

    /// JWS algorithm required for signing UserInfo Responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<String>,

    /// JWE algorithm required for encrypting UserInfo Responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_alg: Option<String>,

    /// JWE algorithm required for encrypting UserInfo Responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_enc: Option<String>,

    /// JWS algorithm required for signing authorization responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<String>,

    /// JWE algorithm required for encrypting authorization responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg: Option<String>,

    /// JWE algorithm required for encrypting authorization responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc: Option<String>,

    /// Requested authentication method for the token endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,

    /// JWS algorithm required for signing the JWT used to authenticate the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,

    /// Default maximum authentication age
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_max_age: Option<i32>,

    /// Boolean value specifying whether the auth_time claim in the ID Token is required
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_auth_time: Option<bool>,

    /// Default requested Authentication Context Class Reference values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_acr_values: Option<Vec<String>>,

    /// URI using the https scheme that the authorization server can call
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiate_login_uri: Option<String>,

    /// Array of request URIs that are pre-registered
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uris: Option<Vec<String>>,

    /// Registration access token for managing this client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,

    /// Registration client URI for managing this client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_client_uri: Option<String>,

    /// Additional client metadata as extension
    #[serde(flatten)]
    pub additional_metadata: HashMap<String, serde_json::Value>,
}

/// Client Update Request (RFC 7592)
/// Parameters for updating a registered client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientUpdateRequest {
    /// Array of redirection URIs for use in redirect-based flows
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uris: Option<Vec<String>>,

    /// Array of OAuth 2.0 response type values that the client will use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_types: Option<Vec<String>>,

    /// Array of OAuth 2.0 grant type values that the client will use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_types: Option<Vec<String>>,

    /// Kind of the application (web, native)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,

    /// Array of e-mail addresses of people responsible for this client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contacts: Option<Vec<String>>,

    /// Name of the client to be presented to the end-user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    /// URL that references a logo for the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,

    /// URL of the home page of the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,

    /// URL that the authorization server can call to determine the client's policy
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,

    /// URL that the authorization server can call to determine the client's terms of service
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,

    /// URL for the authorization server's metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// Client's JSON Web Key Set document
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,

    /// URI using the https scheme that the authorization server can call
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sector_identifier_uri: Option<String>,

    /// Subject type requested for responses to this client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,

    /// JWS algorithm required for signing the ID Token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_signed_response_alg: Option<String>,

    /// JWE algorithm required for encrypting the ID Token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_alg: Option<String>,

    /// JWE algorithm required for encrypting the ID Token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_encrypted_response_enc: Option<String>,

    /// JWS algorithm required for signing UserInfo Responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_signed_response_alg: Option<String>,

    /// JWE algorithm required for encrypting UserInfo Responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_alg: Option<String>,

    /// JWE algorithm required for encrypting UserInfo Responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userinfo_encrypted_response_enc: Option<String>,

    /// JWS algorithm required for signing authorization responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_signing_alg: Option<String>,

    /// JWE algorithm required for encrypting authorization responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_alg: Option<String>,

    /// JWE algorithm required for encrypting authorization responses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_object_encryption_enc: Option<String>,

    /// Requested authentication method for the token endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,

    /// JWS algorithm required for signing the JWT used to authenticate the client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_signing_alg: Option<String>,

    /// Default maximum authentication age
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_max_age: Option<i32>,

    /// Boolean value specifying whether the auth_time claim in the ID Token is required
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_auth_time: Option<bool>,

    /// Default requested Authentication Context Class Reference values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_acr_values: Option<Vec<String>>,

    /// URI using the https scheme that the authorization server can call
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiate_login_uri: Option<String>,

    /// Array of request URIs that are pre-registered
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uris: Option<Vec<String>>,

    /// Additional client metadata as extension
    #[serde(flatten)]
    pub additional_metadata: HashMap<String, serde_json::Value>,
}

/// Software Statement (RFC 7591)
/// JWT containing client metadata signed by a trusted party
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareStatement {
    /// Software identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_id: Option<String>,

    /// Version of the software
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,

    /// Client metadata claims
    #[serde(flatten)]
    pub client_metadata: HashMap<String, serde_json::Value>,
}

/// Client Registration Error Response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistrationError {
    /// Error code
    pub error: String,

    /// Human-readable description of the error
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}
