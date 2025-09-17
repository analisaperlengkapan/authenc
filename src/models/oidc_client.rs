use serde::{Deserialize, Serialize};

/// OIDC client configuration for OAuth 2.0 and OpenID Connect authentication flows.
///
/// This struct represents an OAuth 2.0 client that can participate in OIDC authentication
/// flows with the authorization server. It contains the necessary configuration for
/// client authentication, redirection, and client identification.
///
/// # Fields
/// * `id` - Unique internal identifier for the client
/// * `client_id` - OAuth 2.0 client identifier (public)
/// * `client_secret` - OAuth 2.0 client secret for confidential clients
/// * `redirect_uris` - Allowed redirect URIs for authorization responses
/// * `name` - Human-readable display name for the client
/// * `enabled` - Whether the client is enabled for authentication
///
/// # Security Considerations
/// - Client secrets should be stored securely and never exposed in logs
/// - Redirect URIs should be validated to prevent open redirect attacks
/// - Client IDs should be unique and not guessable
/// - Disabled clients should not be able to authenticate users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClient {
    /// Unique internal identifier for the OIDC client (UUID or similar)
    pub id: String,
    /// OAuth 2.0 client identifier used in authentication requests
    pub client_id: String,
    /// OAuth 2.0 client secret for confidential client authentication
    pub client_secret: String,
    /// List of allowed redirect URIs for authorization code flow responses
    pub redirect_uris: Vec<String>,
    /// Human-readable display name for the client application
    pub name: String,
    /// Flag indicating whether the client is enabled for authentication
    pub enabled: bool,
}
