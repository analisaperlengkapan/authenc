use authenc_core::error::AuthencError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// OAuth2 client model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Client {
    /// Unique identifier for the OAuth2 client
    pub id: Uuid,
    /// The client identifier used in OAuth2 flows
    pub client_id: String,
    /// Hashed client secret for authentication
    pub client_secret_hash: String,
    /// Human-readable name of the client
    pub client_name: String,
    /// Type of client (confidential or public)
    pub client_type: String,
    /// Allowed redirect URIs for authorization responses
    pub redirect_uris: Vec<String>,
    /// OAuth2 scopes the client is allowed to request
    pub scopes: Vec<String>,
    /// Supported OAuth2 grant types
    pub grant_types: Vec<String>,
    /// Supported OAuth2 response types
    pub response_types: Vec<String>,
    /// Authentication method for token endpoint
    pub token_endpoint_auth_method: String,
    /// ID of the user who owns this client
    pub owner_id: Option<Uuid>,
    /// ID of the realm this client belongs to
    pub realm_id: Option<Uuid>,
    /// Whether the client is enabled
    pub enabled: bool,
    /// Timestamp when the client was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the client was last updated
    pub updated_at: DateTime<Utc>,
    /// Timestamp when the client was deleted (soft delete)
    pub deleted_at: Option<DateTime<Utc>>,
}

/// OAuth2 authorization code model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2AuthorizationCode {
    /// Unique identifier for the authorization code
    pub id: Uuid,
    /// The authorization code value
    pub code: String,
    /// ID of the client that requested the code
    pub client_id: Uuid,
    /// ID of the user who authorized the code
    pub user_id: Uuid,
    /// Redirect URI used in the authorization request
    pub redirect_uri: String,
    /// OAuth2 scopes granted in the authorization
    pub scopes: Vec<String>,
    /// PKCE code challenge for security
    pub code_challenge: Option<String>,
    /// PKCE code challenge method (S256 or plain)
    pub code_challenge_method: Option<String>,
    /// Expiration timestamp of the code
    pub expires_at: DateTime<Utc>,
    /// Whether the code has been used
    pub used: bool,
    /// Timestamp when the code was created
    pub created_at: DateTime<Utc>,
}

/// OAuth2 access token model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2AccessToken {
    /// Unique identifier for the access token
    pub id: Uuid,
    /// Hashed access token value
    pub token_hash: String,
    /// Hashed refresh token value (if issued)
    pub refresh_token_hash: Option<String>,
    /// ID of the client that requested the token
    pub client_id: Uuid,
    /// ID of the user the token was issued for
    pub user_id: Option<Uuid>,
    /// OAuth2 scopes granted in the token
    pub scopes: Vec<String>,
    /// Expiration timestamp of the access token
    pub expires_at: DateTime<Utc>,
    /// Expiration timestamp of the refresh token
    pub refresh_expires_at: Option<DateTime<Utc>>,
    /// Whether the token has been revoked
    pub revoked: bool,
    /// Timestamp when the token was revoked
    pub revoked_at: Option<DateTime<Utc>>,
    /// Timestamp when the token was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the token was last used
    pub last_used_at: Option<DateTime<Utc>>,
    /// Session identifier (if bound to a session)
    pub session_id: Option<String>,
}

/// OAuth2 client creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOAuth2ClientRequest {
    /// Human-readable name for the new client
    pub client_name: String,
    /// Type of client (confidential or public)
    pub client_type: String,
    /// Allowed redirect URIs for the client
    pub redirect_uris: Vec<String>,
    /// OAuth2 scopes the client can request
    pub scopes: Vec<String>,
    /// Supported OAuth2 grant types
    pub grant_types: Vec<String>,
    /// Supported OAuth2 response types
    pub response_types: Vec<String>,
    /// Authentication method for token endpoint (optional)
    pub token_endpoint_auth_method: Option<String>,
}

/// OAuth2 authorization request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2AuthorizeRequest {
    /// The response type requested (code, token, id_token)
    pub response_type: String,
    /// The client identifier
    pub client_id: String,
    /// The redirect URI for the authorization response
    pub redirect_uri: Option<String>,
    /// The requested OAuth2 scope
    pub scope: Option<String>,
    /// Opaque value for state maintenance
    pub state: Option<String>,
    /// PKCE code challenge for security
    pub code_challenge: Option<String>,
    /// PKCE code challenge method (S256 or plain)
    pub code_challenge_method: Option<String>,
    /// Nonce for replay attack protection
    pub nonce: Option<String>,
    /// Prompt parameter to force re-authentication
    pub prompt: Option<String>,
    /// Maximum authentication age in seconds
    pub max_age: Option<i64>,
}

/// OAuth2 token request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2TokenRequest {
    /// The OAuth2 grant type
    pub grant_type: String,
    /// Authorization code for authorization_code grant
    pub code: Option<String>,
    /// Redirect URI used in authorization request
    pub redirect_uri: Option<String>,
    /// Client identifier
    pub client_id: Option<String>,
    /// Client secret for confidential clients
    pub client_secret: Option<String>,
    /// PKCE code verifier
    pub code_verifier: Option<String>,
    /// Refresh token for refresh_token grant
    pub refresh_token: Option<String>,
    /// Requested scope (subset of authorized scope)
    pub scope: Option<String>,
    /// Username for password grant
    pub username: Option<String>,
    /// Password for password grant
    pub password: Option<String>,
}

/// OAuth2 token response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2TokenResponse {
    /// The access token issued to the client
    pub access_token: String,
    /// The type of the token (usually "Bearer")
    pub token_type: String,
    /// The lifetime of the access token in seconds
    pub expires_in: i64,
    /// The refresh token (if issued)
    pub refresh_token: Option<String>,
    /// The scope of the access token
    pub scope: Option<String>,
    /// The ID token for OpenID Connect flows
    pub id_token: Option<String>,
}

/// Access Token Claims for JWT
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessTokenClaims {
    /// The issuer of the token
    pub iss: String,
    /// The subject (user) identifier
    pub sub: String,
    /// The audience (client) identifier
    pub aud: String,
    /// The client identifier
    pub client_id: String,
    /// The expiration time
    pub exp: i64,
    /// The issued at time
    pub iat: i64,
    /// The not before time
    pub nbf: i64,
    /// The JWT ID for uniqueness
    pub jti: String,
    /// The granted scope
    pub scope: Option<String>,
    /// The user's roles
    pub roles: Option<Vec<String>>,
    /// The user's groups
    pub groups: Option<Vec<String>>,
    /// The session identifier
    pub sid: Option<String>,
}

use authenc_core::error::Result;

/// Converts a PostgreSQL database row into an OAuth2Client instance
///
/// This implementation extracts all OAuth2Client fields from a database row
/// and constructs a new OAuth2Client struct. All fields are required in the row.
impl TryFrom<tokio_postgres::Row> for OAuth2Client {
    type Error = AuthencError;

    fn try_from(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            client_id: row.try_get("client_id")?,
            client_secret_hash: row.try_get("client_secret_hash")?,
            client_name: row.try_get("client_name")?,
            client_type: row.try_get("client_type")?,
            redirect_uris: row.try_get("redirect_uris")?,
            scopes: row.try_get("scopes")?,
            grant_types: row.try_get("grant_types")?,
            response_types: row.try_get("response_types")?,
            token_endpoint_auth_method: row.try_get("token_endpoint_auth_method")?,
            owner_id: row.try_get("owner_id")?,
            realm_id: row.try_get("realm_id")?,
            enabled: row.try_get("enabled")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            deleted_at: row.try_get("deleted_at")?,
        })
    }
}

/// Converts a PostgreSQL database row into an OAuth2AuthorizationCode instance
///
/// This implementation extracts all OAuth2AuthorizationCode fields from a database row
/// and constructs a new OAuth2AuthorizationCode struct. All fields are required in the row.
impl TryFrom<tokio_postgres::Row> for OAuth2AuthorizationCode {
    type Error = AuthencError;

    fn try_from(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            code: row.try_get("code")?,
            client_id: row.try_get("client_id")?,
            user_id: row.try_get("user_id")?,
            redirect_uri: row.try_get("redirect_uri")?,
            scopes: row.try_get("scopes")?,
            code_challenge: row.try_get("code_challenge")?,
            code_challenge_method: row.try_get("code_challenge_method")?,
            expires_at: row.try_get("expires_at")?,
            used: row.try_get("used")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

/// Converts a PostgreSQL database row into an OAuth2AccessToken instance
///
/// This implementation extracts all OAuth2AccessToken fields from a database row
/// and constructs a new OAuth2AccessToken struct. All fields are required in the row.
impl TryFrom<tokio_postgres::Row> for OAuth2AccessToken {
    type Error = AuthencError;

    fn try_from(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            token_hash: row.try_get("token_hash")?,
            refresh_token_hash: row.try_get("refresh_token_hash")?,
            client_id: row.try_get("client_id")?,
            user_id: row.try_get("user_id")?,
            scopes: row.try_get("scopes")?,
            expires_at: row.try_get("expires_at")?,
            refresh_expires_at: row.try_get("refresh_expires_at")?,
            revoked: row.try_get("revoked")?,
            revoked_at: row.try_get("revoked_at")?,
            created_at: row.try_get("created_at")?,
            last_used_at: row.try_get("last_used_at")?,
            session_id: row.try_get("session_id")?,
        })
    }
}
