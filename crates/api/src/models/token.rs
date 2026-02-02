use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authentication token types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenType {
    /// Access token for API authorization
    AccessToken,
    /// Refresh token for obtaining new access tokens
    RefreshToken,
    /// ID token containing user identity information
    IdToken,
    /// Token for email verification
    VerificationToken,
    /// Token for password reset
    PasswordResetToken,
}

/// Generic token structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Unique identifier for the token
    pub id: Uuid,
    /// Type of the token
    pub token_type: TokenType,
    /// Actual token value (hashed or encrypted)
    pub value: String,
    /// ID of the user this token belongs to
    pub user_id: Option<Uuid>,
    /// ID of the client this token is issued to
    pub client_id: Option<String>,
    /// OAuth2 scope of the token
    pub scope: Option<String>,
    /// Timestamp when the token expires
    pub expires_at: DateTime<Utc>,
    /// Timestamp when the token was created
    pub created_at: DateTime<Utc>,
    /// Whether the token has been revoked
    pub revoked: bool,
    /// Whether the token has been used (for one-time tokens)
    pub used: bool,
}

/// Token creation request
#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    /// Type of token to create
    pub token_type: TokenType,
    /// ID of the user for whom the token is created
    pub user_id: Option<Uuid>,
    /// ID of the client for whom the token is created
    pub client_id: Option<String>,
    /// OAuth2 scope for the token
    pub scope: Option<String>,
    /// Token lifetime in seconds
    pub expires_in: i64,
}

/// Token response (safe for client)
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// Access token value
    pub access_token: String,
    /// Type of the token (usually "Bearer")
    pub token_type: String,
    /// Token lifetime in seconds
    pub expires_in: i64,
    /// Refresh token value (if issued)
    pub refresh_token: Option<String>,
    /// OAuth2 scope of the token
    pub scope: Option<String>,
}

/// JWT token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject identifier (user ID)
    pub sub: String,
    /// Audience (client ID)
    pub aud: String,
    /// Issuer of the token
    pub iss: String,
    /// Expiration timestamp
    pub exp: i64,
    /// Issued at timestamp
    pub iat: i64,
    /// JWT unique identifier
    pub jti: String,
    /// OAuth2 scope
    pub scope: Option<String>,
}

impl Token {
    /// Create a new token
    pub fn new(request: CreateTokenRequest, value: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            token_type: request.token_type,
            value,
            user_id: request.user_id,
            client_id: request.client_id,
            scope: request.scope,
            expires_at: now + chrono::Duration::seconds(request.expires_in),
            created_at: now,
            revoked: false,
            used: false,
        }
    }

    /// Check if token is valid (not expired, revoked, or used)
    pub fn is_valid(&self) -> bool {
        !self.revoked && !self.used && Utc::now() < self.expires_at
    }

    /// Revoke the token
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Mark token as used (for one-time tokens)
    pub fn mark_used(&mut self) {
        self.used = true;
    }

    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Get remaining time to live in seconds
    pub fn ttl(&self) -> i64 {
        (self.expires_at - Utc::now()).num_seconds()
    }
}
