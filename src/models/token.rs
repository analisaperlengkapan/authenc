use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authentication token types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenType {
    AccessToken,
    RefreshToken,
    IdToken,
    VerificationToken,
    PasswordResetToken,
}

/// Generic token structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub id: Uuid,
    pub token_type: TokenType,
    pub value: String,
    pub user_id: Option<Uuid>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
    pub used: bool,
}

/// Token creation request
#[derive(Debug, Deserialize)]
pub struct CreateTokenRequest {
    pub token_type: TokenType,
    pub user_id: Option<Uuid>,
    pub client_id: Option<String>,
    pub scope: Option<String>,
    pub expires_in: i64, // seconds
}

/// Token response (safe for client)
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

/// JWT token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: String, // subject (user_id)
    pub aud: String, // audience (client_id)
    pub iss: String, // issuer
    pub exp: i64,    // expiration time
    pub iat: i64,    // issued at
    pub jti: String, // JWT ID
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
