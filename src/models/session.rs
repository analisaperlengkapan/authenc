use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User session for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub refresh_token: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub revoked: bool,
}

/// Session creation request
#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub user_id: Uuid,
    pub expires_in: i64, // seconds
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Session response (without sensitive tokens)
#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl From<Session> for SessionResponse {
    fn from(session: Session) -> Self {
        Self {
            id: session.id,
            user_id: session.user_id,
            expires_at: session.expires_at,
            created_at: session.created_at,
            last_accessed: session.last_accessed,
            ip_address: session.ip_address,
            user_agent: session.user_agent,
        }
    }
}

impl Session {
    /// Create a new session
    pub fn new(request: CreateSessionRequest, token: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            user_id: request.user_id,
            token,
            refresh_token: None,
            expires_at: now + chrono::Duration::seconds(request.expires_in),
            created_at: now,
            last_accessed: now,
            ip_address: request.ip_address,
            user_agent: request.user_agent,
            revoked: false,
        }
    }

    /// Check if session is valid (not expired and not revoked)
    pub fn is_valid(&self) -> bool {
        !self.revoked && Utc::now() < self.expires_at
    }

    /// Update last accessed time
    pub fn touch(&mut self) {
        self.last_accessed = Utc::now();
    }

    /// Revoke the session
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Check if session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}
