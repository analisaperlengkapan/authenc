use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User session for authentication
/// 
/// Represents an active user session with authentication tokens and metadata.
/// Sessions track user authentication state, expiration, and security information.
/// 
/// # Fields
/// * `id` - Unique session identifier (UUID)
/// * `user_id` - ID of the authenticated user
/// * `token` - JWT access token for API authentication
/// * `refresh_token` - Optional refresh token for token renewal
/// * `expires_at` - Session expiration timestamp
/// * `created_at` - Session creation timestamp
/// * `last_accessed` - Last activity timestamp for session management
/// * `ip_address` - Client IP address for security tracking
/// * `user_agent` - Client user agent string for device identification
/// * `revoked` - Flag indicating if session has been revoked
/// 
/// # Security Considerations
/// - Tokens should be cryptographically secure random values
/// - Sessions should have reasonable expiration times
/// - IP address and user agent tracking helps detect suspicious activity
/// - Revoked sessions should be immediately invalidated
/// - Refresh tokens enable secure token renewal without re-authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier (UUID)
    pub id: Uuid,
    /// ID of the authenticated user
    pub user_id: Uuid,
    /// JWT access token for API authentication
    pub token: String,
    /// Optional refresh token for token renewal
    pub refresh_token: Option<String>,
    /// Session expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Session creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last activity timestamp for session management
    pub last_accessed: DateTime<Utc>,
    /// Client IP address for security tracking
    pub ip_address: Option<String>,
    /// Client user agent for device identification
    pub user_agent: Option<String>,
    /// Flag indicating if session has been revoked
    pub revoked: bool,
}

/// Session creation request
/// 
/// Parameters required to create a new user session.
/// Used when establishing authentication sessions after successful login.
/// 
/// # Fields
/// * `user_id` - ID of the user for whom to create the session
/// * `expires_in` - Session lifetime in seconds from creation
/// * `ip_address` - Client IP address for security tracking
/// * `user_agent` - Client user agent for device identification
/// 
/// # Security Considerations
/// - Session expiration should be reasonable (hours, not days)
/// - IP address tracking helps detect session hijacking
/// - User agent information aids in device identification
/// - All fields should be validated before session creation
#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    /// ID of the user for whom to create the session
    pub user_id: Uuid,
    /// Session lifetime in seconds from creation
    pub expires_in: i64, // seconds
    /// Client IP address for security tracking
    pub ip_address: Option<String>,
    /// Client user agent for device identification
    pub user_agent: Option<String>,
}

/// Session response (without sensitive tokens)
/// 
/// Safe session information returned to clients.
/// Excludes sensitive token data for security.
/// 
/// # Fields
/// * `id` - Unique session identifier
/// * `user_id` - ID of the authenticated user
/// * `expires_at` - Session expiration timestamp
/// * `created_at` - Session creation timestamp
/// * `last_accessed` - Last activity timestamp
/// * `ip_address` - Client IP address (if available)
/// * `user_agent` - Client user agent (if available)
/// 
/// # Security Considerations
/// - Never includes actual tokens in responses
/// - Provides necessary session metadata for client management
/// - Helps clients track session state and expiration
/// - IP and user agent info aids in session identification
#[derive(Debug, Serialize)]
pub struct SessionResponse {
    /// Unique session identifier
    pub id: Uuid,
    /// ID of the authenticated user
    pub user_id: Uuid,
    /// Session expiration timestamp
    pub expires_at: DateTime<Utc>,
    /// Session creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_accessed: DateTime<Utc>,
    /// Client IP address (if available)
    pub ip_address: Option<String>,
    /// Client user agent (if available)
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
    /// 
    /// Creates a new session instance with generated ID and timestamps.
    /// Initializes session with provided token and request parameters.
    /// 
    /// # Arguments
    /// * `request` - Session creation parameters
    /// * `token` - Generated JWT access token
    /// 
    /// # Returns
    /// A new Session instance ready for use
    /// 
    /// # Security Considerations
    /// - Generates cryptographically secure UUID for session ID
    /// - Sets appropriate expiration based on request
    /// - Records creation and access timestamps
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
    /// 
    /// Validates session state for authentication decisions.
    /// Sessions are invalid if expired or explicitly revoked.
    /// 
    /// # Returns
    /// true if session is valid and can be used for authentication
    /// 
    /// # Security Considerations
    /// - Always check validity before granting access
    /// - Expired sessions should be cleaned up
    /// - Revoked sessions indicate security incidents
    pub fn is_valid(&self) -> bool {
        !self.revoked && Utc::now() < self.expires_at
    }

    /// Update last accessed time
    /// 
    /// Updates the session's last accessed timestamp.
    /// Used to track session activity and implement idle timeouts.
    /// 
    /// # Security Considerations
    /// - Helps detect inactive sessions
    /// - Supports session timeout policies
    /// - Tracks user activity patterns
    pub fn touch(&mut self) {
        self.last_accessed = Utc::now();
    }

    /// Revoke the session
    /// 
    /// Marks the session as revoked, preventing further use.
    /// Used for logout, security incidents, or administrative actions.
    /// 
    /// # Security Considerations
    /// - Immediately invalidates session tokens
    /// - Prevents further authentication with this session
    /// - Should trigger token blacklist updates
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Check if session is expired
    /// 
    /// Determines if the session has exceeded its expiration time.
    /// Used for cleanup and validation logic.
    /// 
    /// # Returns
    /// true if the current time is past the session's expiration
    /// 
    /// # Security Considerations
    /// - Expired sessions should not be accepted
    /// - Helps prevent indefinite session validity
    /// - Supports session lifecycle management
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}
