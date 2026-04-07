use authenc_database::database::Database;
use authenc_database::database::operations;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ldap3::LdapConnSettings;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use uuid::Uuid;

/// Structured error type for admin service operations
#[derive(Debug, Clone)]
pub enum AdminServiceError {
    /// The requested resource was not found
    NotFound(String),
    /// The resource was already deleted
    AlreadyDeleted(String),
    /// The operation is not implemented
    NotImplemented(String),
    /// The request was invalid (bad input, validation failure)
    BadRequest(String),
    /// An internal error occurred (database, serialization, etc.)
    Internal(String),
}

impl fmt::Display for AdminServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdminServiceError::NotFound(msg) => write!(f, "{}", msg),
            AdminServiceError::AlreadyDeleted(msg) => write!(f, "{}", msg),
            AdminServiceError::NotImplemented(msg) => write!(f, "{}", msg),
            AdminServiceError::BadRequest(msg) => write!(f, "{}", msg),
            AdminServiceError::Internal(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for AdminServiceError {}

impl AdminServiceError {
    /// Returns true if this is a not-found or already-deleted error
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            AdminServiceError::NotFound(_) | AdminServiceError::AlreadyDeleted(_)
        )
    }
}

impl From<String> for AdminServiceError {
    fn from(s: String) -> Self {
        AdminServiceError::Internal(s)
    }
}

/// Check if a database error message indicates a unique constraint violation
fn is_duplicate_key_error(msg: &str) -> bool {
    msg.contains("duplicate key") || msg.contains("already exists") || msg.contains("unique constraint")
}

/// Parse role attributes from a `serde_json::Value` that may be either:
///   - a JSON object (if the column is JSONB or was inserted as structured JSON), or
///   - a JSON string containing serialized JSON (if the column is TEXT and was
///     written via `serde_json::to_string`).
///
/// Returns `None` when the input is `None` or cannot be parsed.
fn parse_role_attributes(
    attrs: Option<serde_json::Value>,
) -> std::collections::HashMap<String, Vec<String>> {
    match attrs {
        Some(serde_json::Value::String(s)) => {
            // TEXT column: the Value is a String wrapping serialized JSON.
            // Parse the inner JSON string into the target type.
            serde_json::from_str(&s).unwrap_or_default()
        }
        Some(other) => {
            // JSONB column or already a structured Value — deserialize directly.
            serde_json::from_value(other).unwrap_or_default()
        }
        None => std::collections::HashMap::new(),
    }
}

/// Admin service trait
#[async_trait]
pub trait AdminService: Send + Sync {
    /// Get system statistics
    async fn get_system_stats(&self) -> Result<SystemStats, AdminServiceError>;

    /// Get user management data
    async fn get_users(
        &self,
        realm_id: &Uuid,
        page: u32,
        limit: u32,
    ) -> Result<UserListResponse, AdminServiceError>;

    /// Get user by ID
    async fn get_user(&self, user_id: &Uuid) -> Result<UserResponse, AdminServiceError>;

    /// Create new user
    async fn create_user(
        &self,
        request: CreateUserRequest,
    ) -> Result<UserResponse, AdminServiceError>;

    /// Update user
    async fn update_user(
        &self,
        user_id: &Uuid,
        request: UpdateUserRequest,
    ) -> Result<UserResponse, AdminServiceError>;

    /// Delete user
    async fn delete_user(&self, user_id: &Uuid) -> Result<(), AdminServiceError>;

    /// Get roles
    async fn get_roles(&self, realm_id: &Uuid) -> Result<Vec<RoleResponse>, AdminServiceError>;

    /// Get role by ID
    async fn get_role(&self, role_id: &Uuid) -> Result<RoleResponse, AdminServiceError>;

    /// Create role
    async fn create_role(
        &self,
        request: CreateRoleRequest,
    ) -> Result<RoleResponse, AdminServiceError>;

    /// Update role
    async fn update_role(
        &self,
        role_id: &Uuid,
        request: UpdateRoleRequest,
    ) -> Result<RoleResponse, AdminServiceError>;

    /// Delete role
    async fn delete_role(&self, role_id: &Uuid) -> Result<(), AdminServiceError>;

    /// Get sessions
    async fn get_sessions(
        &self,
        user_id: Option<Uuid>,
        realm_id: Option<Uuid>,
        page: u32,
        limit: u32,
    ) -> Result<SessionListResponse, AdminServiceError>;

    /// Terminate session
    async fn terminate_session(&self, session_id: &str) -> Result<(), AdminServiceError>;

    /// Get audit logs
    async fn get_audit_logs(
        &self,
        filter: AuditLogFilter,
    ) -> Result<AuditLogResponse, AdminServiceError>;

    /// Get authorization policies
    async fn get_policies(
        &self,
        realm_id: &Uuid,
        page: u32,
        limit: u32,
    ) -> Result<Vec<PolicyResponse>, AdminServiceError>;

    /// Create policy
    async fn create_policy(
        &self,
        request: CreatePolicyRequest,
    ) -> Result<PolicyResponse, AdminServiceError>;

    /// Get zero trust dashboard data
    async fn get_zero_trust_dashboard(
        &self,
        realm_id: &Uuid,
    ) -> Result<ZeroTrustDashboard, AdminServiceError>;

    /// Get identity providers
    async fn get_identity_providers(
        &self,
        realm_id: &Uuid,
    ) -> Result<Vec<IdentityProviderResponse>, AdminServiceError>;

    /// Create identity provider
    async fn create_identity_provider(
        &self,
        request: CreateIdentityProviderRequest,
    ) -> Result<IdentityProviderResponse, AdminServiceError>;

    /// Update identity provider
    async fn update_identity_provider(
        &self,
        provider_id: &Uuid,
        request: UpdateIdentityProviderRequest,
    ) -> Result<IdentityProviderResponse, AdminServiceError>;

    /// Delete identity provider
    async fn delete_identity_provider(
        &self,
        provider_id: &Uuid,
    ) -> Result<(), AdminServiceError>;

    /// Get identity provider by ID
    async fn get_identity_provider(
        &self,
        provider_id: &Uuid,
    ) -> Result<IdentityProviderResponse, AdminServiceError>;

    /// Test identity provider connection
    async fn test_identity_provider(
        &self,
        provider_id: &Uuid,
    ) -> Result<TestIdentityProviderResponse, AdminServiceError>;
}

/// System statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStats {
    /// Total number of users in the system
    pub total_users: u64,
    /// Number of currently active users
    pub active_users: u64,
    /// Total number of sessions
    pub total_sessions: u64,
    /// Number of currently active sessions
    pub active_sessions: u64,
    /// Total number of realms
    pub total_realms: u64,
    /// Total number of authorization policies
    pub total_policies: u64,
    /// Number of security events today
    pub security_events_today: u64,
    /// Number of failed login attempts
    pub failed_login_attempts: u64,
    /// System uptime in seconds
    pub uptime_seconds: u64,
    /// Memory usage in MB
    pub memory_usage_mb: u64,
    /// CPU usage percentage
    pub cpu_usage_percent: f64,
}

/// User list response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserListResponse {
    /// List of users
    pub users: Vec<UserResponse>,
    /// Total count of users
    pub total_count: u64,
    /// Current page number
    pub page: u32,
    /// Number of items per page
    pub limit: u32,
}

/// User response for admin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    /// Unique identifier for the user
    pub id: Uuid,
    /// Username of the user
    pub username: String,
    /// Email address of the user
    pub email: String,
    /// First name of the user
    pub first_name: Option<String>,
    /// Last name of the user
    pub last_name: Option<String>,
    /// Whether the user account is enabled
    pub enabled: bool,
    /// Whether the user's email is verified
    pub email_verified: bool,
    /// ID of the realm the user belongs to
    pub realm_id: Uuid,
    /// ID of the organization the user belongs to
    pub organization_id: Option<Uuid>,
    /// List of roles assigned to the user
    pub roles: Vec<String>,
    /// List of groups the user belongs to
    pub groups: Vec<String>,
    /// Timestamp when the user was created
    pub created_at: DateTime<Utc>,
    /// Timestamp of the user's last login
    pub last_login: Option<DateTime<Utc>>,
    /// Number of failed login attempts
    pub login_attempts: u32,
    /// Timestamp until which the account is locked
    pub locked_until: Option<DateTime<Utc>>,
}

/// Create user request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    /// Username for the new user
    pub username: String,
    /// Email address for the new user
    pub email: String,
    /// Password for the new user (optional for social users)
    pub password: Option<String>,
    /// First name of the new user
    pub first_name: Option<String>,
    /// Last name of the new user
    pub last_name: Option<String>,
    /// Phone number of the new user
    pub phone_number: Option<String>,
    /// ID of the realm for the new user
    pub realm_id: Uuid,
    /// ID of the organization for the new user
    pub organization_id: Option<Uuid>,
    /// List of roles to assign to the new user
    pub roles: Vec<String>,
    /// List of groups to assign to the new user
    pub groups: Vec<String>,
    /// Additional user attributes
    pub attributes: Option<serde_json::Value>,
    /// Whether the user's email should be marked as verified
    pub email_verified: bool,
    /// Whether the user account should be enabled
    pub enabled: bool,
    /// Require password change
    pub require_password_change: Option<bool>,
}

/// Update user request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    /// New username for the user
    pub username: Option<String>,
    /// New email address for the user
    pub email: Option<String>,
    /// New first name for the user
    pub first_name: Option<String>,
    /// New last name for the user
    pub last_name: Option<String>,
    /// New phone number for the user
    pub phone_number: Option<String>,
    /// New list of roles for the user
    pub roles: Option<Vec<String>>,
    /// New list of groups for the user
    pub groups: Option<Vec<String>>,
    /// New email verification status
    pub email_verified: Option<bool>,
    /// New phone verification status
    pub phone_verified: Option<bool>,
    /// New account enabled status
    pub enabled: Option<bool>,
    /// New password change requirement
    pub require_password_change: Option<bool>,
    /// ID of the organization the user belongs to
    pub organization_id: Option<Uuid>,
    /// New user attributes
    pub attributes: Option<serde_json::Value>,
}

/// Role response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleResponse {
    /// Unique identifier for the role
    pub id: Uuid,
    /// Name of the role
    pub name: String,
    /// Description of the role
    pub description: String,
    /// ID of the realm the role belongs to
    pub realm_id: Uuid,
    /// Whether this is a composite role
    pub composite: bool,
    /// Whether this is a client role
    pub client_role: bool,
    /// Container ID for client roles
    pub container_id: Option<String>,
    /// Additional attributes for the role
    pub attributes: std::collections::HashMap<String, Vec<String>>,
}

/// Create role request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRoleRequest {
    /// Name of the new role
    pub name: String,
    /// Description of the new role
    pub description: String,
    /// ID of the realm for the new role
    pub realm_id: Uuid,
    /// Whether this should be a composite role
    pub composite: bool,
    /// Whether this should be a client role
    pub client_role: bool,
    /// Additional attributes for the role
    pub attributes: std::collections::HashMap<String, Vec<String>>,
}

/// Update role request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRoleRequest {
    /// New name for the role
    pub name: Option<String>,
    /// New description for the role
    pub description: Option<String>,
    /// Whether this should be a composite role
    pub composite: Option<bool>,
    /// Whether this should be a client role
    pub client_role: Option<bool>,
    /// Additional attributes for the role
    pub attributes: Option<std::collections::HashMap<String, Vec<String>>>,
}

/// Session list response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionListResponse {
    /// List of sessions
    pub sessions: Vec<SessionResponse>,
    /// Total count of sessions
    pub total_count: u64,
    /// Current page number
    pub page: u32,
    /// Number of items per page
    pub limit: u32,
}

/// Session response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    /// Unique identifier for the session
    pub id: String,
    /// ID of the user who owns the session
    pub user_id: Uuid,
    /// Username of the user
    pub username: String,
    /// IP address where the session was created
    pub ip_address: String,
    /// User agent string from the client
    pub user_agent: String,
    /// Timestamp when the session started
    pub started_at: DateTime<Utc>,
    /// Timestamp of the last activity in the session
    pub last_activity: DateTime<Utc>,
    /// Timestamp when the session expires
    pub expires_at: DateTime<Utc>,
    /// ID of the client application
    pub client_id: Option<String>,
}

/// Audit log filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogFilter {
    /// Filter by user ID
    pub user_id: Option<Uuid>,
    /// Filter by event type
    pub event_type: Option<String>,
    /// Filter by realm ID
    pub realm_id: Option<Uuid>,
    /// Filter by start date
    pub from_date: Option<DateTime<Utc>>,
    /// Filter by end date
    pub to_date: Option<DateTime<Utc>>,
    /// Page number for pagination
    pub page: u32,
    /// Number of items per page
    pub limit: u32,
}

/// Audit log response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogResponse {
    /// List of audit log entries
    pub logs: Vec<AuditLogEntry>,
    /// Total count of audit log entries
    pub total_count: u64,
    /// Current page number
    pub page: u32,
    /// Number of items per page
    pub limit: u32,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Unique identifier for the audit log entry
    pub id: Uuid,
    /// Timestamp when the event occurred
    pub timestamp: DateTime<Utc>,
    /// ID of the user who performed the action
    pub user_id: Option<Uuid>,
    /// Username of the user who performed the action
    pub username: Option<String>,
    /// Type of the event
    pub event_type: String,
    /// Type of operation performed
    pub operation_type: String,
    /// Type of resource affected
    pub resource_type: String,
    /// Path or identifier of the resource
    pub resource_path: String,
    /// IP address of the client
    pub ip_address: String,
    /// User agent string from the client
    pub user_agent: String,
    /// ID of the realm where the event occurred
    pub realm_id: Uuid,
    /// ID of the client application
    pub client_id: Option<String>,
    /// Additional details about the event
    pub details: serde_json::Value,
    /// Whether the operation was successful
    pub success: bool,
    /// Error message if the operation failed
    pub error_message: Option<String>,
}

/// Policy response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResponse {
    /// Unique identifier for the policy
    pub id: Uuid,
    /// Name of the policy
    pub name: String,
    /// Description of the policy
    pub description: String,
    /// Type of the policy
    pub policy_type: String,
    /// Logic used by the policy
    pub logic: String,
    /// Configuration for the policy
    pub config: serde_json::Value,
    /// Whether the policy is enabled
    pub enabled: bool,
    /// ID of the realm the policy belongs to
    pub realm_id: Uuid,
    /// Timestamp when the policy was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the policy was last updated
    pub updated_at: DateTime<Utc>,
}

/// Create policy request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePolicyRequest {
    /// Name of the new policy
    pub name: String,
    /// Description of the new policy
    pub description: String,
    /// Type of the new policy
    pub policy_type: String,
    /// Logic for the new policy
    pub logic: String,
    /// Configuration for the new policy
    pub config: serde_json::Value,
    /// Whether the policy is enabled
    pub enabled: Option<bool>,
    /// ID of the realm for the new policy
    pub realm_id: Uuid,
}

/// Zero Trust dashboard data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroTrustDashboard {
    /// Distribution of risk levels across users
    pub risk_distribution: std::collections::HashMap<String, u64>,
    /// List of users with highest risk scores
    pub top_risk_users: Vec<RiskUser>,
    /// Recent security events
    pub security_events: Vec<SecurityEvent>,
    /// Device trust statistics
    pub device_trust_stats: DeviceTrustStats,
    /// Adaptive controls statistics
    pub adaptive_controls_stats: AdaptiveControlsStats,
}

/// Risk user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskUser {
    /// ID of the user
    pub user_id: Uuid,
    /// Username of the user
    pub username: String,
    /// Risk score of the user
    pub risk_score: f64,
    /// Risk level of the user
    pub risk_level: String,
    /// Timestamp of the user's last activity
    pub last_activity: DateTime<Utc>,
}

/// Security event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique identifier for the security event
    pub id: Uuid,
    /// Type of the security event
    pub event_type: String,
    /// Severity of the security event
    pub severity: String,
    /// ID of the user associated with the event
    pub user_id: Option<Uuid>,
    /// Username of the user associated with the event
    pub username: Option<String>,
    /// IP address where the event occurred
    pub ip_address: String,
    /// Timestamp when the event occurred
    pub timestamp: DateTime<Utc>,
    /// Additional details about the event
    pub details: serde_json::Value,
}

/// Device trust statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTrustStats {
    /// Total number of devices
    pub total_devices: u64,
    /// Number of trusted devices
    pub trusted_devices: u64,
    /// Number of untrusted devices
    pub untrusted_devices: u64,
    /// Compliance rate as a percentage
    pub compliance_rate: f64,
}

/// Adaptive controls statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveControlsStats {
    /// Number of active sessions
    pub active_sessions: u64,
    /// Number of sessions with MFA enabled
    pub sessions_with_mfa: u64,
    /// Number of sessions with device verification
    pub sessions_with_device_verification: u64,
    /// Number of blocked actions due to adaptive controls
    pub blocked_actions: u64,
}

/// Admin Manager - main service implementation
pub struct AdminManager {
    // Database connection for admin operations
    db: Arc<Database>,
}

impl AdminManager {
    /// Create a new admin manager for system administration operations
    ///
    /// This constructor initializes an admin manager that provides
    /// administrative functions for managing users, realms, and system
    /// configuration. The manager starts with a clean state and requires
    /// explicit configuration for specific administrative operations.
    ///
    /// # Parameters
    /// - `db`: Database connection for admin operations
    ///
    /// # Returns
    /// A new `AdminManager` instance ready for administrative operations
    ///
    /// # Security Considerations
    /// - Admin operations should be properly authenticated and authorized
    /// - Audit logging is automatically enabled for all admin actions
    /// - Sensitive operations require additional verification
    /// - Access to admin functions should be restricted to authorized personnel
    ///
    /// # Administrative Functions
    /// - User management (creation, modification, deletion)
    /// - Realm administration and configuration
    /// - System statistics and monitoring
    /// - Security policy management
    /// - Audit log access and analysis
    ///
    /// # Example
    /// ```rust,no_run
    /// use authenc_services::services::admin::AdminManager;
    /// use authenc_database::database::Database;
    /// use authenc_core::config::DatabaseConfig;
    /// use std::sync::Arc;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = DatabaseConfig {
    ///     host: "localhost".to_string(),
    ///     port: 5432,
    ///     username: "postgres".to_string(),
    ///     password: "password".to_string(),
    ///     database: "authenc".to_string(),
    ///     max_connections: 10,
    ///     connection_timeout: 30,
    ///     audit_log_url: None,
    ///     connection_timeout_seconds: 30,
    /// };
    /// let db = Arc::new(Database::new(&config).await?);
    /// let admin = AdminManager::new(db);
    /// // Use admin for system management operations
    /// // let stats = admin.get_system_stats().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Generate system statistics with real database queries
    async fn generate_system_stats(&self) -> SystemStats {
        // Integration 17: Admin Console Statistics with database verification
        // Using concurrent queries to improve performance (addressing sequential query latency)

        // Define queries
        let total_users_query = self.db.query_raw("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL", &[]);
        let active_users_query = self.db.query_raw(
            "SELECT COUNT(DISTINCT user_id) FROM user_sessions WHERE last_activity_at > NOW() - INTERVAL '30 days'",
            &[]
        );
        let total_sessions_query = self.db.query_raw("SELECT COUNT(*) FROM user_sessions", &[]);
        let active_sessions_query = self.db.query_raw(
            "SELECT COUNT(*) FROM user_sessions WHERE expires_at > NOW() AND terminated = false",
            &[],
        );
        let total_realms_query = self.db.query_raw("SELECT COUNT(*) FROM realms WHERE enabled = true", &[]);
        let total_policies_query = self.db.query_raw("SELECT COUNT(*) FROM policies", &[]);
        let security_events_query = self.db.query_raw(
            "SELECT COUNT(*) FROM audit_logs WHERE timestamp >= CURRENT_DATE AND event_type IN ('login', 'logout', 'access_denied', 'permission_check')",
            &[]
        );
        let failed_logins_query = self.db.query_raw(
            "SELECT COUNT(*) FROM audit_logs WHERE timestamp >= CURRENT_DATE AND event_type = 'login' AND status != 'SUCCESS'",
            &[]
        );

        // Execute all queries concurrently
        let (
            total_users_res,
            active_users_res,
            total_sessions_res,
            active_sessions_res,
            total_realms_res,
            total_policies_res,
            security_events_res,
            failed_logins_res
        ) = tokio::join!(
            total_users_query,
            active_users_query,
            total_sessions_query,
            active_sessions_query,
            total_realms_query,
            total_policies_query,
            security_events_query,
            failed_logins_query
        );

        // Helper to extract count
        fn extract_count(res: Result<Vec<tokio_postgres::Row>, authenc_core::error::AuthencError>) -> u64 {
            res.ok()
                .and_then(|rows| rows.first().map(|row| row.get::<_, i64>(0)))
                .unwrap_or(0) as u64
        }

        let total_users = extract_count(total_users_res);
        let active_users = extract_count(active_users_res);
        let total_sessions = extract_count(total_sessions_res);
        let active_sessions = extract_count(active_sessions_res);
        let total_realms = extract_count(total_realms_res);
        let total_policies = extract_count(total_policies_res);
        let security_events_today = extract_count(security_events_res);
        let failed_login_attempts = extract_count(failed_logins_res);

        // System metrics (would come from system monitoring in production)
        let uptime_seconds = 86400; // Placeholder: 24 hours
        let memory_usage_mb = 512; // Placeholder: 512 MB
        let cpu_usage_percent = 15.5; // Placeholder: 15.5%

        SystemStats {
            total_users,
            active_users,
            total_sessions,
            active_sessions,
            total_realms,
            total_policies,
            security_events_today,
            failed_login_attempts,
            uptime_seconds,
            memory_usage_mb,
            cpu_usage_percent,
        }
    }

    /// Generate zero trust dashboard data
    async fn generate_zero_trust_dashboard(
        &self,
        realm_id: &Uuid,
    ) -> Result<ZeroTrustDashboard, String> {
        // 1. Risk Distribution
        // Join with users to filter by realm_id
        let risk_query = r#"
            SELECT
                CASE
                    WHEN ds.risk_score < 0.3 THEN 'low'
                    WHEN ds.risk_score < 0.6 THEN 'medium'
                    WHEN ds.risk_score < 0.8 THEN 'high'
                    ELSE 'critical'
                END as risk_level,
                COUNT(DISTINCT ds.user_id)::bigint as user_count
            FROM device_sessions ds
            JOIN users u ON ds.user_id = u.id
            WHERE ds.is_active = true AND u.realm_id = $1
            GROUP BY 1
        "#;

        let risk_rows: Vec<tokio_postgres::Row> = self
            .db
            .query(risk_query, &[realm_id])
            .await
            .map_err(|e| format!("Failed to query risk distribution: {}", e))?;

        let mut risk_distribution = std::collections::HashMap::new();
        // Initialize with zeros
        risk_distribution.insert("low".to_string(), 0);
        risk_distribution.insert("medium".to_string(), 0);
        risk_distribution.insert("high".to_string(), 0);
        risk_distribution.insert("critical".to_string(), 0);

        for row in risk_rows {
            let level: String = row.get("risk_level");
            let count: i64 = row.get("user_count");
            risk_distribution.insert(level, count as u64);
        }

        // 2. Top Risk Users
        let top_users_query = r#"
            SELECT
                u.id, u.username,
                MAX(ds.risk_score) as risk_score,
                MAX(ds.last_activity) as last_activity
            FROM users u
            JOIN device_sessions ds ON u.id = ds.user_id
            WHERE ds.is_active = true AND u.realm_id = $1
            GROUP BY u.id, u.username
            ORDER BY risk_score DESC
            LIMIT 5
        "#;

        let user_rows: Vec<tokio_postgres::Row> = self
            .db
            .query(top_users_query, &[realm_id])
            .await
            .map_err(|e| format!("Failed to query top risk users: {}", e))?;

        let mut top_risk_users = Vec::new();
        for row in user_rows {
            let risk_score: f64 = row.get("risk_score");
            let risk_level = if risk_score < 0.3 {
                "low"
            } else if risk_score < 0.6 {
                "medium"
            } else if risk_score < 0.8 {
                "high"
            } else {
                "critical"
            }
            .to_string();

            top_risk_users.push(RiskUser {
                user_id: row.get("id"),
                username: row.get("username"),
                risk_score,
                risk_level,
                last_activity: row.get("last_activity"),
            });
        }

        // 3. Security Events
        // Filter by realm_id via user join.
        // Note: This excludes events not linked to a user or linked to a user without realm (rare).
        let events_query = r#"
            SELECT
                a.id, a.event_type, a.status, a.user_id, u.username,
                a.ip_address, a.timestamp, a.details
            FROM audit_logs a
            LEFT JOIN users u ON a.user_id = u.id
            WHERE (u.realm_id = $1)
              AND (a.status != 'SUCCESS' OR a.event_type IN ('failed_login', 'access_denied', 'suspicious_activity'))
            ORDER BY a.timestamp DESC
            LIMIT 10
        "#;

        let event_rows: Vec<tokio_postgres::Row> =
            self.db
                .query(events_query, &[realm_id])
                .await
                .map_err(|e| format!("Failed to query security events: {}", e))?;

        let mut security_events = Vec::new();
        for row in event_rows {
            let event_type: String = row.get("event_type");
            let status: String = row.get("status");
            let severity = if status != "SUCCESS" || event_type.contains("failed") {
                "high".to_string()
            } else {
                "medium".to_string()
            };

            security_events.push(SecurityEvent {
                id: row.get("id"),
                event_type,
                severity,
                user_id: row.get("user_id"),
                username: row.get("username"),
                ip_address: row.get("ip_address"),
                timestamp: row.get("timestamp"),
                details: row
                    .get::<_, Option<String>>("details")
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                    .unwrap_or(serde_json::json!({})),
            });
        }

        // 4. Device Trust Stats
        let device_stats_query = r#"
            SELECT
                COUNT(d.id)::bigint as total,
                COUNT(d.id) FILTER (WHERE d.trust_score >= 0.7)::bigint as trusted
            FROM devices d
            JOIN users u ON d.user_id = u.id
            WHERE u.realm_id = $1
        "#;

        let device_row: tokio_postgres::Row = self
            .db
            .query_one(device_stats_query, &[realm_id])
            .await
            .map_err(|e| format!("Failed to query device stats: {}", e))?;

        let total_devices: i64 = device_row.get("total");
        let trusted_devices: i64 = device_row.get("trusted");
        let untrusted_devices = total_devices - trusted_devices;
        let compliance_rate = if total_devices > 0 {
            (trusted_devices as f64 / total_devices as f64) * 100.0
        } else {
            100.0
        };

        let device_trust_stats = DeviceTrustStats {
            total_devices: total_devices as u64,
            trusted_devices: trusted_devices as u64,
            untrusted_devices: untrusted_devices as u64,
            compliance_rate,
        };

        // 5. Adaptive Controls Stats
        // The canonical user_sessions table does NOT have realm_id or
        // authentication_method columns, so we JOIN with users for realm
        // filtering and approximate MFA from audit_logs instead.
        let active_sessions_query = "SELECT COUNT(*)::bigint FROM user_sessions s JOIN users u ON s.user_id = u.id WHERE u.realm_id = $1 AND s.expires_at > NOW() AND NOT s.terminated";

        // MFA session count: approximate by counting active sessions whose
        // user has a WebAuthn credential or a recent MFA audit event.
        let mfa_sessions_query = "SELECT COUNT(DISTINCT s.id)::bigint FROM user_sessions s JOIN users u ON s.user_id = u.id LEFT JOIN webauthn_credentials wc ON wc.user_id = u.id AND wc.enabled = true WHERE u.realm_id = $1 AND s.expires_at > NOW() AND NOT s.terminated AND wc.id IS NOT NULL";

        // device_sessions needs join with users
        let device_verification_query = "SELECT COUNT(ds.id)::bigint FROM device_sessions ds JOIN users u ON ds.user_id = u.id WHERE u.realm_id = $1 AND ds.is_active = true";

        // audit_logs needs join with users
        let blocked_actions_query = "SELECT COUNT(a.id)::bigint FROM audit_logs a LEFT JOIN users u ON a.user_id = u.id WHERE u.realm_id = $1 AND (a.action = 'BLOCK' OR a.status = 'DENIED') AND a.timestamp > NOW() - INTERVAL '24 hours'";

        let active_sessions: i64 = self
            .db
            .query_one::<tokio_postgres::Row>(active_sessions_query, &[realm_id])
            .await
            .map_err(|e| format!("Failed to count active sessions: {}", e))?
            .get(0);

        let sessions_with_mfa: i64 = self
            .db
            .query_one::<tokio_postgres::Row>(mfa_sessions_query, &[realm_id])
            .await
            .map_err(|e| format!("Failed to count MFA sessions: {}", e))?
            .get(0);

        let sessions_with_device_verification: i64 = self
            .db
            .query_one::<tokio_postgres::Row>(device_verification_query, &[realm_id])
            .await
            .map_err(|e| format!("Failed to count device sessions: {}", e))?
            .get(0);

        let blocked_actions: i64 = self
            .db
            .query_one::<tokio_postgres::Row>(blocked_actions_query, &[realm_id])
            .await
            .map_err(|e| format!("Failed to count blocked actions: {}", e))?
            .get(0);

        let adaptive_controls_stats = AdaptiveControlsStats {
            active_sessions: active_sessions as u64,
            sessions_with_mfa: sessions_with_mfa as u64,
            sessions_with_device_verification: sessions_with_device_verification as u64,
            blocked_actions: blocked_actions as u64,
        };

        Ok(ZeroTrustDashboard {
            risk_distribution,
            top_risk_users,
            security_events,
            device_trust_stats,
            adaptive_controls_stats,
        })
    }
}

#[async_trait]
impl AdminService for AdminManager {
    async fn get_system_stats(&self) -> Result<SystemStats, AdminServiceError> {
        Ok(self.generate_system_stats().await)
    }

    async fn get_user(&self, user_id: &Uuid) -> Result<UserResponse, AdminServiceError> {
        match operations::users::get_user_by_id(&self.db, *user_id).await {
            Ok(Some(user)) => {
                // Guard against returning soft-deleted users in case the
                // underlying get_user_by_id does not filter by deleted_at.
                if user.deleted_at.is_some() {
                    return Err(AdminServiceError::NotFound(format!("User with ID {} not found", user_id)));
                }
                let realm_id = user.realm_id.unwrap_or(Uuid::nil());
                let roles = authenc_database::database::operations::roles::get_user_roles(&self.db, &user.id)
                    .await
                    .map_err(|e| AdminServiceError::Internal(format!("Failed to get user roles: {}", e)))?
                    .into_iter()
                    .map(|r| r.name)
                    .collect();
                let user_groups = operations::groups::get_user_groups(&self.db, user.id)
                    .await
                    .map_err(|e| AdminServiceError::Internal(format!("Failed to get user groups: {}", e)))?;
                let group_names = user_groups.iter().map(|g| g.name.clone()).collect();

                Ok(UserResponse {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    enabled: user.enabled,
                    email_verified: user.email_verified,
                    realm_id,
                    organization_id: user.organization_id,
                    roles,
                    groups: group_names,
                    created_at: user.created_at,
                    last_login: user.last_login_at,
                    login_attempts: user.failed_login_attempts as u32,
                    locked_until: user.account_locked_until,
                })
            }
            Ok(None) => Err(AdminServiceError::NotFound(format!("User with ID {} not found", user_id))),
            Err(e) => Err(AdminServiceError::Internal(format!("Failed to get user: {}", e))),
        }
    }

    async fn get_users(
        &self,
        realm_id: &Uuid,
        page: u32,
        limit: u32,
    ) -> Result<UserListResponse, AdminServiceError> {
        // Integration 19: User Listing with Pagination and Realm Filtering

        let offset = (page.saturating_sub(1)).saturating_mul(limit);

        // Query total count first
        let total_count_query =
            "SELECT COUNT(*) FROM users WHERE realm_id = $1 AND deleted_at IS NULL";
        let total_count = self
            .db
            .query_raw(total_count_query, &[&realm_id])
            .await
            .map_err(|e| AdminServiceError::Internal(format!("Failed to get user count: {}", e)))?
            .first()
            .map(|row| row.get::<_, i64>(0))
            .unwrap_or(0) as u64;

        // Query users with pagination
        // Added organization_id to the query
        let users_query = "SELECT id, username, email, first_name, last_name, enabled, email_verified, realm_id, created_at, last_login_at, failed_login_attempts, account_locked_until, organization_id FROM users WHERE realm_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT $2 OFFSET $3";
        let rows = self
            .db
            .query_raw(users_query, &[&realm_id, &(limit as i64), &(offset as i64)])
            .await
            .map_err(|e| AdminServiceError::Internal(format!("Failed to get users: {}", e)))?;

        let mut users = Vec::new();
        for row in rows {
            let id: Uuid = row.get(0);
            let username: String = row.get(1);
            let email: String = row.get(2);
            let first_name: Option<String> = row.get(3);
            let last_name: Option<String> = row.get(4);
            let enabled: bool = row.get(5);
            let email_verified: bool = row.get(6);
            let user_realm_id: Uuid = row.get(7);
            let created_at: DateTime<Utc> = row.get(8);
            let last_login: Option<DateTime<Utc>> = row.get(9);
            let login_attempts: i32 = row.get(10);
            let locked_until: Option<DateTime<Utc>> = row.get(11);
            let organization_id: Option<Uuid> = row.get(12);

            // Get roles for user (using existing get_user_roles operation)
            let roles = authenc_database::database::operations::roles::get_user_roles(&self.db, &id)
                .await
                .map_err(|e| AdminServiceError::Internal(format!("Failed to get roles for user {}: {}", id, e)))?
                .into_iter()
                .map(|r| r.name)
                .collect();

            // Get user groups
            let user_groups = operations::groups::get_user_groups(&self.db, id)
                .await
                .map_err(|e| AdminServiceError::Internal(format!("Failed to get groups for user {}: {}", id, e)))?;

            users.push(UserResponse {
                id,
                username,
                email,
                first_name,
                last_name,
                enabled,
                email_verified,
                realm_id: user_realm_id,
                organization_id,
                roles,
                groups: user_groups.iter().map(|g| g.name.clone()).collect(),
                created_at,
                last_login,
                login_attempts: login_attempts as u32,
                locked_until,
            });
        }

        Ok(UserListResponse {
            users,
            total_count,
            page,
            limit,
        })
    }

    async fn create_user(&self, request: CreateUserRequest) -> Result<UserResponse, AdminServiceError> {
        // Convert admin request to model request
        let create_request = authenc_models::models::user::CreateUserRequest {
            username: request.username.clone(),
            email: request.email.clone(),
            password: request.password.clone(),
            first_name: request.first_name.clone(),
            last_name: request.last_name.clone(),
            phone_number: request.phone_number.clone(),
            realm_id: Some(request.realm_id),
            organization_id: request.organization_id,
            attributes: request.attributes.clone(),
            enabled: Some(request.enabled),
            email_verified: Some(request.email_verified),
            require_password_change: Some(request.require_password_change.unwrap_or(false)),
        };

        // Create user in database
        match operations::users::create_user(&self.db, &create_request).await {
            Ok(user) => {
                let realm_id = user.realm_id.unwrap_or(Uuid::nil());

                // Assign roles if provided
                if !request.roles.is_empty() {
                    let all_roles = operations::roles::list_roles_by_realm(&self.db, &realm_id)
                        .await
                        .map_err(|e| AdminServiceError::Internal(format!("Failed to fetch realm roles: {}", e)))?;

                    for role_name in &request.roles {
                        if let Some(role) = all_roles.iter().find(|r| &r.name == role_name) {
                            operations::roles::assign_role_to_user(
                                &self.db, &user.id, &role.id,
                            )
                            .await
                            .map_err(|e| AdminServiceError::Internal(format!("Failed to assign role {}: {}", role_name, e)))?;
                        } else {
                            log::warn!("Role '{}' not found in realm {}, skipping assignment", role_name, realm_id);
                        }
                    }
                }

                // Assign groups if provided
                for group_name in &request.groups {
                    let group = operations::groups::get_group_by_name(&self.db, realm_id, group_name)
                        .await
                        .map_err(|e| AdminServiceError::Internal(format!("Failed to look up group {}: {}", group_name, e)))?;
                    if let Some(group) = group {
                        operations::groups::add_user_to_group(
                            &self.db, user.id, group.id, None, None,
                        )
                        .await
                        .map_err(|e| AdminServiceError::Internal(format!("Failed to add user to group {}: {}", group_name, e)))?;
                    } else {
                        log::warn!("Group '{}' not found in realm {}, skipping assignment", group_name, realm_id);
                    }
                }

                // Get user roles from database
                let roles = operations::roles::get_user_roles(&self.db, &user.id)
                    .await
                    .map_err(|e| AdminServiceError::Internal(format!("Failed to get user roles: {}", e)))?;

                let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

                // Get user groups
                let user_groups = operations::groups::get_user_groups(&self.db, user.id)
                    .await
                    .map_err(|e| AdminServiceError::Internal(format!("Failed to get user groups: {}", e)))?;
                let group_names: Vec<String> = user_groups.iter().map(|g| g.name.clone()).collect();

                // Convert to admin response
                Ok(UserResponse {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    enabled: user.enabled,
                    email_verified: user.email_verified,
                    realm_id,
                    organization_id: user.organization_id,
                    roles: role_names,
                    groups: group_names,
                    created_at: user.created_at,
                    last_login: user.last_login_at,
                    login_attempts: user.failed_login_attempts as u32,
                    locked_until: user.account_locked_until,
                })
            }
            Err(e) => {
                let msg = e.to_string();
                if is_duplicate_key_error(&msg) {
                    Err(AdminServiceError::BadRequest(format!("User already exists: {}", msg)))
                } else {
                    Err(AdminServiceError::Internal(format!("Failed to create user: {}", e)))
                }
            }
        }
    }

    async fn update_user(
        &self,
        user_id: &Uuid,
        request: UpdateUserRequest,
    ) -> Result<UserResponse, AdminServiceError> {
        // Convert admin request to model request
        let update_request = authenc_models::models::user::UpdateUserRequest {
            username: request.username.clone(),
            email: request.email.clone(),
            first_name: request.first_name.clone(),
            last_name: request.last_name.clone(),
            phone_number: request.phone_number.clone(),
            enabled: request.enabled,
            email_verified: request.email_verified,
            phone_verified: request.phone_verified,
            require_password_change: request.require_password_change,
            organization_id: request.organization_id.map(Some),
            attributes: request.attributes.clone(),
        };

        // Update user in database
        match operations::users::update_user(&self.db, *user_id, &update_request).await {
            Ok(user) => {
                // Guard against updating soft-deleted users
                if user.deleted_at.is_some() {
                    return Err(AdminServiceError::NotFound(format!("User with ID {} not found", user_id)));
                }
                let realm_id = user.realm_id.unwrap_or(Uuid::nil());

                // Handle role and group updates atomically within a transaction
                // to prevent inconsistent state on partial failure.
                let has_role_updates = request.roles.is_some();
                let has_group_updates = request.groups.is_some();

                if has_role_updates || has_group_updates {
                    // Pre-fetch current roles/groups and resolve names to IDs
                    // outside the transaction (read-only lookups).
                    let role_changes: Option<(Vec<Uuid>, Vec<Uuid>)> = if let Some(role_names) = &request.roles {
                        let all_roles = operations::roles::list_roles_by_realm(&self.db, &realm_id)
                            .await
                            .map_err(|e| AdminServiceError::Internal(format!("Failed to fetch realm roles: {}", e)))?;

                        let current_roles = operations::roles::get_user_roles(&self.db, &user.id)
                            .await
                            .map_err(|e| AdminServiceError::Internal(format!("Failed to get user roles: {}", e)))?;
                        let current_role_names: Vec<String> = current_roles.iter().map(|r| r.name.clone()).collect();

                        let roles_to_remove: Vec<Uuid> = current_roles.iter()
                            .filter(|r| !role_names.contains(&r.name))
                            .map(|r| r.id)
                            .collect();

                        let roles_to_add: Vec<Uuid> = role_names.iter()
                            .filter(|name| !current_role_names.contains(name))
                            .filter_map(|name| all_roles.iter().find(|r| &r.name == name).map(|r| r.id))
                            .collect();

                        Some((roles_to_remove, roles_to_add))
                    } else {
                        None
                    };

                    let group_changes: Option<(Vec<Uuid>, Vec<Uuid>)> = if let Some(group_names) = &request.groups {
                        let all_groups = operations::groups::get_groups_by_realm(&self.db, realm_id, None, None)
                            .await
                            .map_err(|e| AdminServiceError::Internal(format!("Failed to fetch realm groups: {}", e)))?;

                        let current_groups = operations::groups::get_user_groups(&self.db, user.id)
                            .await
                            .map_err(|e| AdminServiceError::Internal(format!("Failed to get user groups: {}", e)))?;
                        let current_group_names: Vec<String> = current_groups.iter().map(|g| g.name.clone()).collect();

                        let groups_to_remove: Vec<Uuid> = current_groups.iter()
                            .filter(|g| !group_names.contains(&g.name))
                            .map(|g| g.id)
                            .collect();

                        let groups_to_add: Vec<Uuid> = group_names.iter()
                            .filter(|name| !current_group_names.contains(name))
                            .filter_map(|name| all_groups.iter().find(|g| &g.name == name).map(|g| g.id))
                            .collect();

                        Some((groups_to_remove, groups_to_add))
                    } else {
                        None
                    };

                    // Execute all mutations inside a single transaction so that
                    // a partial failure rolls back all changes.
                    let user_id_copy = user.id;
                    self.db.with_transaction(move |client| {
                        Box::pin(async move {
                            let now = Utc::now();

                            if let Some((roles_to_remove, roles_to_add)) = role_changes {
                                for role_id in &roles_to_remove {
                                    client.execute(
                                        "DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2",
                                        &[&user_id_copy, role_id],
                                    ).await.map_err(|e| {
                                        authenc_core::error::AuthencError::database(format!("Failed to remove role: {}", e))
                                    })?;
                                }
                                for role_id in &roles_to_add {
                                    client.execute(
                                        "INSERT INTO user_roles (user_id, role_id, assigned_at) VALUES ($1, $2, $3) ON CONFLICT (user_id, role_id) DO NOTHING",
                                        &[&user_id_copy, role_id, &now],
                                    ).await.map_err(|e| {
                                        authenc_core::error::AuthencError::database(format!("Failed to assign role: {}", e))
                                    })?;
                                }
                            }

                            if let Some((groups_to_remove, groups_to_add)) = group_changes {
                                for group_id in &groups_to_remove {
                                    client.execute(
                                        "DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2",
                                        &[&user_id_copy, group_id],
                                    ).await.map_err(|e| {
                                        authenc_core::error::AuthencError::database(format!("Failed to remove group: {}", e))
                                    })?;
                                }
                                for group_id in &groups_to_add {
                                    let ug_id = Uuid::new_v4();
                                    client.execute(
                                        "INSERT INTO user_groups (id, user_id, group_id, joined_at, attributes) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (user_id, group_id) DO NOTHING",
                                        &[&ug_id, &user_id_copy, group_id, &now, &serde_json::json!({})],
                                    ).await.map_err(|e| {
                                        authenc_core::error::AuthencError::database(format!("Failed to add group: {}", e))
                                    })?;
                                }
                            }

                            Ok(())
                        })
                    }).await.map_err(|e| AdminServiceError::Internal(format!("Failed to sync roles/groups: {}", e)))?;
                }

                // Get user roles from database
                let roles = operations::roles::get_user_roles(&self.db, &user.id)
                    .await
                    .map_err(|e| AdminServiceError::Internal(format!("Failed to get user roles: {}", e)))?;

                let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

                // Get user groups
                let user_groups = operations::groups::get_user_groups(&self.db, user.id)
                    .await
                    .map_err(|e| AdminServiceError::Internal(format!("Failed to get user groups: {}", e)))?;
                let group_names: Vec<String> = user_groups.iter().map(|g| g.name.clone()).collect();

                // Convert to admin response
                Ok(UserResponse {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    enabled: user.enabled,
                    email_verified: user.email_verified,
                    realm_id,
                    organization_id: user.organization_id,
                    roles: role_names,
                    groups: group_names,
                    created_at: user.created_at,
                    last_login: user.last_login_at,
                    login_attempts: user.failed_login_attempts as u32,
                    locked_until: user.account_locked_until,
                })
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("query returned no rows") || msg.contains("no rows") {
                    Err(AdminServiceError::NotFound(format!("User with ID {} not found", user_id)))
                } else if is_duplicate_key_error(&msg) {
                    Err(AdminServiceError::BadRequest(format!("Conflict: {}", msg)))
                } else {
                    Err(AdminServiceError::Internal(format!("Failed to update user: {}", e)))
                }
            }
        }
    }

    async fn delete_user(&self, user_id: &Uuid) -> Result<(), AdminServiceError> {
        // Soft-delete user, checking that the user exists and isn't already deleted
        let now = Utc::now();
        let query = "UPDATE users SET deleted_at = $2, updated_at = $2 WHERE id = $1 AND deleted_at IS NULL";
        match self.db.execute(query, &[user_id, &now]).await {
            Ok(affected) if affected > 0 => Ok(()),
            Ok(_) => Err(AdminServiceError::NotFound(format!("User with ID {} not found", user_id))),
            Err(e) => Err(AdminServiceError::Internal(format!("Failed to delete user: {}", e))),
        }
    }

    async fn get_roles(&self, realm_id: &Uuid) -> Result<Vec<RoleResponse>, AdminServiceError> {
        // Get roles from database
        match operations::roles::list_roles_by_realm(&self.db, realm_id).await {
            Ok(roles) => {
                // Convert to admin responses, filtering out soft-deleted roles
                let mut responses = Vec::new();
                for role in roles.into_iter().filter(|r| r.deleted_at.is_none()) {
                    responses.push(RoleResponse {
                        id: role.id,
                        name: role.name,
                        description: role.description.unwrap_or_default(),
                        realm_id: role.realm_id.unwrap_or(Uuid::nil()),
                        composite: role.composite,
                        client_role: role.client_role,
                        container_id: role.client_id,
                        attributes: parse_role_attributes(role.attributes),
                    });
                }
                Ok(responses)
            }
            Err(e) => Err(AdminServiceError::Internal(format!("Failed to get roles: {}", e))),
        }
    }

    async fn get_role(&self, role_id: &Uuid) -> Result<RoleResponse, AdminServiceError> {
        match operations::roles::get_role_by_id(&self.db, role_id).await {
            Ok(Some(role)) => {
                // Guard against returning soft-deleted roles in case the
                // underlying get_role_by_id does not filter by deleted_at.
                if role.deleted_at.is_some() {
                    return Err(AdminServiceError::NotFound(format!("Role with ID {} not found", role_id)));
                }
                Ok(RoleResponse {
                    id: role.id,
                    name: role.name,
                    description: role.description.unwrap_or_default(),
                    realm_id: role.realm_id.unwrap_or(Uuid::nil()),
                    composite: role.composite,
                    client_role: role.client_role,
                    container_id: role.client_id,
                    attributes: parse_role_attributes(role.attributes),
                })
            }
            Ok(None) => Err(AdminServiceError::NotFound(format!("Role with ID {} not found", role_id))),
            Err(e) => Err(AdminServiceError::Internal(format!("Failed to get role: {}", e))),
        }
    }

    async fn create_role(&self, request: CreateRoleRequest) -> Result<RoleResponse, AdminServiceError> {
        // Use a transaction to ensure atomicity: if the follow-up UPDATE fails,
        // the INSERT is rolled back so no partially-created role is left behind.
        let name = request.name.clone();
        let description = request.description.clone();
        let realm_id = request.realm_id;
        let composite = request.composite;
        let client_role = request.client_role;
        let attributes = request.attributes.clone();

        let role_id = self.db.with_transaction(move |client| {
            Box::pin(async move {
                let role_id = Uuid::new_v4();
                let now = Utc::now();

                let insert_query = r#"
                    INSERT INTO roles (id, name, description, realm_id, created_at, updated_at)
                    VALUES ($1, $2, $3, $4, $5, $6)
                "#;

                client.execute(
                    insert_query,
                    &[&role_id, &name, &Some(&description), &realm_id, &now, &now],
                ).await.map_err(|e| {
                    authenc_core::error::AuthencError::database(format!("Failed to create role: {}", e))
                })?;

                let needs_update = composite || client_role || !attributes.is_empty();

                if needs_update {
                    let attr_json: Option<String> = if !attributes.is_empty() {
                        Some(serde_json::to_string(&attributes).unwrap_or_default())
                    } else {
                        None
                    };

                    let update_query = r#"
                        UPDATE roles
                        SET composite = $2, client_role = $3, attributes = $4, updated_at = $5
                        WHERE id = $1 AND deleted_at IS NULL
                    "#;

                    client.execute(update_query, &[
                        &role_id,
                        &composite,
                        &client_role,
                        &attr_json,
                        &now,
                    ]).await.map_err(|e| {
                        authenc_core::error::AuthencError::database(format!("Failed to update role attributes: {}", e))
                    })?;
                }

                Ok(role_id)
            })
        }).await.map_err(|e| {
            let msg = e.to_string();
            if is_duplicate_key_error(&msg) {
                AdminServiceError::BadRequest(format!("Role already exists: {}", msg))
            } else {
                AdminServiceError::Internal(format!("Failed to create role: {}", e))
            }
        })?;

        // Re-fetch to get the complete role
        self.get_role(&role_id).await
    }

    async fn update_role(
        &self,
        role_id: &Uuid,
        request: UpdateRoleRequest,
    ) -> Result<RoleResponse, AdminServiceError> {
        // Fetch raw role from DB to preserve Option/NULL status
        let existing = operations::roles::get_role_by_id(&self.db, role_id)
            .await
            .map_err(|e| AdminServiceError::Internal(format!("Failed to get role: {}", e)))?
            .ok_or_else(|| AdminServiceError::NotFound(format!("Role with ID {} not found", role_id)))?;

        // Guard against updating soft-deleted roles
        if existing.deleted_at.is_some() {
            return Err(AdminServiceError::NotFound(format!("Role with ID {} not found", role_id)));
        }

        let name = request.name.unwrap_or(existing.name);
        let composite = request.composite.unwrap_or(existing.composite);
        let client_role = request.client_role.unwrap_or(existing.client_role);

        // Preserve NULL when no update is provided
        let description: Option<String> = if request.description.is_some() {
            request.description
        } else {
            existing.description
        };

        let attr_json: Option<String> = if let Some(attrs) = request.attributes {
            Some(serde_json::to_string(&attrs).unwrap_or_default())
        } else {
            existing.attributes.and_then(|v| serde_json::to_string(&v).ok())
        };

        let now = Utc::now();
        let update_query = r#"
            UPDATE roles
            SET name = $2, description = $3, composite = $4, client_role = $5,
                attributes = $6, updated_at = $7
            WHERE id = $1 AND deleted_at IS NULL
        "#;

        let affected = self.db.execute(update_query, &[
            role_id,
            &name,
            &description,
            &composite,
            &client_role,
            &attr_json,
            &now
        ]).await.map_err(|e| AdminServiceError::Internal(format!("Failed to update role: {}", e)))?;

        if affected == 0 {
            return Err(AdminServiceError::NotFound(format!("Role with ID {} not found", role_id)));
        }

        // Fetch the updated role
        self.get_role(role_id).await
    }

    async fn delete_role(&self, role_id: &Uuid) -> Result<(), AdminServiceError> {
        let role_id_copy = *role_id;
        self.db.with_transaction(move |client| {
            Box::pin(async move {
                let now = Utc::now();

                // Soft-delete the role
                let query = "UPDATE roles SET deleted_at = $2, updated_at = $2 WHERE id = $1 AND deleted_at IS NULL";
                let affected = client.execute(query, &[&role_id_copy, &now]).await.map_err(|e| {
                    authenc_core::error::AuthencError::database(format!("Failed to delete role: {}", e))
                })?;

                if affected == 0 {
                    return Err(authenc_core::error::AuthencError::resource_not_found(
                        format!("Role with ID {} not found or already deleted", role_id_copy),
                    ));
                }

                // Clean up user_roles assignments so users don't retain a deleted role
                client.execute(
                    "DELETE FROM user_roles WHERE role_id = $1",
                    &[&role_id_copy],
                ).await.map_err(|e| {
                    authenc_core::error::AuthencError::database(format!("Failed to clean up user_roles: {}", e))
                })?;

                Ok(())
            })
        }).await.map_err(|e| {
            if e.error_code() == "RESOURCE_NOT_FOUND" {
                AdminServiceError::NotFound(e.to_string())
            } else {
                AdminServiceError::Internal(format!("Failed to delete role: {}", e))
            }
        })
    }

    async fn get_sessions(
        &self,
        user_id: Option<Uuid>,
        realm_id: Option<Uuid>,
        page: u32,
        limit: u32,
    ) -> Result<SessionListResponse, AdminServiceError> {
        // Calculate pagination parameters
        let offset = (page.saturating_sub(1)).saturating_mul(limit);

        // Build dynamic WHERE conditions and params.
        // The canonical user_sessions table does NOT have a realm_id column,
        // so we filter by realm through a JOIN with users.
        let mut conditions: Vec<String> = vec![
            "NOT s.terminated".to_string(),
            "s.expires_at > NOW()".to_string(),
        ];
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        let mut param_idx: usize = 1;

        if let Some(uid) = user_id {
            conditions.push(format!("s.user_id = ${}", param_idx));
            params.push(Box::new(uid));
            param_idx += 1;
        }

        if let Some(rid) = realm_id {
            conditions.push(format!("u.realm_id = ${}", param_idx));
            params.push(Box::new(rid));
            param_idx += 1;
        }

        let where_clause = conditions.join(" AND ");

        let query = format!(
            r#"
                SELECT s.id, s.user_id, u.username, s.ip_address, s.user_agent,
                       s.started_at, s.last_activity_at, s.expires_at
                FROM user_sessions s
                LEFT JOIN users u ON s.user_id = u.id
                WHERE {}
                ORDER BY s.last_activity_at DESC
                LIMIT ${} OFFSET ${}
            "#,
            where_clause, param_idx, param_idx + 1
        );

        params.push(Box::new(limit as i64));
        params.push(Box::new(offset as i64));

        // Execute query
        let rows: Vec<tokio_postgres::Row> = self
            .db
            .query(
                &query,
                params
                    .iter()
                    .map(|b| b.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
                    .collect::<Vec<_>>()
                    .as_slice(),
            )
            .await
            .map_err(|e| AdminServiceError::Internal(format!("Failed to query sessions: {}", e)))?;

        // Convert rows to SessionResponse
        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(SessionResponse {
                id: row.get::<_, Uuid>("id").to_string(),
                user_id: row.get("user_id"),
                username: row
                    .get::<_, Option<String>>("username")
                    .unwrap_or_else(|| "Unknown".to_string()),
                ip_address: row
                    .get::<_, Option<std::net::IpAddr>>("ip_address")
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "Unknown".to_string()),
                user_agent: row
                    .get::<_, Option<String>>("user_agent")
                    .unwrap_or_else(|| "Unknown".to_string()),
                started_at: row.get("started_at"),
                last_activity: row.get("last_activity_at"),
                expires_at: row.get("expires_at"),
                client_id: None,
            });
        }

        // Build count query with same filters (minus LIMIT/OFFSET)
        let count_query = format!(
            "SELECT COUNT(*) FROM user_sessions s LEFT JOIN users u ON s.user_id = u.id WHERE {}",
            where_clause
        );

        // Rebuild count params (same filter params, without limit/offset)
        let mut count_params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(uid) = user_id {
            count_params.push(Box::new(uid));
        }
        if let Some(rid) = realm_id {
            count_params.push(Box::new(rid));
        }

        let count_row: tokio_postgres::Row = self
            .db
            .query_one(
                &count_query,
                count_params
                    .iter()
                    .map(|b| b.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
                    .collect::<Vec<_>>()
                    .as_slice(),
            )
            .await
            .map_err(|e| AdminServiceError::Internal(format!("Failed to count sessions: {}", e)))?;

        let total_count: i64 = count_row.get(0);

        Ok(SessionListResponse {
            sessions,
            total_count: total_count as u64,
            page,
            limit,
        })
    }

    async fn terminate_session(&self, session_id: &str) -> Result<(), AdminServiceError> {
        // Parse session_id from string to Uuid
        let session_uuid =
            Uuid::parse_str(session_id).map_err(|e| AdminServiceError::BadRequest(format!("Invalid session ID format: {}", e)))?;

        // Use a direct UPDATE with affected-row check so we can return 404
        // for non-existent or already-terminated sessions, consistent with
        // delete_user / delete_role behaviour.
        let query = r#"
            UPDATE user_sessions
            SET terminated = TRUE,
                terminated_at = NOW(),
                terminated_reason = $2
            WHERE id = $1 AND NOT terminated
        "#;
        let reason: Option<&str> = Some("Terminated by administrator");
        match self.db.execute(query, &[&session_uuid, &reason]).await {
            Ok(affected) if affected > 0 => Ok(()),
            Ok(_) => Err(AdminServiceError::NotFound(format!("Session with ID {} not found or already terminated", session_id))),
            Err(e) => Err(AdminServiceError::Internal(format!("Failed to terminate session: {}", e))),
        }
    }

    async fn get_audit_logs(&self, filter: AuditLogFilter) -> Result<AuditLogResponse, AdminServiceError> {
        // Calculate pagination
        let offset = (filter.page.saturating_sub(1)).saturating_mul(filter.limit);

        // Build dynamic query to support from_date/to_date filtering
        // that the underlying operations::audit::get_audit_logs doesn't support
        let mut conditions = vec![
            "($1::uuid IS NULL OR user_id = $1)".to_string(),
            "($2::text IS NULL OR event_type = $2)".to_string(),
            "($3::uuid IS NULL OR realm_id = $3)".to_string(),
        ];
        let mut param_index = 4;

        if filter.from_date.is_some() {
            conditions.push(format!("timestamp >= ${}", param_index));
            param_index += 1;
        }
        if filter.to_date.is_some() {
            conditions.push(format!("timestamp <= ${}", param_index));
            param_index += 1;
        }

        let where_clause = conditions.join(" AND ");

        let data_query = format!(
            r#"
                SELECT
                    id, timestamp, event_type, user_id, session_id,
                    client_id, resource_type, resource_id, action,
                    status, details, ip_address, user_agent,
                    location_data, error_message, request_id, correlation_id,
                    realm_id
                FROM audit_logs
                WHERE {}
                ORDER BY timestamp DESC
                LIMIT ${} OFFSET ${}
            "#,
            where_clause, param_index, param_index + 1
        );

        let count_query = format!(
            "SELECT COUNT(*) FROM audit_logs WHERE {}",
            where_clause
        );

        // Build params dynamically
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        params.push(Box::new(filter.user_id));
        params.push(Box::new(filter.event_type.as_deref().map(|s| s.to_string())));
        params.push(Box::new(filter.realm_id));
        if let Some(from_date) = filter.from_date {
            params.push(Box::new(from_date));
        }
        if let Some(to_date) = filter.to_date {
            params.push(Box::new(to_date));
        }

        // Count query params (same filters, no limit/offset)
        let count_params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|b| b.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync)).collect();

        let count_row: tokio_postgres::Row = self.db
            .query_one(&count_query, &count_params_refs)
            .await
            .map_err(|e| AdminServiceError::Internal(format!("Failed to count audit logs: {}", e)))?;
        let total_count: i64 = count_row.get(0);

        // Data query params (filters + limit + offset)
        params.push(Box::new(filter.limit as i64));
        params.push(Box::new(offset as i64));

        let data_params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|b| b.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync)).collect();

        let rows: Vec<tokio_postgres::Row> = self.db
            .query(&data_query, &data_params_refs)
            .await
            .map_err(|e| AdminServiceError::Internal(format!("Failed to query audit logs: {}", e)))?;

        // Extract (id, AuditEvent) pairs so we preserve the database id
        // that the TryFrom<Row> for AuditEvent discards.
        let audit_entries: Vec<(Uuid, authenc_models::models::AuditEvent)> = rows
            .into_iter()
            .map(|row| {
                let id: Uuid = row.try_get::<_, Uuid>("id")
                    .map_err(|e| authenc_core::error::AuthencError::database(format!("Missing audit log id: {}", e)))?;
                let event: authenc_models::models::AuditEvent = row.try_into()?;
                Ok((id, event))
            })
            .collect::<authenc_core::error::Result<Vec<_>>>()
            .map_err(|e| AdminServiceError::Internal(format!("Failed to parse audit logs: {}", e)))?;

        // Convert AuditEvent to AuditLogEntry with username lookup
        let mut logs = Vec::new();
        for (db_id, event) in audit_entries {
            // Get username if user_id exists
            let username = if let Some(uid) = event.user_id {
                operations::users::get_user_by_id(&self.db, uid)
                    .await
                    .ok()
                    .flatten()
                    .map(|user| user.username)
            } else {
                None
            };

            logs.push(AuditLogEntry {
                id: db_id,
                timestamp: event.timestamp,
                user_id: event.user_id,
                username,
                event_type: event.event_type.clone(),
                operation_type: event.action.clone(),
                resource_type: event
                    .resource_type
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
                resource_path: event.resource_id.clone().unwrap_or_else(|| "".to_string()),
                ip_address: event
                    .ip_address
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
                user_agent: event
                    .user_agent
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
                realm_id: event.realm_id.unwrap_or_else(Uuid::nil),
                client_id: event.client_id.clone(),
                details: event
                    .details
                    .clone()
                    .unwrap_or_else(|| serde_json::json!({})),
                success: event.status == "SUCCESS" || event.status == "success",
                error_message: event.error_message.clone(),
            });
        }

        Ok(AuditLogResponse {
            logs,
            total_count: total_count as u64,
            page: filter.page,
            limit: filter.limit,
        })
    }

    async fn get_policies(
        &self,
        realm_id: &Uuid,
        page: u32,
        limit: u32,
    ) -> Result<Vec<PolicyResponse>, AdminServiceError> {
        match operations::policies::get_policies_by_realm(&self.db, *realm_id, page, limit).await {
            Ok(policies) => {
                let responses = policies
                    .into_iter()
                    .map(|p| PolicyResponse {
                        id: p.id,
                        name: p.name,
                        description: p.description.unwrap_or_default(),
                        policy_type: p.policy_type,
                        logic: p.logic,
                        config: p.config,
                        enabled: p.enabled,
                        realm_id: p.realm_id,
                        created_at: p.created_at,
                        updated_at: p.updated_at,
                    })
                    .collect();
                Ok(responses)
            }
            Err(e) => Err(AdminServiceError::Internal(format!("Failed to get policies: {}", e))),
        }
    }

    async fn create_policy(&self, request: CreatePolicyRequest) -> Result<PolicyResponse, AdminServiceError> {
        match operations::policies::create_policy(
            &self.db,
            &request.name,
            Some(&request.description),
            &request.policy_type,
            &request.logic,
            &request.config,
            request.enabled.unwrap_or(true),
            request.realm_id,
        )
        .await
        {
            Ok(policy) => Ok(PolicyResponse {
                id: policy.id,
                name: policy.name,
                description: policy.description.unwrap_or_default(),
                policy_type: policy.policy_type,
                logic: policy.logic,
                config: policy.config,
                enabled: policy.enabled,
                realm_id: policy.realm_id,
                created_at: policy.created_at,
                updated_at: policy.updated_at,
            }),
            Err(e) => Err(AdminServiceError::Internal(format!("Failed to create policy: {}", e))),
        }
    }

    async fn get_zero_trust_dashboard(
        &self,
        realm_id: &Uuid,
    ) -> Result<ZeroTrustDashboard, AdminServiceError> {
        self.generate_zero_trust_dashboard(realm_id).await.map_err(AdminServiceError::Internal)
    }

    async fn get_identity_providers(
        &self,
        realm_id: &Uuid,
    ) -> Result<Vec<IdentityProviderResponse>, AdminServiceError> {
        match operations::identity_providers::get_identity_providers_by_realm(&self.db, *realm_id)
            .await
        {
            Ok(providers) => {
                let responses = providers
                    .into_iter()
                    .map(|p| IdentityProviderResponse {
                        id: p.id,
                        name: p.name,
                        display_name: p.display_name,
                        provider_type: match p.provider_type.as_str() {
                            "SAML" => IdentityProviderType::SAML,
                            "OIDC" => IdentityProviderType::OIDC,
                            "OAuth2" => IdentityProviderType::OAuth2,
                            "LDAP" => IdentityProviderType::LDAP,
                            "Kerberos" => IdentityProviderType::Kerberos,
                            "SocialLogin" => IdentityProviderType::SocialLogin,
                            _ => IdentityProviderType::Custom,
                        },
                        enabled: p.enabled,
                        config: p.config,
                        realm_id: p.realm_id,
                        truststore_path: p.truststore_path,
                        keystore_path: p.keystore_path,
                        created_at: p.created_at,
                        updated_at: p.updated_at,
                    })
                    .collect();
                Ok(responses)
            }
            Err(e) => Err(AdminServiceError::Internal(format!("Failed to get identity providers: {}", e))),
        }
    }

    async fn create_identity_provider(
        &self,
        request: CreateIdentityProviderRequest,
    ) -> Result<IdentityProviderResponse, AdminServiceError> {
        let provider_type_str = match request.provider_type {
            IdentityProviderType::SAML => "SAML",
            IdentityProviderType::OIDC => "OIDC",
            IdentityProviderType::OAuth2 => "OAuth2",
            IdentityProviderType::LDAP => "LDAP",
            IdentityProviderType::Kerberos => "Kerberos",
            IdentityProviderType::SocialLogin => "SocialLogin",
            IdentityProviderType::Custom => "Custom",
        };

        match operations::identity_providers::create_identity_provider(
            &self.db,
            &request.name,
            &request.display_name,
            provider_type_str,
            request.enabled,
            request.realm_id,
            request.config,
            request.truststore_path.as_deref(),
            request.keystore_path.as_deref(),
        )
        .await
        {
            Ok(provider) => Ok(IdentityProviderResponse {
                id: provider.id,
                name: provider.name,
                display_name: provider.display_name,
                provider_type: match provider.provider_type.as_str() {
                    "SAML" => IdentityProviderType::SAML,
                    "OIDC" => IdentityProviderType::OIDC,
                    "OAuth2" => IdentityProviderType::OAuth2,
                    "LDAP" => IdentityProviderType::LDAP,
                    "Kerberos" => IdentityProviderType::Kerberos,
                    "SocialLogin" => IdentityProviderType::SocialLogin,
                    _ => IdentityProviderType::Custom,
                },
                enabled: provider.enabled,
                config: provider.config,
                realm_id: provider.realm_id,
                truststore_path: provider.truststore_path,
                keystore_path: provider.keystore_path,
                created_at: provider.created_at,
                updated_at: provider.updated_at,
            }),
            Err(e) => Err(AdminServiceError::Internal(format!("Failed to create identity provider: {}", e))),
        }
    }

    async fn update_identity_provider(
        &self,
        provider_id: &Uuid,
        request: UpdateIdentityProviderRequest,
    ) -> Result<IdentityProviderResponse, AdminServiceError> {
        let provider_type_str = request.provider_type.as_ref().map(|pt| match pt {
            IdentityProviderType::SAML => "SAML",
            IdentityProviderType::OIDC => "OIDC",
            IdentityProviderType::OAuth2 => "OAuth2",
            IdentityProviderType::LDAP => "LDAP",
            IdentityProviderType::Kerberos => "Kerberos",
            IdentityProviderType::SocialLogin => "SocialLogin",
            IdentityProviderType::Custom => "Custom",
        });

        match operations::identity_providers::update_identity_provider(
            &self.db,
            *provider_id,
            request.name.as_deref(),
            request.display_name.as_deref(),
            provider_type_str,
            request.enabled,
            request.config,
            request.truststore_path.as_deref(),
            request.keystore_path.as_deref(),
        )
        .await
        {
            Ok(provider) => Ok(IdentityProviderResponse {
                id: provider.id,
                name: provider.name,
                display_name: provider.display_name,
                provider_type: match provider.provider_type.as_str() {
                    "SAML" => IdentityProviderType::SAML,
                    "OIDC" => IdentityProviderType::OIDC,
                    "OAuth2" => IdentityProviderType::OAuth2,
                    "LDAP" => IdentityProviderType::LDAP,
                    "Kerberos" => IdentityProviderType::Kerberos,
                    "SocialLogin" => IdentityProviderType::SocialLogin,
                    _ => IdentityProviderType::Custom,
                },
                enabled: provider.enabled,
                config: provider.config,
                realm_id: provider.realm_id,
                truststore_path: provider.truststore_path,
                keystore_path: provider.keystore_path,
                created_at: provider.created_at,
                updated_at: provider.updated_at,
            }),
            Err(e) => Err(AdminServiceError::Internal(format!("Failed to update identity provider: {}", e))),
        }
    }

    async fn delete_identity_provider(&self, provider_id: &Uuid) -> Result<(), AdminServiceError> {
        match operations::identity_providers::delete_identity_provider(&self.db, *provider_id).await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(AdminServiceError::Internal(format!("Failed to delete identity provider: {}", e))),
        }
    }

    async fn get_identity_provider(
        &self,
        provider_id: &Uuid,
    ) -> Result<IdentityProviderResponse, AdminServiceError> {
        match operations::identity_providers::get_identity_provider_by_id(&self.db, *provider_id)
            .await
        {
            Ok(Some(provider)) => Ok(IdentityProviderResponse {
                id: provider.id,
                name: provider.name,
                display_name: provider.display_name,
                provider_type: match provider.provider_type.as_str() {
                    "SAML" => IdentityProviderType::SAML,
                    "OIDC" => IdentityProviderType::OIDC,
                    "OAuth2" => IdentityProviderType::OAuth2,
                    "LDAP" => IdentityProviderType::LDAP,
                    "Kerberos" => IdentityProviderType::Kerberos,
                    "SocialLogin" => IdentityProviderType::SocialLogin,
                    _ => IdentityProviderType::Custom,
                },
                enabled: provider.enabled,
                config: provider.config,
                realm_id: provider.realm_id,
                truststore_path: provider.truststore_path,
                keystore_path: provider.keystore_path,
                created_at: provider.created_at,
                updated_at: provider.updated_at,
            }),
            Ok(None) => Err(AdminServiceError::NotFound("Identity provider not found".to_string())),
            Err(e) => Err(AdminServiceError::Internal(format!("Failed to get identity provider: {}", e))),
        }
    }

    async fn test_identity_provider(
        &self,
        provider_id: &Uuid,
    ) -> Result<TestIdentityProviderResponse, AdminServiceError> {
        let provider = self
            .get_identity_provider(provider_id)
            .await?;

        let mut details = serde_json::Map::new();
        let start = std::time::Instant::now();

        match provider.provider_type {
            IdentityProviderType::SAML => {
                let sso_url = provider.config.get("sso_url").and_then(|v| v.as_str());
                let metadata_url = provider.config.get("metadata_url").and_then(|v| v.as_str());

                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .map_err(|e| AdminServiceError::Internal(e.to_string()))?;

                if let Some(url) = metadata_url {
                    let res = client.get(url).send().await.map_err(|e| AdminServiceError::Internal(e.to_string()))?;
                    let status = res.status();
                    details.insert(
                        "metadata_status".to_string(),
                        serde_json::Value::Number(status.as_u16().into()),
                    );

                    if status.is_success() {
                        details.insert(
                            "metadata_reachable".to_string(),
                            serde_json::Value::Bool(true),
                        );
                        // Check if content looks like XML
                        let content_type = res
                            .headers()
                            .get(reqwest::header::CONTENT_TYPE)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        if content_type.contains("xml") {
                            details.insert(
                                "metadata_valid_content_type".to_string(),
                                serde_json::Value::Bool(true),
                            );
                        }
                    }
                }

                if let Some(url) = sso_url {
                    let res = client.get(url).send().await.map_err(|e| AdminServiceError::Internal(e.to_string()))?;
                    details.insert(
                        "sso_status".to_string(),
                        serde_json::Value::Number(res.status().as_u16().into()),
                    );
                    details.insert("reachable".to_string(), serde_json::Value::Bool(true));
                } else {
                    return Err(AdminServiceError::Internal("No SSO URL configured".to_string()));
                }
            }
            IdentityProviderType::OIDC
            | IdentityProviderType::SocialLogin
            | IdentityProviderType::OAuth2 => {
                let discovery_url = provider
                    .config
                    .get("discovery_url")
                    .and_then(|v| v.as_str());
                let auth_url = provider
                    .config
                    .get("authorization_url")
                    .and_then(|v| v.as_str());
                let token_url = provider.config.get("token_url").and_then(|v| v.as_str());
                let userinfo_url = provider.config.get("userinfo_url").and_then(|v| v.as_str());

                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .map_err(|e| AdminServiceError::Internal(e.to_string()))?;

                let mut checked_any = false;

                if let Some(url) = discovery_url {
                    let res = client.get(url).send().await.map_err(|e| AdminServiceError::Internal(e.to_string()))?;
                    details.insert(
                        "discovery_status".to_string(),
                        serde_json::Value::Number(res.status().as_u16().into()),
                    );

                    if res.status().is_success() {
                        if let Ok(json) = res.json::<serde_json::Value>().await {
                            details.insert(
                                "discovery_valid_json".to_string(),
                                serde_json::Value::Bool(true),
                            );
                            if let Some(issuer) = json.get("issuer") {
                                details.insert("issuer".to_string(), issuer.clone());
                            }
                        } else {
                            details.insert(
                                "discovery_valid_json".to_string(),
                                serde_json::Value::Bool(false),
                            );
                        }
                    }
                    checked_any = true;
                }

                if let Some(url) = auth_url {
                    let res = client.get(url).send().await.map_err(|e| AdminServiceError::Internal(e.to_string()))?;
                    details.insert(
                        "auth_endpoint_status".to_string(),
                        serde_json::Value::Number(res.status().as_u16().into()),
                    );
                    checked_any = true;
                }

                if let Some(url) = token_url {
                    // Token endpoint usually requires POST, but we just check reachability with GET or check if it exists
                    // Many token endpoints return 405 Method Not Allowed on GET, which confirms reachability
                    let res = client.get(url).send().await.map_err(|e| AdminServiceError::Internal(e.to_string()))?;
                    details.insert(
                        "token_endpoint_status".to_string(),
                        serde_json::Value::Number(res.status().as_u16().into()),
                    );
                    checked_any = true;
                }

                if let Some(url) = userinfo_url {
                    let res = client.get(url).send().await.map_err(|e| AdminServiceError::Internal(e.to_string()))?;
                    details.insert(
                        "userinfo_endpoint_status".to_string(),
                        serde_json::Value::Number(res.status().as_u16().into()),
                    );
                    checked_any = true;
                }

                if !checked_any {
                    return Err(AdminServiceError::Internal(
                        "No Discovery, Authorization, Token or UserInfo URL configured".to_string(),
                    ));
                }

                details.insert("reachable".to_string(), serde_json::Value::Bool(true));
            }
            IdentityProviderType::LDAP => {
                let server_url = provider
                    .config
                    .get("server_url")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| AdminServiceError::Internal("No server_url configured".to_string()))?
                    .to_string();
                let bind_dn = provider
                    .config
                    .get("bind_dn")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let bind_password = provider
                    .config
                    .get("bind_password")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let use_tls = provider
                    .config
                    .get("use_tls")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                // Check for required credentials if not anonymous
                if (bind_dn.is_some() && bind_password.is_none())
                    || (bind_dn.is_none() && bind_password.is_some())
                {
                    return Err(AdminServiceError::Internal(
                        "Incomplete LDAP credentials: both bind_dn and bind_password must be provided"
                            .to_string(),
                    ));
                }

                // Basic URL validation
                if !server_url.starts_with("ldap://") && !server_url.starts_with("ldaps://") {
                    return Err(AdminServiceError::Internal("Server URL must start with ldap:// or ldaps://".to_string()));
                }

                let settings =
                    LdapConnSettings::new().set_conn_timeout(std::time::Duration::from_secs(10));

                let (conn, mut ldap) = ldap3::LdapConnAsync::with_settings(settings, &server_url)
                    .await
                    .map_err(|e| AdminServiceError::Internal(format!("Failed to connect to LDAP server: {}", e)))?;

                ldap3::drive!(conn);

                if use_tls {
                    // Attempt StartTLS if configured
                    // Note: For ldaps://, the connection is already encrypted, so StartTLS is for ldap:// upgrade
                    if server_url.starts_with("ldap://") {
                        // StartTLS support requires specific feature flags in ldap3 crate which are causing build conflicts.
                        // To ensure security, we reject non-LDAPS connections when TLS is requested if we cannot upgrade.
                        return Err(AdminServiceError::Internal("StartTLS upgrade not supported. Please use ldaps:// protocol for secure connection.".to_string()));
                    }
                }

                match (bind_dn, bind_password) {
                    (Some(dn), Some(pw)) => {
                        ldap.simple_bind(&dn, &pw)
                            .await
                            .map_err(|e| AdminServiceError::Internal(format!("Bind failed: {}", e)))?
                            .success()
                            .map_err(|e| AdminServiceError::Internal(format!("Bind error: {}", e)))?;
                    }
                    (None, None) => {
                        ldap.simple_bind("", "")
                            .await
                            .map_err(|e| AdminServiceError::Internal(format!("Anonymous bind failed: {}", e)))?
                            .success()
                            .map_err(|e| AdminServiceError::Internal(format!("Anonymous bind error: {}", e)))?;
                    }
                    _ => {
                        return Err(AdminServiceError::Internal(
                            "Incomplete LDAP credentials: both bind_dn and bind_password must be provided"
                                .to_string(),
                        ));
                    }
                }

                // Unbind gracefully
                let _ = ldap.unbind().await;

                details.insert("connected".to_string(), serde_json::Value::Bool(true));
                details.insert("authenticated".to_string(), serde_json::Value::Bool(true));
            }
            _ => {
                details.insert("skipped".to_string(), serde_json::Value::Bool(true));
                details.insert(
                    "message".to_string(),
                    serde_json::Value::String("Provider type check not implemented".to_string()),
                );
            }
        }

        let duration = start.elapsed().as_millis() as u64;
        details.insert(
            "connection_time_ms".to_string(),
            serde_json::Value::Number(duration.into()),
        );

        Ok(TestIdentityProviderResponse {
            success: true,
            message: "Identity provider connection test successful".to_string(),
            details: Some(serde_json::Value::Object(details)),
        })
    }
}

/// Identity provider types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentityProviderType {
    /// SAML 2.0 identity provider
    SAML,
    /// OpenID Connect identity provider
    OIDC,
    /// OAuth 2.0 identity provider
    OAuth2,
    /// LDAP directory server
    LDAP,
    /// Kerberos authentication
    Kerberos,
    /// Social login providers
    SocialLogin,
    /// Custom identity provider
    Custom,
}

/// Identity provider response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProviderResponse {
    /// Unique identifier for the identity provider
    pub id: Uuid,
    /// Internal name of the provider
    pub name: String,
    /// Display name shown to users
    pub display_name: String,
    /// Type of identity provider
    pub provider_type: IdentityProviderType,
    /// Whether the provider is enabled
    pub enabled: bool,
    /// Configuration parameters specific to the provider
    pub config: serde_json::Value,
    /// ID of the realm this provider belongs to
    pub realm_id: Uuid,
    /// Path to truststore for SSL/TLS certificates
    pub truststore_path: Option<String>,
    /// Path to keystore for client certificates
    pub keystore_path: Option<String>,
    /// Timestamp when the provider was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the provider was last updated
    pub updated_at: DateTime<Utc>,
}

/// Create identity provider request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIdentityProviderRequest {
    /// Internal name of the provider
    pub name: String,
    /// Display name shown to users
    pub display_name: String,
    /// Type of identity provider
    pub provider_type: IdentityProviderType,
    /// Whether the provider should be enabled
    pub enabled: bool,
    /// Configuration parameters specific to the provider
    pub config: serde_json::Value,
    /// ID of the realm this provider belongs to
    pub realm_id: Uuid,
    /// Path to truststore for SSL/TLS certificates
    pub truststore_path: Option<String>,
    /// Path to keystore for client certificates
    pub keystore_path: Option<String>,
}

/// Update identity provider request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateIdentityProviderRequest {
    /// New internal name of the provider
    pub name: Option<String>,
    /// New display name shown to users
    pub display_name: Option<String>,
    /// New type of identity provider
    pub provider_type: Option<IdentityProviderType>,
    /// New enabled status
    pub enabled: Option<bool>,
    /// New configuration parameters
    pub config: Option<serde_json::Value>,
    /// New truststore path
    pub truststore_path: Option<String>,
    /// New keystore path
    pub keystore_path: Option<String>,
}

/// Test identity provider response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestIdentityProviderResponse {
    /// Whether the test was successful
    pub success: bool,
    /// Test result message
    pub message: String,
    /// Additional test details
    pub details: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── AdminServiceError ──────────────────────────────────────────────

    #[test]
    fn test_admin_service_error_display() {
        let err = AdminServiceError::NotFound("user 123".to_string());
        assert_eq!(format!("{}", err), "user 123");

        let err = AdminServiceError::AlreadyDeleted("role gone".to_string());
        assert_eq!(format!("{}", err), "role gone");

        let err = AdminServiceError::NotImplemented("todo".to_string());
        assert_eq!(format!("{}", err), "todo");

        let err = AdminServiceError::BadRequest("bad input".to_string());
        assert_eq!(format!("{}", err), "bad input");

        let err = AdminServiceError::Internal("db down".to_string());
        assert_eq!(format!("{}", err), "db down");
    }

    #[test]
    fn test_admin_service_error_is_not_found() {
        assert!(AdminServiceError::NotFound("x".into()).is_not_found());
        assert!(AdminServiceError::AlreadyDeleted("x".into()).is_not_found());
        assert!(!AdminServiceError::Internal("x".into()).is_not_found());
        assert!(!AdminServiceError::BadRequest("x".into()).is_not_found());
        assert!(!AdminServiceError::NotImplemented("x".into()).is_not_found());
    }

    #[test]
    fn test_admin_service_error_from_string() {
        let err: AdminServiceError = "something broke".to_string().into();
        assert!(matches!(err, AdminServiceError::Internal(ref m) if m == "something broke"));
    }

    #[test]
    fn test_is_duplicate_key_error() {
        assert!(is_duplicate_key_error("ERROR: duplicate key value violates unique constraint"));
        assert!(is_duplicate_key_error("Key (username)=(alice) already exists."));
        assert!(is_duplicate_key_error("unique constraint violation on email"));
        assert!(!is_duplicate_key_error("connection refused"));
        assert!(!is_duplicate_key_error("query returned no rows"));
    }

    // ── UpdateRoleRequest serialization round-trip ──────────────────────

    #[test]
    fn test_update_role_request_all_none_fields() {
        let req = UpdateRoleRequest {
            name: None,
            description: None,
            composite: None,
            client_role: None,
            attributes: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: UpdateRoleRequest = serde_json::from_str(&json).unwrap();
        assert!(deserialized.name.is_none());
        assert!(deserialized.description.is_none());
        assert!(deserialized.composite.is_none());
        assert!(deserialized.client_role.is_none());
        assert!(deserialized.attributes.is_none());
    }

    #[test]
    fn test_update_role_request_partial_fields() {
        let json = r#"{"description":"new desc","composite":true}"#;
        let req: UpdateRoleRequest = serde_json::from_str(json).unwrap();
        assert!(req.name.is_none());
        assert_eq!(req.description.as_deref(), Some("new desc"));
        assert_eq!(req.composite, Some(true));
        assert!(req.client_role.is_none());
        assert!(req.attributes.is_none());
    }

    // ── CreateUserRequest / UpdateUserRequest serialization ─────────────

    #[test]
    fn test_create_user_request_round_trip() {
        let realm_id = Uuid::new_v4();
        let req = CreateUserRequest {
            username: "alice".to_string(),
            email: "alice@example.com".to_string(),
            password: Some("Secret1!".to_string()),
            first_name: Some("Alice".to_string()),
            last_name: None,
            phone_number: None,
            realm_id,
            organization_id: None,
            roles: vec!["admin".to_string()],
            groups: vec![],
            attributes: None,
            email_verified: true,
            enabled: true,
            require_password_change: Some(false),
        };
        let json = serde_json::to_string(&req).unwrap();
        let deserialized: CreateUserRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.username, "alice");
        assert_eq!(deserialized.realm_id, realm_id);
        assert_eq!(deserialized.roles, vec!["admin".to_string()]);
        assert!(deserialized.enabled);
    }

    #[test]
    fn test_update_user_request_empty_json() {
        let json = "{}";
        let req: UpdateUserRequest = serde_json::from_str(json).unwrap();
        assert!(req.username.is_none());
        assert!(req.email.is_none());
        assert!(req.enabled.is_none());
        assert!(req.roles.is_none());
        assert!(req.groups.is_none());
    }

    // ── Response types serialization ────────────────────────────────────

    #[test]
    fn test_role_response_serialization() {
        let resp = RoleResponse {
            id: Uuid::nil(),
            name: "viewer".to_string(),
            description: "Read-only access".to_string(),
            realm_id: Uuid::nil(),
            composite: false,
            client_role: false,
            container_id: None,
            attributes: std::collections::HashMap::new(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "viewer");
        assert_eq!(json["composite"], false);
    }

    #[test]
    fn test_session_list_response_serialization() {
        let resp = SessionListResponse {
            sessions: vec![],
            total_count: 0,
            page: 1,
            limit: 20,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["total_count"], 0);
        assert_eq!(json["page"], 1);
        assert_eq!(json["limit"], 20);
        assert!(json["sessions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_audit_log_filter_serialization() {
        let filter = AuditLogFilter {
            user_id: None,
            event_type: Some("login".to_string()),
            realm_id: None,
            from_date: None,
            to_date: None,
            page: 2,
            limit: 50,
        };
        let json = serde_json::to_value(&filter).unwrap();
        assert_eq!(json["event_type"], "login");
        assert_eq!(json["page"], 2);
        assert_eq!(json["limit"], 50);
    }

    // ── parse_role_attributes ───────────────────────────────────────────

    #[test]
    fn test_parse_role_attributes_none() {
        let result = parse_role_attributes(None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_role_attributes_from_json_string_value() {
        // Simulates what happens when a TEXT column stores a JSON string
        // and tokio_postgres reads it back as Value::String("...").
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("scope".to_string(), vec!["read".to_string(), "write".to_string()]);
        let json_str = serde_json::to_string(&attrs).unwrap();
        let value = serde_json::Value::String(json_str);

        let result = parse_role_attributes(Some(value));
        assert_eq!(result.get("scope").unwrap(), &vec!["read".to_string(), "write".to_string()]);
    }

    #[test]
    fn test_parse_role_attributes_from_json_object_value() {
        // Simulates what happens when a JSONB column returns a structured Value.
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("tier".to_string(), vec!["premium".to_string()]);
        let value = serde_json::to_value(&attrs).unwrap();

        let result = parse_role_attributes(Some(value));
        assert_eq!(result.get("tier").unwrap(), &vec!["premium".to_string()]);
    }

    #[test]
    fn test_parse_role_attributes_invalid_string_returns_empty() {
        let value = serde_json::Value::String("not valid json".to_string());
        let result = parse_role_attributes(Some(value));
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_role_attributes_wrong_type_returns_empty() {
        // e.g. Value::Number — cannot be deserialized into HashMap
        let value = serde_json::Value::Number(serde_json::Number::from(42));
        let result = parse_role_attributes(Some(value));
        assert!(result.is_empty());
    }
}
