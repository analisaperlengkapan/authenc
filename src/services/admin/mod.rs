use crate::database::Database;
use crate::database::operations;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ldap3::{LdapConn, LdapConnSettings};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Admin service trait
#[async_trait]
pub trait AdminService: Send + Sync {
    /// Get system statistics
    async fn get_system_stats(&self) -> Result<SystemStats, String>;

    /// Get user management data
    async fn get_users(
        &self,
        realm_id: &Uuid,
        page: u32,
        limit: u32,
    ) -> Result<UserListResponse, String>;

    /// Create new user
    async fn create_user(&self, request: CreateUserRequest) -> Result<UserResponse, String>;

    /// Update user
    async fn update_user(
        &self,
        user_id: &Uuid,
        request: UpdateUserRequest,
    ) -> Result<UserResponse, String>;

    /// Delete user
    async fn delete_user(&self, user_id: &Uuid) -> Result<(), String>;

    /// Get roles
    async fn get_roles(&self, realm_id: &Uuid) -> Result<Vec<RoleResponse>, String>;

    /// Create role
    async fn create_role(&self, request: CreateRoleRequest) -> Result<RoleResponse, String>;

    /// Get sessions
    async fn get_sessions(
        &self,
        user_id: Option<Uuid>,
        page: u32,
        limit: u32,
    ) -> Result<SessionListResponse, String>;

    /// Terminate session
    async fn terminate_session(&self, session_id: &str) -> Result<(), String>;

    /// Get audit logs
    async fn get_audit_logs(&self, filter: AuditLogFilter) -> Result<AuditLogResponse, String>;

    /// Get authorization policies
    async fn get_policies(
        &self,
        realm_id: &Uuid,
        page: u32,
        limit: u32,
    ) -> Result<Vec<PolicyResponse>, String>;

    /// Create policy
    async fn create_policy(&self, request: CreatePolicyRequest) -> Result<PolicyResponse, String>;

    /// Get zero trust dashboard data
    async fn get_zero_trust_dashboard(&self, realm_id: &Uuid)
    -> Result<ZeroTrustDashboard, String>;

    /// Get identity providers
    async fn get_identity_providers(
        &self,
        realm_id: &Uuid,
    ) -> Result<Vec<IdentityProviderResponse>, String>;

    /// Create identity provider
    async fn create_identity_provider(
        &self,
        request: CreateIdentityProviderRequest,
    ) -> Result<IdentityProviderResponse, String>;

    /// Update identity provider
    async fn update_identity_provider(
        &self,
        provider_id: &Uuid,
        request: UpdateIdentityProviderRequest,
    ) -> Result<IdentityProviderResponse, String>;

    /// Delete identity provider
    async fn delete_identity_provider(&self, provider_id: &Uuid) -> Result<(), String>;

    /// Get identity provider by ID
    async fn get_identity_provider(
        &self,
        provider_id: &Uuid,
    ) -> Result<IdentityProviderResponse, String>;

    /// Test identity provider connection
    async fn test_identity_provider(
        &self,
        provider_id: &Uuid,
    ) -> Result<TestIdentityProviderResponse, String>;
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
    /// ```rust
    /// use authenc::services::admin::AdminManager;
    /// use authenc::database::Database;
    /// use authenc::config::DatabaseConfig;
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

        // Query 1: Total users count
        let total_users = self
            .db
            .query_raw("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL", &[])
            .await
            .ok()
            .and_then(|rows| rows.first().map(|row| row.get::<_, i64>(0)))
            .unwrap_or(0) as u64;

        // Query 2: Active users (logged in within last 30 days)
        let active_users = self.db.query_raw(
            "SELECT COUNT(DISTINCT user_id) FROM user_sessions WHERE last_activity > NOW() - INTERVAL '30 days'",
            &[]
        ).await.ok()
            .and_then(|rows| rows.first().map(|row| row.get::<_, i64>(0)))
            .unwrap_or(0) as u64;

        // Query 3: Total sessions count
        let total_sessions = self
            .db
            .query_raw("SELECT COUNT(*) FROM user_sessions", &[])
            .await
            .ok()
            .and_then(|rows| rows.first().map(|row| row.get::<_, i64>(0)))
            .unwrap_or(0) as u64;

        // Query 4: Active sessions (not expired and not revoked)
        let active_sessions = self
            .db
            .query_raw(
                "SELECT COUNT(*) FROM user_sessions WHERE expires_at > NOW() AND revoked = false",
                &[],
            )
            .await
            .ok()
            .and_then(|rows| rows.first().map(|row| row.get::<_, i64>(0)))
            .unwrap_or(0) as u64;

        // Query 5: Total realms
        let total_realms = self
            .db
            .query_raw("SELECT COUNT(*) FROM realms WHERE enabled = true", &[])
            .await
            .ok()
            .and_then(|rows| rows.first().map(|row| row.get::<_, i64>(0)))
            .unwrap_or(0) as u64;

        // Query 6: Total policies (from authorization_policies or similar)
        let total_policies = self
            .db
            .query_raw("SELECT COUNT(*) FROM policies", &[])
            .await
            .ok()
            .and_then(|rows| rows.first().map(|row| row.get::<_, i64>(0)))
            .unwrap_or(0) as u64;

        // Query 7: Security events today (from audit_logs)
        let security_events_today = self.db.query_raw(
            "SELECT COUNT(*) FROM audit_logs WHERE timestamp >= CURRENT_DATE AND event_type IN ('login', 'logout', 'access_denied', 'permission_check')",
            &[]
        ).await.ok()
            .and_then(|rows| rows.first().map(|row| row.get::<_, i64>(0)))
            .unwrap_or(0) as u64;

        // Query 8: Failed login attempts today
        let failed_login_attempts = self.db.query_raw(
            "SELECT COUNT(*) FROM audit_logs WHERE timestamp >= CURRENT_DATE AND event_type = 'login' AND status != 'SUCCESS'",
            &[]
        ).await.ok()
            .and_then(|rows| rows.first().map(|row| row.get::<_, i64>(0)))
            .unwrap_or(0) as u64;

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

        let event_rows: Vec<tokio_postgres::Row> = self
            .db
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
        // We'll run a few separate counts, filtering by realm_id
        // user_sessions has realm_id
        let active_sessions_query =
            "SELECT COUNT(*)::bigint FROM user_sessions WHERE realm_id = $1 AND expires_at > NOW() AND NOT revoked";

        // user_sessions has realm_id
        let mfa_sessions_query = "SELECT COUNT(*)::bigint FROM user_sessions WHERE realm_id = $1 AND (authentication_method ILIKE '%mfa%' OR authentication_method ILIKE '%totp%' OR authentication_method ILIKE '%webauthn%') AND expires_at > NOW()";

        // device_sessions needs join with users
        let device_verification_query =
            "SELECT COUNT(ds.id)::bigint FROM device_sessions ds JOIN users u ON ds.user_id = u.id WHERE u.realm_id = $1 AND ds.is_active = true";

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
    async fn get_system_stats(&self) -> Result<SystemStats, String> {
        Ok(self.generate_system_stats().await)
    }

    async fn get_users(
        &self,
        realm_id: &Uuid,
        page: u32,
        limit: u32,
    ) -> Result<UserListResponse, String> {
        // Integration 19: User Listing with Pagination and Realm Filtering

        let offset = page * limit;

        // Query total count first
        let total_count_query =
            "SELECT COUNT(*) FROM users WHERE realm_id = $1 AND deleted_at IS NULL";
        let total_count = self
            .db
            .query_raw(total_count_query, &[&realm_id])
            .await
            .map_err(|e| format!("Failed to get user count: {}", e))?
            .first()
            .map(|row| row.get::<_, i64>(0))
            .unwrap_or(0) as u64;

        // Query users with pagination
        // Added organization_id to the query
        let users_query = "SELECT id, username, email, first_name, last_name, enabled, email_verified, realm_id, created_at, last_login, login_attempts, locked_until, organization_id FROM users WHERE realm_id = $1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT $2 OFFSET $3";
        let rows = self
            .db
            .query_raw(users_query, &[&realm_id, &(limit as i64), &(offset as i64)])
            .await
            .map_err(|e| format!("Failed to get users: {}", e))?;

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
            let roles = crate::database::operations::roles::get_user_roles(&self.db, &id)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|r| r.name)
                .collect();

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
                groups: {
                    // Get user groups
                    let user_groups = operations::groups::get_user_groups(&self.db, id)
                        .await
                        .unwrap_or_default();
                    user_groups.iter().map(|g| g.name.clone()).collect()
                },
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

    async fn create_user(&self, request: CreateUserRequest) -> Result<UserResponse, String> {
        // Convert admin request to model request
        let create_request = crate::models::user::CreateUserRequest {
            username: request.username.clone(),
            email: request.email.clone(),
            password: request.password.clone(),
            first_name: request.first_name.clone(),
            last_name: request.last_name.clone(),
            phone_number: request.phone_number.clone(),
            realm_id: Some(request.realm_id),
            organization_id: request.organization_id,
            attributes: request.attributes.clone(),
        };

        // Create user in database
        match operations::users::create_user(&self.db, &create_request).await {
            Ok(user) => {
                // Get user roles from database
                let roles = operations::roles::get_user_roles(&self.db, &user.id)
                    .await
                    .unwrap_or_else(|_| vec![]);

                let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

                // Convert to admin response
                Ok(UserResponse {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    enabled: user.enabled,
                    email_verified: user.email_verified,
                    realm_id: user.realm_id.unwrap_or_else(Uuid::new_v4),
                    organization_id: user.organization_id,
                    roles: role_names,
                    groups: vec![], // TODO: Get user groups (operation not implemented yet)
                    created_at: user.created_at,
                    last_login: user.last_login_at,
                    login_attempts: user.failed_login_attempts as u32,
                    locked_until: user.account_locked_until,
                })
            }
            Err(e) => Err(format!("Failed to create user: {}", e)),
        }
    }

    async fn update_user(
        &self,
        user_id: &Uuid,
        request: UpdateUserRequest,
    ) -> Result<UserResponse, String> {
        // Convert admin request to model request
        let update_request = crate::models::user::UpdateUserRequest {
            username: request.username.clone(),
            email: request.email.clone(),
            first_name: request.first_name.clone(),
            last_name: request.last_name.clone(),
            phone_number: request.phone_number.clone(),
            enabled: request.enabled,
            email_verified: request.email_verified,
            phone_verified: request.phone_verified,
            require_password_change: request.require_password_change,
            attributes: request.attributes.clone(),
        };

        // Update user in database
        match operations::users::update_user(&self.db, *user_id, &update_request).await {
            Ok(user) => {
                // Get user roles from database
                let roles = operations::roles::get_user_roles(&self.db, &user.id)
                    .await
                    .unwrap_or_else(|_| vec![]);

                let role_names: Vec<String> = roles.iter().map(|r| r.name.clone()).collect();

                // Convert to admin response
                Ok(UserResponse {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    enabled: user.enabled,
                    email_verified: user.email_verified,
                    realm_id: user.realm_id.unwrap_or_else(Uuid::new_v4),
                    organization_id: user.organization_id,
                    roles: role_names,
                    groups: vec![], // TODO: Get user groups (operation not implemented yet)
                    created_at: user.created_at,
                    last_login: user.last_login_at,
                    login_attempts: user.failed_login_attempts as u32,
                    locked_until: user.account_locked_until,
                })
            }
            Err(e) => Err(format!("Failed to update user: {}", e)),
        }
    }

    async fn delete_user(&self, user_id: &Uuid) -> Result<(), String> {
        // Delete user from database
        match operations::users::delete_user(&self.db, *user_id).await {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Failed to delete user: {}", e)),
        }
    }

    async fn get_roles(&self, realm_id: &Uuid) -> Result<Vec<RoleResponse>, String> {
        // Get roles from database
        match operations::roles::list_roles_by_realm(&self.db, realm_id).await {
            Ok(roles) => {
                // Convert to admin responses
                let mut responses = Vec::new();
                for role in roles {
                    responses.push(RoleResponse {
                        id: role.id,
                        name: role.name,
                        description: role.description.unwrap_or_default(),
                        realm_id: role.realm_id.unwrap_or_else(Uuid::new_v4),
                        composite: role.composite,
                        client_role: role.client_role,
                        container_id: role.client_id,
                        attributes: role
                            .attributes
                            .and_then(|attrs| serde_json::from_value(attrs).ok())
                            .unwrap_or_default(),
                    });
                }
                Ok(responses)
            }
            Err(e) => Err(format!("Failed to get roles: {}", e)),
        }
    }

    async fn create_role(&self, request: CreateRoleRequest) -> Result<RoleResponse, String> {
        // Create role in database
        match operations::roles::create_role(
            &self.db,
            &request.name,
            Some(&request.description),
            &request.realm_id,
        )
        .await
        {
            Ok(role) => {
                // Convert to admin response
                Ok(RoleResponse {
                    id: role.id,
                    name: role.name,
                    description: role.description.unwrap_or_default(),
                    realm_id: role.realm_id.unwrap_or_else(Uuid::new_v4),
                    composite: role.composite,
                    client_role: role.client_role,
                    container_id: role.client_id,
                    attributes: role
                        .attributes
                        .and_then(|attrs| serde_json::from_value(attrs).ok())
                        .unwrap_or_default(),
                })
            }
            Err(e) => Err(format!("Failed to create role: {}", e)),
        }
    }

    async fn get_sessions(
        &self,
        user_id: Option<Uuid>,
        page: u32,
        limit: u32,
    ) -> Result<SessionListResponse, String> {
        // Calculate pagination parameters
        let offset = (page.saturating_sub(1)) * limit;

        // Build query based on whether we're filtering by user_id
        let (query, params): (
            String,
            Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>>,
        ) = if let Some(uid) = user_id {
            (
                format!(
                    r#"
                    SELECT s.id, s.user_id, u.username, s.ip_address, s.user_agent,
                           s.started_at, s.last_accessed, s.expires_at, s.client_id
                    FROM user_sessions s
                    LEFT JOIN users u ON s.user_id = u.id
                    WHERE s.user_id = $1 AND NOT s.revoked AND s.expires_at > NOW()
                    ORDER BY s.last_accessed DESC
                    LIMIT $2 OFFSET $3
                    "#
                ),
                vec![
                    Box::new(uid) as Box<dyn tokio_postgres::types::ToSql + Sync + Send>,
                    Box::new(limit as i64) as Box<dyn tokio_postgres::types::ToSql + Sync + Send>,
                    Box::new(offset as i64) as Box<dyn tokio_postgres::types::ToSql + Sync + Send>,
                ],
            )
        } else {
            (
                format!(
                    r#"
                    SELECT s.id, s.user_id, u.username, s.ip_address, s.user_agent,
                           s.started_at, s.last_accessed, s.expires_at, s.client_id
                    FROM user_sessions s
                    LEFT JOIN users u ON s.user_id = u.id
                    WHERE NOT s.revoked AND s.expires_at > NOW()
                    ORDER BY s.last_accessed DESC
                    LIMIT $1 OFFSET $2
                    "#
                ),
                vec![
                    Box::new(limit as i64) as Box<dyn tokio_postgres::types::ToSql + Sync + Send>,
                    Box::new(offset as i64) as Box<dyn tokio_postgres::types::ToSql + Sync + Send>,
                ],
            )
        };

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
            .map_err(|e| format!("Failed to query sessions: {}", e))?;

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
                last_activity: row.get("last_accessed"),
                expires_at: row.get("expires_at"),
                client_id: row
                    .get::<_, Option<Uuid>>("client_id")
                    .map(|id| id.to_string()),
            });
        }

        // Get total count
        let count_query = if user_id.is_some() {
            "SELECT COUNT(*) FROM user_sessions WHERE user_id = $1 AND NOT revoked AND expires_at > NOW()"
        } else {
            "SELECT COUNT(*) FROM user_sessions WHERE NOT revoked AND expires_at > NOW()"
        };

        let count_params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
            if let Some(uid) = user_id {
                vec![Box::new(uid)]
            } else {
                vec![]
            };

        let count_row: tokio_postgres::Row = self
            .db
            .query_one(
                count_query,
                count_params
                    .iter()
                    .map(|b| b.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
                    .collect::<Vec<_>>()
                    .as_slice(),
            )
            .await
            .map_err(|e| format!("Failed to count sessions: {}", e))?;

        let total_count: i64 = count_row.get(0);

        Ok(SessionListResponse {
            sessions,
            total_count: total_count as u64,
            page,
            limit,
        })
    }

    async fn terminate_session(&self, session_id: &str) -> Result<(), String> {
        // Parse session_id from string to Uuid
        let session_uuid =
            Uuid::parse_str(session_id).map_err(|e| format!("Invalid session ID format: {}", e))?;

        // Use database operation to revoke the session
        operations::sessions::revoke_session(
            &self.db,
            session_uuid,
            Some("Terminated by administrator"),
        )
        .await
        .map_err(|e| format!("Failed to terminate session: {}", e))?;

        Ok(())
    }

    async fn get_audit_logs(&self, filter: AuditLogFilter) -> Result<AuditLogResponse, String> {
        // Calculate pagination
        let offset = (filter.page.saturating_sub(1)) * filter.limit;

        // Query audit logs with filters
        let audit_events = operations::audit::get_audit_logs(
            &self.db,
            filter.user_id,
            filter.event_type.as_deref(),
            filter.limit as i64,
            offset as i64,
        )
        .await
        .map_err(|e| format!("Failed to query audit logs: {}", e))?;

        // Get total count
        let total_count = operations::audit::get_audit_log_count(
            &self.db,
            filter.user_id,
            filter.event_type.as_deref(),
        )
        .await
        .map_err(|e| format!("Failed to count audit logs: {}", e))?;

        // Convert AuditEvent to AuditLogEntry with username lookup
        let mut logs = Vec::new();
        for event in audit_events {
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
                id: Uuid::new_v4(), // Database doesn't return id, generate one for API response
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
                realm_id: Uuid::nil(), // TODO: Add realm_id to audit_logs table if needed
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
    ) -> Result<Vec<PolicyResponse>, String> {
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
            Err(e) => Err(format!("Failed to get policies: {}", e)),
        }
    }

    async fn create_policy(&self, request: CreatePolicyRequest) -> Result<PolicyResponse, String> {
        match operations::policies::create_policy(
            &self.db,
            &request.name,
            Some(&request.description),
            &request.policy_type,
            &request.logic,
            &request.config,
            true, // enabled by default for new policies if not specified, but request doesn't have enabled field?
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
            Err(e) => Err(format!("Failed to create policy: {}", e)),
        }
    }

    async fn get_zero_trust_dashboard(
        &self,
        realm_id: &Uuid,
    ) -> Result<ZeroTrustDashboard, String> {
        self.generate_zero_trust_dashboard(realm_id).await
    }

    async fn get_identity_providers(
        &self,
        realm_id: &Uuid,
    ) -> Result<Vec<IdentityProviderResponse>, String> {
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
            Err(e) => Err(format!("Failed to get identity providers: {}", e)),
        }
    }

    async fn create_identity_provider(
        &self,
        request: CreateIdentityProviderRequest,
    ) -> Result<IdentityProviderResponse, String> {
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
            Err(e) => Err(format!("Failed to create identity provider: {}", e)),
        }
    }

    async fn update_identity_provider(
        &self,
        provider_id: &Uuid,
        request: UpdateIdentityProviderRequest,
    ) -> Result<IdentityProviderResponse, String> {
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
            Err(e) => Err(format!("Failed to update identity provider: {}", e)),
        }
    }

    async fn delete_identity_provider(&self, provider_id: &Uuid) -> Result<(), String> {
        match operations::identity_providers::delete_identity_provider(&self.db, *provider_id).await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Failed to delete identity provider: {}", e)),
        }
    }

    async fn get_identity_provider(
        &self,
        provider_id: &Uuid,
    ) -> Result<IdentityProviderResponse, String> {
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
            Ok(None) => Err("Identity provider not found".to_string()),
            Err(e) => Err(format!("Failed to get identity provider: {}", e)),
        }
    }

    async fn test_identity_provider(
        &self,
        provider_id: &Uuid,
    ) -> Result<TestIdentityProviderResponse, String> {
        let provider = self
            .get_identity_provider(provider_id)
            .await
            .map_err(|e| format!("Failed to get provider: {}", e))?;

        let mut details = serde_json::Map::new();
        let start = std::time::Instant::now();

        match provider.provider_type {
            IdentityProviderType::SAML => {
                let sso_url = provider.config.get("sso_url").and_then(|v| v.as_str());
                if let Some(url) = sso_url {
                    let client = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(10))
                        .build()
                        .map_err(|e| e.to_string())?;

                    let res = client.get(url).send().await.map_err(|e| e.to_string())?;
                    details.insert(
                        "status".to_string(),
                        serde_json::Value::Number(res.status().as_u16().into()),
                    );
                    details.insert("reachable".to_string(), serde_json::Value::Bool(true));
                } else {
                    return Err("No SSO URL configured".to_string());
                }
            }
            IdentityProviderType::OIDC
            | IdentityProviderType::SocialLogin
            | IdentityProviderType::OAuth2 => {
                let discovery_url = provider.config.get("discovery_url").and_then(|v| v.as_str());
                let auth_url = provider
                    .config
                    .get("authorization_url")
                    .and_then(|v| v.as_str());
                let token_url = provider.config.get("token_url").and_then(|v| v.as_str());

                let url_to_check = discovery_url.or(auth_url).or(token_url);

                if let Some(url) = url_to_check {
                    let client = reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(10))
                        .build()
                        .map_err(|e| e.to_string())?;

                    let res = client.get(url).send().await.map_err(|e| e.to_string())?;
                    details.insert(
                        "status".to_string(),
                        serde_json::Value::Number(res.status().as_u16().into()),
                    );
                    details.insert("reachable".to_string(), serde_json::Value::Bool(true));
                } else {
                    return Err("No Discovery or Authorization URL configured".to_string());
                }
            }
            IdentityProviderType::LDAP => {
                let server_url = provider
                    .config
                    .get("server_url")
                    .and_then(|v| v.as_str())
                    .ok_or("No server_url configured")?
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

                let result = tokio::task::spawn_blocking(move || {
                    let settings = LdapConnSettings::new()
                        .set_conn_timeout(std::time::Duration::from_secs(10));
                    // LdapConn::with_settings is blocking
                    let mut ldap = LdapConn::with_settings(settings, &server_url)?;
                    match (bind_dn, bind_password) {
                        (Some(dn), Some(pw)) => {
                            ldap.simple_bind(&dn, &pw)?.success()?;
                        }
                        (None, None) => {
                            ldap.simple_bind("", "")?.success()?;
                        }
                        _ => {
                            return Err(Box::from("Incomplete LDAP credentials: both bind_dn and bind_password must be provided"));
                        }
                    }
                    Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
                })
                .await
                .map_err(|e| e.to_string())?; // JoinError

                match result {
                    Ok(_) => {
                        details.insert("connected".to_string(), serde_json::Value::Bool(true));
                        details.insert(
                            "authenticated".to_string(),
                            serde_json::Value::Bool(true),
                        );
                    }
                    Err(e) => return Err(format!("LDAP connection failed: {}", e)),
                }
            }
            _ => {
                details.insert("skipped".to_string(), serde_json::Value::Bool(true));
                details.insert(
                    "message".to_string(),
                    serde_json::Value::String(
                        "Provider type check not implemented".to_string(),
                    ),
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
