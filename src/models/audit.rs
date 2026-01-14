use crate::error::AuthencError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Audit log entry model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    /// Unique identifier for the audit log entry
    pub id: Uuid,
    /// Timestamp when the event occurred
    pub timestamp: DateTime<Utc>,
    /// Type of audit event
    pub event_type: AuditEventType,
    /// ID of the user who performed the action (if applicable)
    pub user_id: Option<Uuid>,
    /// Session ID associated with the event
    pub session_id: Option<String>,
    /// Client ID associated with the event
    pub client_id: Option<String>,
    /// Realm ID where the event occurred
    pub realm_id: Option<Uuid>,
    /// Organization ID where the event occurred
    pub organization_id: Option<Uuid>,
    /// IP address of the client
    pub ip_address: Option<String>,
    /// User agent string from the client
    pub user_agent: Option<String>,
    /// Type of resource being accessed/modified
    pub resource_type: Option<String>,
    /// ID of the specific resource
    pub resource_id: Option<String>,
    /// Operation being performed
    pub operation: AuditOperation,
    /// Result of the operation
    pub result: AuditResult,
    /// Additional details about the event
    pub details: Option<serde_json::Value>,
    /// Error message if the operation failed
    pub error_message: Option<String>,
    /// Correlation ID for tracing related events
    pub correlation_id: Option<String>,
}

/// Audit event type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    /// User login event
    Login,
    /// User logout event
    Logout,
    /// User registration event
    Register,
    /// Password reset event
    PasswordReset,
    /// User profile update event
    ProfileUpdate,
    /// Role assignment event
    RoleAssignment,
    /// Permission change event
    PermissionChange,
    /// Token issued event
    TokenIssued,
    /// Token revoked event
    TokenRevoked,
    /// Client created event
    ClientCreated,
    /// Client updated event
    ClientUpdated,
    /// Client deleted event
    ClientDeleted,
    /// User created event
    UserCreated,
    /// User updated event
    UserUpdated,
    /// User deleted event
    UserDeleted,
    /// Organization created event
    OrganizationCreated,
    /// Organization updated event
    OrganizationUpdated,
    /// Organization deleted event
    OrganizationDeleted,
    /// Device registered event
    DeviceRegistered,
    /// Device updated event
    DeviceUpdated,
    /// Device deleted event
    DeviceDeleted,
    /// WebAuthn credential registered event
    WebauthnCredentialRegistered,
    /// WebAuthn credential deleted event
    WebauthnCredentialDeleted,
    /// SAML authentication request event
    SamlAuthnRequest,
    /// SAML authentication response event
    SamlAuthnResponse,
    /// SAML logout request event
    SamlLogoutRequest,
    /// SAML logout response event
    SamlLogoutResponse,
    /// OAuth2 authorization request event
    OAuth2AuthzRequest,
    /// OAuth2 authorization response event
    OAuth2AuthzResponse,
    /// OAuth2 token request event
    OAuth2TokenRequest,
    /// OAuth2 token response event
    OAuth2TokenResponse,
    /// Security-related event
    SecurityEvent,
    /// Administrative action event
    AdminAction,
    /// System-level event
    SystemEvent,
}

/// Audit operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditOperation {
    /// Create operation
    Create,
    /// Read operation
    Read,
    /// Update operation
    Update,
    /// Delete operation
    Delete,
    /// Authentication operation
    Authenticate,
    /// Authorization operation
    Authorize,
    /// Logout operation
    Logout,
    /// Registration operation
    Register,
    /// Reset operation
    Reset,
    /// Import operation
    Import,
    /// Export operation
    Export,
    /// Backup operation
    Backup,
    /// Restore operation
    Restore,
    /// Configuration operation
    Configure,
}

/// Audit result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditResult {
    /// Operation completed successfully
    Success,
    /// Operation failed
    Failure,
    /// Operation completed partially
    Partial,
    /// Operation was denied
    Denied,
    /// Operation resulted in an error
    Error,
}

/// Audit event for creating audit log entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Timestamp when the event occurred
    pub timestamp: DateTime<Utc>,
    /// Type of the audit event
    pub event_type: String,
    /// ID of the user who performed the action
    pub user_id: Option<Uuid>,
    /// Session ID associated with the event
    pub session_id: Option<String>,
    /// Client ID associated with the event
    pub client_id: Option<String>,
    /// Type of resource being accessed
    pub resource_type: Option<String>,
    /// ID of the specific resource
    pub resource_id: Option<String>,
    /// Action being performed
    pub action: String,
    /// Status of the operation
    pub status: String,
    /// Additional details about the event
    pub details: Option<serde_json::Value>,
    /// IP address of the client
    pub ip_address: Option<String>,
    /// User agent string from the client
    pub user_agent: Option<String>,
    /// Geographic location data
    pub location_data: Option<String>,
    /// Error message if the operation failed
    pub error_message: Option<String>,
    /// Request ID for tracing
    pub request_id: Option<String>,
    /// Correlation ID for tracing related events
    pub correlation_id: Option<String>,
    /// Realm ID where the event occurred
    pub realm_id: Option<Uuid>,
}

/// Audit log filter for queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogFilter {
    /// Start date for filtering audit logs
    pub start_date: Option<DateTime<Utc>>,
    /// End date for filtering audit logs
    pub end_date: Option<DateTime<Utc>>,
    /// Filter by specific event types
    pub event_types: Option<Vec<AuditEventType>>,
    /// Filter by user ID
    pub user_id: Option<Uuid>,
    /// Filter by realm ID
    pub realm_id: Option<Uuid>,
    /// Filter by organization ID
    pub organization_id: Option<Uuid>,
    /// Filter by client ID
    pub client_id: Option<String>,
    /// Filter by IP address
    pub ip_address: Option<String>,
    /// Filter by operation result
    pub result: Option<AuditResult>,
    /// Filter by operation type
    pub operation: Option<AuditOperation>,
    /// Maximum number of results to return
    pub limit: Option<i64>,
    /// Number of results to skip
    pub offset: Option<i64>,
}

/// Audit log summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogSummary {
    /// Total number of audit events
    pub total_events: i64,
    /// Count of events grouped by event type
    pub events_by_type: std::collections::HashMap<String, i64>,
    /// Count of events grouped by result
    pub events_by_result: std::collections::HashMap<String, i64>,
    /// Count of events grouped by user
    pub events_by_user: std::collections::HashMap<String, i64>,
    /// List of recent audit events
    pub recent_events: Vec<AuditLog>,
    /// Time range covered by this summary
    pub time_range: AuditTimeRange,
}

/// Audit time range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTimeRange {
    /// Start timestamp of the time range
    pub start: DateTime<Utc>,
    /// End timestamp of the time range
    pub end: DateTime<Utc>,
}

/// Security event model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique identifier for the security event
    pub id: Uuid,
    /// Timestamp when the security event occurred
    pub timestamp: DateTime<Utc>,
    /// Type of security event
    pub event_type: SecurityEventType,
    /// Severity level of the security event
    pub severity: SecuritySeverity,
    /// ID of the user associated with the event
    pub user_id: Option<Uuid>,
    /// Session ID associated with the event
    pub session_id: Option<String>,
    /// IP address where the event originated
    pub ip_address: Option<String>,
    /// User agent string from the client
    pub user_agent: Option<String>,
    /// Detailed information about the security event
    pub details: serde_json::Value,
    /// Whether the security event has been resolved
    pub resolved: bool,
    /// Timestamp when the event was resolved
    pub resolved_at: Option<DateTime<Utc>>,
    /// ID of the user who resolved the event
    pub resolved_by: Option<Uuid>,
}

/// Security event type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    /// Brute force attack attempt detected
    BruteForceAttempt,
    /// Account has been locked out
    AccountLockout,
    /// Suspicious activity detected
    SuspiciousActivity,
    /// Failed login attempt
    FailedLogin,
    /// Password has been compromised
    PasswordCompromised,
    /// Token has been compromised
    TokenCompromised,
    /// Device has been compromised
    DeviceCompromised,
    /// Login from unusual location
    UnusualLocation,
    /// Login at unusual time
    UnusualTime,
    /// Multiple failed authentication attempts
    MultipleFailedAttempts,
    /// Administrative privilege escalation attempt
    AdminPrivilegeEscalation,
    /// Data export operation
    DataExport,
    /// Configuration change
    ConfigurationChange,
    /// Certificate-related issue
    CertificateIssue,
}

/// Security severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    /// Low severity security event
    Low,
    /// Medium severity security event
    Medium,
    /// High severity security event
    High,
    /// Critical severity security event
    Critical,
}

/// Audit retention policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRetentionPolicy {
    /// Unique identifier for the retention policy
    pub id: Uuid,
    /// Name of the retention policy
    pub name: String,
    /// Description of the retention policy
    pub description: Option<String>,
    /// Number of days to retain audit logs
    pub retention_period_days: i32,
    /// Number of days after which to archive logs
    pub archive_after_days: Option<i32>,
    /// Number of days after which to delete logs
    pub delete_after_days: Option<i32>,
    /// Types of audit events this policy applies to
    pub event_types: Vec<AuditEventType>,
    /// Whether the retention policy is enabled
    pub enabled: bool,
    /// Timestamp when the policy was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the policy was last updated
    pub updated_at: DateTime<Utc>,
}

/// Audit export job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditExportJob {
    /// Unique identifier for the export job
    pub id: Uuid,
    /// Name of the export job
    pub name: String,
    /// Description of the export job
    pub description: Option<String>,
    /// Filter criteria for the audit logs to export
    pub filter: AuditLogFilter,
    /// Format of the exported data
    pub format: AuditExportFormat,
    /// Current status of the export job
    pub status: AuditExportStatus,
    /// File path where the exported data is stored
    pub file_path: Option<String>,
    /// Size of the exported file in bytes
    pub file_size: Option<i64>,
    /// Number of records exported
    pub record_count: Option<i64>,
    /// ID of the user who created the export job
    pub created_by: Uuid,
    /// Timestamp when the export job was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the export job started
    pub started_at: Option<DateTime<Utc>>,
    /// Timestamp when the export job completed
    pub completed_at: Option<DateTime<Utc>>,
    /// Error message if the export job failed
    pub error_message: Option<String>,
}

/// Audit export format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditExportFormat {
    /// Export in JSON format
    Json,
    /// Export in CSV format
    Csv,
    /// Export in XML format
    Xml,
    /// Export in Parquet format
    Parquet,
}

/// Audit export status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditExportStatus {
    /// Export job is pending
    Pending,
    /// Export job is running
    Running,
    /// Export job completed successfully
    Completed,
    /// Export job failed
    Failed,
    /// Export job was cancelled
    Cancelled,
}

impl TryFrom<tokio_postgres::Row> for AuditEvent {
    type Error = AuthencError;

    fn try_from(row: tokio_postgres::Row) -> Result<Self, Self::Error> {
        Ok(AuditEvent {
            timestamp: row.try_get("timestamp")?,
            event_type: row.try_get("event_type")?,
            user_id: row.try_get("user_id")?,
            session_id: row.try_get("session_id")?,
            client_id: row.try_get("client_id")?,
            resource_type: row.try_get("resource_type")?,
            resource_id: row.try_get("resource_id")?,
            action: row.try_get("action")?,
            status: row.try_get("status")?,
            details: {
                let json_str: Option<String> = row.try_get("details")?;
                json_str.and_then(|s| serde_json::from_str(&s).ok())
            },
            ip_address: row.try_get("ip_address")?,
            user_agent: row.try_get("user_agent")?,
            location_data: row.try_get("location_data")?,
            error_message: row.try_get("error_message")?,
            request_id: row.try_get("request_id")?,
            correlation_id: row.try_get("correlation_id")?,
            realm_id: row.try_get("realm_id")?,
        })
    }
}
