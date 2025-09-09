use crate::error::AuthencError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Audit log entry model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub user_id: Option<Uuid>,
    pub session_id: Option<String>,
    pub client_id: Option<String>,
    pub realm_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub operation: AuditOperation,
    pub result: AuditResult,
    pub details: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub correlation_id: Option<String>,
}

/// Audit event type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    Login,
    Logout,
    Register,
    PasswordReset,
    ProfileUpdate,
    RoleAssignment,
    PermissionChange,
    TokenIssued,
    TokenRevoked,
    ClientCreated,
    ClientUpdated,
    ClientDeleted,
    UserCreated,
    UserUpdated,
    UserDeleted,
    OrganizationCreated,
    OrganizationUpdated,
    OrganizationDeleted,
    DeviceRegistered,
    DeviceUpdated,
    DeviceDeleted,
    WebauthnCredentialRegistered,
    WebauthnCredentialDeleted,
    SamlAuthnRequest,
    SamlAuthnResponse,
    SamlLogoutRequest,
    SamlLogoutResponse,
    OAuth2AuthzRequest,
    OAuth2AuthzResponse,
    OAuth2TokenRequest,
    OAuth2TokenResponse,
    SecurityEvent,
    AdminAction,
    SystemEvent,
}

/// Audit operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditOperation {
    Create,
    Read,
    Update,
    Delete,
    Authenticate,
    Authorize,
    Logout,
    Register,
    Reset,
    Import,
    Export,
    Backup,
    Restore,
    Configure,
}

/// Audit result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditResult {
    Success,
    Failure,
    Partial,
    Denied,
    Error,
}

/// Audit event for creating audit log entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub user_id: Option<Uuid>,
    pub session_id: Option<String>,
    pub client_id: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub action: String,
    pub status: String,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub location_data: Option<String>,
    pub error_message: Option<String>,
    pub request_id: Option<String>,
    pub correlation_id: Option<String>,
}

/// Audit log filter for queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogFilter {
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub event_types: Option<Vec<AuditEventType>>,
    pub user_id: Option<Uuid>,
    pub realm_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub client_id: Option<String>,
    pub ip_address: Option<String>,
    pub result: Option<AuditResult>,
    pub operation: Option<AuditOperation>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Audit log summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogSummary {
    pub total_events: i64,
    pub events_by_type: std::collections::HashMap<String, i64>,
    pub events_by_result: std::collections::HashMap<String, i64>,
    pub events_by_user: std::collections::HashMap<String, i64>,
    pub recent_events: Vec<AuditLog>,
    pub time_range: AuditTimeRange,
}

/// Audit time range
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditTimeRange {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

/// Security event model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub user_id: Option<Uuid>,
    pub session_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub details: serde_json::Value,
    pub resolved: bool,
    pub resolved_at: Option<DateTime<Utc>>,
    pub resolved_by: Option<Uuid>,
}

/// Security event type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEventType {
    BruteForceAttempt,
    AccountLockout,
    SuspiciousActivity,
    FailedLogin,
    PasswordCompromised,
    TokenCompromised,
    DeviceCompromised,
    UnusualLocation,
    UnusualTime,
    MultipleFailedAttempts,
    AdminPrivilegeEscalation,
    DataExport,
    ConfigurationChange,
    CertificateIssue,
}

/// Security severity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Audit retention policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRetentionPolicy {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub retention_period_days: i32,
    pub archive_after_days: Option<i32>,
    pub delete_after_days: Option<i32>,
    pub event_types: Vec<AuditEventType>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Audit export job
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditExportJob {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub filter: AuditLogFilter,
    pub format: AuditExportFormat,
    pub status: AuditExportStatus,
    pub file_path: Option<String>,
    pub file_size: Option<i64>,
    pub record_count: Option<i64>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
}

/// Audit export format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditExportFormat {
    Json,
    Csv,
    Xml,
    Parquet,
}

/// Audit export status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditExportStatus {
    Pending,
    Running,
    Completed,
    Failed,
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
        })
    }
}
