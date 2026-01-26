use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Audit log entry for tracking security and operational events.
///
/// This struct represents a single audit log entry that captures important
/// events, user actions, and system activities for compliance and monitoring
/// purposes. Audit logs are crucial for security analysis, compliance reporting,
/// and forensic investigations.
///
/// # Fields
/// * `timestamp` - When the event occurred (UTC)
/// * `event` - Description of the event or action
/// * `user_id` - ID of the user who performed the action (if applicable)
/// * `client_id` - ID of the client application involved (if applicable)
/// * `status` - Outcome status of the event (success/failure)
/// * `detail` - Additional details about the event
///
/// # Security Considerations
/// - Audit logs should be tamper-proof and immutable once written
/// - Sensitive information should be sanitized before logging
/// - Logs should be stored securely with proper access controls
/// - Retention policies should comply with regulatory requirements
/// - Timestamps should use UTC to ensure consistency across systems
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    /// Timestamp when the audit event occurred (UTC timezone)
    pub timestamp: DateTime<Utc>,
    /// Human-readable description of the event or action being audited
    pub event: String,
    /// Optional user identifier associated with the event
    pub user_id: Option<String>,
    /// Optional client identifier associated with the event
    pub client_id: Option<String>,
    /// Status outcome of the event (e.g., "success", "failure", "error")
    pub status: String,
    /// Optional additional details about the event for context
    pub detail: Option<String>,
}

/// Filter criteria for querying audit logs
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditLogFilter {
    /// Filter by user ID
    pub user_id: Option<String>,
    /// Filter by client ID
    pub client_id: Option<String>,
    /// Filter by status
    pub status: Option<String>,
    /// Filter by start date (inclusive)
    pub start_date: Option<DateTime<Utc>>,
    /// Filter by end date (inclusive)
    pub end_date: Option<DateTime<Utc>>,
}

/// Pagination parameters for queries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    /// Maximum number of items to return
    pub limit: i64,
    /// Number of items to skip
    pub offset: i64,
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            limit: 50,
            offset: 0,
        }
    }
}
