use crate::models::audit_log::{AuditLog, AuditLogFilter};
use anyhow::Result;
use async_trait::async_trait;

/// Audit log storage trait for persistent audit event storage
///
/// This trait defines the interface for storing and retrieving audit log events.
/// Implementations should provide thread-safe, persistent storage of audit events
/// for compliance, security monitoring, and forensic analysis.
///
/// # Security Considerations
/// - Audit logs should be tamper-proof and immutable once written
/// - Implement proper access controls for audit log reading
/// - Ensure audit logs cannot be deleted or modified by regular users
/// - Implement retention policies for long-term storage
/// - Log access to audit logs themselves for compliance
///
/// # Performance Considerations
/// - Implement efficient indexing for common query patterns
/// - Consider asynchronous writes to avoid blocking operations
/// - Implement proper connection pooling for database backends
/// - Cache frequently accessed audit data if appropriate
///
/// # Compliance Requirements
/// - Maintain audit trail integrity (immutable logs)
/// - Support retention periods required by regulations
/// - Enable efficient querying for compliance reporting
/// - Provide tamper-evident storage mechanisms
///
/// # Example Implementation
/// ```rust
/// use async_trait::async_trait;
/// use authenc::services::stores::audit_log_store::AuditLogStore;
/// use authenc::models::audit_log::AuditLog;
///
/// struct DatabaseAuditStore {
///     // database connection
/// }
///
/// #[async_trait]
/// impl AuditLogStore for DatabaseAuditStore {
///     async fn add_log(&self, log: &AuditLog) -> Result<(), anyhow::Error> {
///         // Store audit log in database
///         Ok(())
///     }
///     
///     async fn all(&self) -> Result<Vec<AuditLog>, anyhow::Error> {
///         // Retrieve all audit logs
///         Ok(vec![])
///     }
/// }
/// ```
#[async_trait]
pub trait AuditLogStore: Send + Sync {
    /// Add a new audit log entry to persistent storage
    ///
    /// This method stores an audit log event in the underlying storage backend.
    /// The operation should be atomic and ensure the audit log is durably stored
    /// before returning success.
    ///
    /// # Arguments
    /// * `log` - The audit log entry to store
    ///
    /// # Returns
    /// A `Result` indicating success or failure of the storage operation
    ///
    /// # Security Considerations
    /// - Validate audit log data before storage
    /// - Ensure atomic writes to prevent partial log entries
    /// - Log failures to store audit events (critical for compliance)
    /// - Implement proper error handling without exposing sensitive data
    ///
    /// # Example
    /// ```rust
    /// use authenc::models::audit_log::AuditLog;
    /// use chrono::{DateTime, Utc};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let audit_log = AuditLog {
    ///     timestamp: Utc::now(),
    ///     event: "user_login".to_string(),
    ///     user_id: Some("user123".to_string()),
    ///     client_id: Some("client456".to_string()),
    ///     status: "success".to_string(),
    ///     detail: Some("User logged in from web client".to_string()),
    /// };
    /// // audit_store.add_log(&audit_log).await?;
    /// # Ok(())
    /// # }
    /// ```
    async fn add_log(&self, log: &AuditLog) -> Result<()>;

    /// Retrieve all audit log entries from storage
    ///
    /// This method retrieves all audit log entries from the storage backend.
    /// In production implementations, this should support pagination and filtering
    /// to handle large volumes of audit data efficiently.
    ///
    /// # Returns
    /// A `Result` containing a vector of all audit log entries, or an error
    ///
    /// # Security Considerations
    /// - Implement proper authorization checks for audit log access
    /// - Consider pagination to prevent resource exhaustion
    /// - Log audit log access events for compliance
    /// - Implement rate limiting for audit log queries
    ///
    /// # Performance Considerations
    /// - Implement efficient querying and indexing
    /// - Consider pagination for large result sets
    /// - Cache results if appropriate for the use case
    /// - Optimize database queries for common access patterns
    ///
    /// # Example
    /// ```rust
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // let all_logs = audit_store.all().await?;
    /// // for log in all_logs {
    /// //     println!("Event: {} at {}", log.event, log.timestamp);
    /// // }
    /// # Ok(())
    /// # }
    /// ```
    async fn all(&self) -> Result<Vec<AuditLog>>;

    /// Query audit logs with filtering and pagination
    ///
    /// This method allows for efficient retrieval of audit logs matching specific
    /// criteria, pushing filtering down to the storage layer for better performance.
    ///
    /// # Arguments
    /// * `filter` - The filtering criteria
    ///
    /// # Returns
    /// A `Result` containing a vector of matching audit log entries and the total count
    async fn query(&self, filter: &AuditLogFilter) -> Result<(Vec<AuditLog>, u64)>;
}
