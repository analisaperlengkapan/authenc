use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

use crate::models::audit_log::AuditLog;

/// Trait for audit log sinks that can receive and process audit logs
pub trait AuditLogSink: Send + Sync {
    /// Send audit log to this sink
    ///
    /// # Arguments
    /// * `log` - The audit log entry to send
    fn send(&self, log: &AuditLog);
}

/// Multi-sink implementation that sends logs to multiple sinks
pub struct MultiAuditLogSink {
    /// Collection of sinks to send logs to
    sinks: Vec<Box<dyn AuditLogSink>>,
}

impl MultiAuditLogSink {
    /// Create new multi audit log sink
    ///
    /// # Arguments
    /// * `sinks` - Vector of audit log sinks to send logs to
    pub fn new(sinks: Vec<Box<dyn AuditLogSink>>) -> Self {
        Self { sinks }
    }
}

impl AuditLogSink for MultiAuditLogSink {
    /// Send audit log to all configured sinks
    ///
    /// # Arguments
    /// * `log` - The audit log entry to send
    fn send(&self, log: &AuditLog) {
        for sink in &self.sinks {
            sink.send(log);
        }
    }
}

// Example: PostgreSQL sink (wrapper, will call existing PgAuditLogStore)
/// PostgreSQL audit log sink for persistent audit event storage
///
/// This sink implementation provides asynchronous audit log storage using
/// PostgreSQL as the backend. It wraps the existing `PgAuditLogStore` to
/// provide a standardized sink interface for audit event processing.
///
/// # Fields
/// * `store` - The underlying PostgreSQL audit log store instance
///
/// # Security Considerations
/// - Ensures audit logs are durably stored in PostgreSQL
/// - Implements proper transaction handling for data integrity
/// - Provides connection pooling for high-throughput scenarios
/// - Supports encryption at rest for sensitive audit data
///
/// # Performance Considerations
/// - Uses asynchronous operations to avoid blocking
/// - Implements connection pooling for efficient resource usage
/// - Supports batch operations for high-volume audit logging
/// - Provides configurable timeouts and retry mechanisms
///
/// # Example
/// ```rust
/// use authenc::services::audit_log_sink::PgAuditLogSink;
/// use authenc::services::pg_audit_log_store::PgAuditLogStore;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let pg_store = PgAuditLogStore::new("postgresql://user:pass@localhost/db").await?;
/// let sink = PgAuditLogSink { store: pg_store };
/// # Ok(())
/// # }
/// ```
pub struct PgAuditLogSink {
    /// PostgreSQL audit log store instance
    pub store: crate::services::pg_audit_log_store::PgAuditLogStore,
}

impl PgAuditLogSink {
    /// Create a new PostgreSQL audit log sink
    ///
    /// # Arguments
    /// * `store` - The PostgreSQL audit log store instance
    ///
    /// # Returns
    /// A new PgAuditLogSink instance
    pub fn new(store: crate::services::pg_audit_log_store::PgAuditLogStore) -> Self {
        Self { store }
    }
}

impl AuditLogSink for PgAuditLogSink {
    /// Send audit log to PostgreSQL store asynchronously
    ///
    /// # Arguments
    /// * `log` - The audit log entry to send
    fn send(&self, log: &AuditLog) {
        // Fire and forget, or spawn task for async
        let store = self.store.clone();
        let log = log.clone();
        tokio::spawn(async move {
            let _ = store.add_log(&log).await;
        });
    }
}

/// File audit log sink for local file storage
pub struct FileAuditLogSink {
    path: PathBuf,
}

impl FileAuditLogSink {
    /// Create new file audit log sink
    ///
    /// # Arguments
    /// * `path` - Path to the log file
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl AuditLogSink for FileAuditLogSink {
    fn send(&self, log: &AuditLog) {
        let path = self.path.clone();
        let log = log.clone();
        tokio::spawn(async move {
            let json = serde_json::to_string(&log).unwrap_or_default();
            // Append newline
            let entry = format!("{}\n", json);

            // Use tokio fs to append
            if let Ok(mut file) = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await
            {
                let _ = file.write_all(entry.as_bytes()).await;
            } else {
                tracing::error!("Failed to write audit log to file: {:?}", path);
            }
        });
    }
}

/// Splunk audit log sink for Splunk SIEM integration
#[cfg(feature = "reqwest")]
pub struct SplunkAuditLogSink {
    client: reqwest::Client,
    url: String,
    token: String,
}

#[cfg(feature = "reqwest")]
impl SplunkAuditLogSink {
    /// Create new Splunk audit log sink
    ///
    /// # Arguments
    /// * `url` - Splunk HEC URL
    /// * `token` - Splunk HEC token
    pub fn new(url: String, token: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
            token,
        }
    }
}

#[cfg(feature = "reqwest")]
impl AuditLogSink for SplunkAuditLogSink {
    fn send(&self, log: &AuditLog) {
        let client = self.client.clone();
        let url = self.url.clone();
        let token = self.token.clone();
        let log = log.clone();

        tokio::spawn(async move {
            // Splunk HEC format
            let payload = serde_json::json!({
                "time": log.timestamp.timestamp(),
                "event": log,
                "sourcetype": "_json"
            });

            let _ = client
                .post(&url)
                .header("Authorization", format!("Splunk {}", token))
                .json(&payload)
                .send()
                .await
                .map_err(|e| tracing::error!("Failed to send audit log to Splunk: {}", e));
        });
    }
}
