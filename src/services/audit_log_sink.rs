use crate::models::audit_log::AuditLog;

pub trait AuditLogSink: Send + Sync {
    fn send(&self, log: &AuditLog);
}

pub struct MultiAuditLogSink {
    sinks: Vec<Box<dyn AuditLogSink>>,
}

impl MultiAuditLogSink {
    pub fn new(sinks: Vec<Box<dyn AuditLogSink>>) -> Self {
        Self { sinks }
    }
}

impl AuditLogSink for MultiAuditLogSink {
    fn send(&self, log: &AuditLog) {
        for sink in &self.sinks {
            sink.send(log);
        }
    }
}

// Example: PostgreSQL sink (wrapper, will call existing PgAuditLogStore)
pub struct PgAuditLogSink {
    pub store: crate::services::pg_audit_log_store::PgAuditLogStore,
}

impl AuditLogSink for PgAuditLogSink {
    fn send(&self, log: &AuditLog) {
        // Fire and forget, or spawn task for async
        let store = self.store.clone();
        let log = log.clone();
        tokio::spawn(async move {
            let _ = store.add_log(&log).await;
        });
    }
}

// TODO: KafkaAuditLogSink, FileAuditLogSink, etc.
