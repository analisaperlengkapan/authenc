/// Audit log sink interface and implementations
pub mod audit_log_sink;
/// Elasticsearch-based audit log streaming
pub mod elasticsearch_audit_log_sink;
/// Kafka-based audit log streaming
pub mod kafka_audit_log_sink;

pub use audit_log_sink::AuditLogSink;
