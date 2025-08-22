use crate::models::audit_log::AuditLog;
use crate::services::audit_log_sink::AuditLogSink;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::time::Duration;

pub struct KafkaAuditLogSink {
    producer: FutureProducer,
    topic: String,
}

impl KafkaAuditLogSink {
    pub fn new(brokers: &str, topic: &str) -> Result<Self, rdkafka::error::KafkaError> {
        let producer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .create()?;
        Ok(Self {
            producer,
            topic: topic.to_string(),
        })
    }
}

impl AuditLogSink for KafkaAuditLogSink {
    fn send(&self, log: &AuditLog) {
        let payload = serde_json::to_string(log).unwrap_or_default();
        let key_binding = log.user_id.clone().unwrap_or_default();
        let record = FutureRecord::to(&self.topic)
            .payload(&payload)
            .key(&key_binding);
        // Fire and forget: explicitly drop the future to satisfy Clippy
        drop(self.producer.send(record, Duration::from_secs(0)));
    }
}
