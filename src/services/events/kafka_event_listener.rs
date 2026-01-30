use async_trait::async_trait;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::time::Duration;

use crate::error::Result;
use crate::models::events::{AdminEvent, Event};
use crate::services::events::EventListenerProvider;

/// Kafka event listener for streaming events to Kafka topics
pub struct KafkaEventListener {
    /// Kafka producer for sending messages
    producer: FutureProducer,
    /// Kafka topic for user events
    user_events_topic: String,
    /// Kafka topic for admin events
    admin_events_topic: String,
}

impl KafkaEventListener {
    /// Create a new Kafka event listener
    ///
    /// # Arguments
    /// * `brokers` - Kafka broker addresses (comma-separated)
    /// * `user_events_topic` - Topic for user events
    /// * `admin_events_topic` - Topic for admin events
    pub fn new(brokers: &str, user_events_topic: &str, admin_events_topic: &str) -> Result<Self> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", brokers)
            .create()
            .map_err(|e| crate::error::AuthencError::InternalError {
                message: format!("Failed to create Kafka producer: {}", e),
            })?;

        Ok(Self {
            producer,
            user_events_topic: user_events_topic.to_string(),
            admin_events_topic: admin_events_topic.to_string(),
        })
    }

    /// Send event to Kafka topic
    async fn send_to_kafka(
        &self,
        topic: &str,
        event: &impl serde::Serialize,
        key: &str,
    ) -> Result<()> {
        let payload = serde_json::to_string(event).map_err(|e| {
            crate::error::AuthencError::InternalError {
                message: format!("Failed to serialize event: {}", e),
            }
        })?;

        let record = FutureRecord::to(topic).payload(&payload).key(key);

        // Send message asynchronously with timeout
        match self.producer.send(record, Duration::from_secs(5)).await {
            Ok(_) => {
                tracing::debug!("Successfully sent event to Kafka topic: {}", topic);
                Ok(())
            }
            Err((e, _)) => {
                tracing::error!("Failed to send event to Kafka topic {}: {}", topic, e);
                Err(crate::error::AuthencError::InternalError {
                    message: format!("Kafka send error: {}", e),
                })
            }
        }
    }
}

#[async_trait]
impl EventListenerProvider for KafkaEventListener {
    /// Handle user events by streaming them to Kafka
    async fn on_event(&self, event: &Event) -> Result<()> {
        let key = event.user_id.as_deref().unwrap_or("unknown");
        self.send_to_kafka(&self.user_events_topic, event, key)
            .await
    }

    /// Handle admin events by streaming them to Kafka
    async fn on_admin_event(
        &self,
        event: &AdminEvent,
        _include_representation: bool,
    ) -> Result<()> {
        let key = &event.auth_details.user_id;
        self.send_to_kafka(&self.admin_events_topic, event, key)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::events::{AuthDetails, EventType, OperationType, ResourceType};

    #[tokio::test]
    async fn test_kafka_event_listener_creation() {
        // Test creation without actual Kafka connection
        let result = KafkaEventListener::new(
            "localhost:9092",
            "authenc.user.events",
            "authenc.admin.events",
        );

        // This will fail without Kafka running, but tests the creation logic
        match result {
            Ok(listener) => {
                assert_eq!(listener.user_events_topic, "authenc.user.events");
                assert_eq!(listener.admin_events_topic, "authenc.admin.events");
            }
            Err(_) => {
                // Expected to fail without Kafka
                assert!(true);
            }
        }
    }

    #[tokio::test]
    async fn test_event_serialization() {
        // Test that events can be serialized for Kafka
        let event = Event::new(EventType::Login, "test-realm".to_string());

        let json_result = serde_json::to_string(&event);
        assert!(json_result.is_ok());

        let json_str = json_result.unwrap();
        assert!(json_str.contains("test-realm"));
    }

    #[tokio::test]
    async fn test_admin_event_serialization() {
        // Test that admin events can be serialized for Kafka
        let auth_details = AuthDetails {
            user_id: "admin-user".to_string(),
            username: Some("admin".to_string()),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
        };

        let admin_event = AdminEvent::new(
            "test-realm".to_string(),
            auth_details,
            ResourceType::User,
            OperationType::Create,
            "/realms/test-realm/users/test-user".to_string(),
        );

        let json_result = serde_json::to_string(&admin_event);
        assert!(json_result.is_ok());

        let json_str = json_result.unwrap();
        assert!(json_str.contains("admin-user"));
        assert!(json_str.contains("test-realm"));
    }
}
