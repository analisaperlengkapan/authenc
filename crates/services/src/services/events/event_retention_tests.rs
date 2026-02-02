#[cfg(test)]
mod tests {

    use authenc_core::config::EventsConfig;
    use authenc_db::database::Database;
    use crate::services::event_retention::EventRetentionService;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_event_retention_service_creation() {
        let config = EventsConfig {
            enabled: true,
            user_event_retention_days: 90,
            admin_event_retention_days: 365,
            max_cleanup_batch_size: 10000,
            cleanup_interval_hours: 24,
            archive_before_delete: false,
            archive_directory: None,
        };

        // For this test, we'll create a mock database connection
        // In a real test, you'd set up a test database
        let _database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://test:test@localhost:5432/test".to_string());

        // Skip test if database is not available
        if let Ok(database) = Database::new(&authenc_core::config::DatabaseConfig {
            host: "localhost".to_string(),
            port: 5432,
            username: "test".to_string(),
            password: "test".to_string(),
            database: "test".to_string(),
            max_connections: 5,
            connection_timeout: 30,
            audit_log_url: None,
            connection_timeout_seconds: 30,
        })
        .await
        {
            let database = Arc::new(database);

            // Create a mock event store (we'd need to implement this properly)
            // For now, just test that the service can be created
            let _service = EventRetentionService::new(config, database, Arc::new(MockEventStore));
        } else {
            println!("Skipping test: database not available");
        }
    }

    // Mock event store for testing
    struct MockEventStore;

    #[async_trait::async_trait]
    impl crate::services::events::EventStoreProvider for MockEventStore {
        async fn store_event(
            &self,
            _event: &authenc_api::models::events::Event,
        ) -> authenc_api::error::Result<()> {
            Ok(())
        }

        async fn store_admin_event(
            &self,
            _event: &authenc_api::models::events::AdminEvent,
        ) -> authenc_api::error::Result<()> {
            Ok(())
        }

        async fn query_events(
            &self,
            _realm_id: Option<&str>,
            _event_type: Option<&str>,
            _user_id: Option<&str>,
            _client_id: Option<&str>,
            _date_from: Option<chrono::DateTime<chrono::Utc>>,
            _date_to: Option<chrono::DateTime<chrono::Utc>>,
            _first_result: usize,
            _max_results: usize,
        ) -> authenc_api::error::Result<Vec<authenc_api::models::events::Event>> {
            Ok(Vec::new())
        }

        async fn query_admin_events(
            &self,
            _realm_id: Option<&str>,
            _operation_type: Option<&str>,
            _resource_type: Option<&str>,
            _auth_user: Option<&str>,
            _date_from: Option<chrono::DateTime<chrono::Utc>>,
            _date_to: Option<chrono::DateTime<chrono::Utc>>,
            _first_result: usize,
            _max_results: usize,
        ) -> authenc_api::error::Result<Vec<authenc_api::models::events::AdminEvent>> {
            Ok(Vec::new())
        }

        async fn clear_old_events(
            &self,
            _older_than: chrono::DateTime<chrono::Utc>,
        ) -> authenc_api::error::Result<usize> {
            Ok(0)
        }
    }
}
