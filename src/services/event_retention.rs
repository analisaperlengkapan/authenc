use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration as TokioDuration};

use crate::config::EventsConfig;
use crate::database::Database;
use crate::error::{Result, AuthencError as Error};
use crate::services::events::EventStoreProvider;

/// Event retention policy service
pub struct EventRetentionService {
    config: EventsConfig,
    database: Arc<Database>,
    event_store: Arc<dyn EventStoreProvider>,
}

impl EventRetentionService {
    /// Create a new event retention service
    pub fn new(
        config: EventsConfig,
        database: Arc<Database>,
        event_store: Arc<dyn EventStoreProvider>,
    ) -> Self {
        Self {
            config,
            database,
            event_store,
        }
    }

    /// Start the retention cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) {
        if !self.config.enabled {
            tracing::info!("Event retention is disabled, skipping cleanup task");
            return;
        }

        let cleanup_interval = TokioDuration::from_secs(self.config.cleanup_interval_hours as u64 * 3600);
        let self_clone = Arc::clone(&self);

        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);

            loop {
                interval.tick().await;

                if let Err(e) = self_clone.perform_cleanup().await {
                    tracing::error!("Event retention cleanup failed: {}", e);
                }
            }
        });

        tracing::info!(
            "Event retention cleanup task started with interval: {} hours",
            self.config.cleanup_interval_hours
        );
    }

    /// Perform cleanup of old events
    pub async fn perform_cleanup(&self) -> Result<RetentionCleanupResult> {
        if !self.config.enabled {
            return Ok(RetentionCleanupResult::default());
        }

        let now = Utc::now();
        let mut total_deleted = 0;

        // Clean up user events
        let user_cutoff = now - Duration::days(self.config.user_event_retention_days as i64);
        let user_deleted = self.cleanup_user_events(user_cutoff).await?;
        total_deleted += user_deleted;

        // Clean up admin events
        let admin_cutoff = now - Duration::days(self.config.admin_event_retention_days as i64);
        let admin_deleted = self.cleanup_admin_events(admin_cutoff).await?;
        total_deleted += admin_deleted;

        let result = RetentionCleanupResult {
            user_events_deleted: user_deleted,
            admin_events_deleted: admin_deleted,
            total_events_deleted: total_deleted,
            cleanup_time: now,
        };

        tracing::info!(
            "Event retention cleanup completed: {} user events, {} admin events, {} total deleted",
            user_deleted,
            admin_deleted,
            total_deleted
        );

        Ok(result)
    }

    /// Clean up old user events
    async fn cleanup_user_events(&self, cutoff_date: DateTime<Utc>) -> Result<usize> {
        let deleted = self.event_store.clear_old_events(cutoff_date).await?;
        Ok(deleted)
    }

    /// Clean up old admin events
    async fn cleanup_admin_events(&self, cutoff_date: DateTime<Utc>) -> Result<usize> {
        // For now, we'll use the same cutoff for admin events
        // In the future, we could implement separate logic for admin events
        let query = "DELETE FROM admin_events WHERE time < $1";
        let result = self.database
            .execute(query, &[&cutoff_date])
            .await
            .map_err(|e| Error::database(e.to_string()))?;

        Ok(result as usize)
    }

    /// Get retention statistics
    pub async fn get_retention_stats(&self) -> Result<RetentionStats> {
        let now = Utc::now();

        // Count total events
        let total_user_events = self.count_table_rows("events").await?;
        let total_admin_events = self.count_table_rows("admin_events").await?;

        // Count events older than retention periods
        let user_cutoff = now - Duration::days(self.config.user_event_retention_days as i64);
        let admin_cutoff = now - Duration::days(self.config.admin_event_retention_days as i64);

        let expired_user_events = self.count_expired_events("events", user_cutoff).await?;
        let expired_admin_events = self.count_expired_events("admin_events", admin_cutoff).await?;

        Ok(RetentionStats {
            total_user_events,
            total_admin_events,
            expired_user_events,
            expired_admin_events,
            user_retention_days: self.config.user_event_retention_days,
            admin_retention_days: self.config.admin_event_retention_days,
            cleanup_interval_hours: self.config.cleanup_interval_hours,
            last_cleanup_check: now,
        })
    }

    /// Count rows in a table
    async fn count_table_rows(&self, table_name: &str) -> Result<i64> {
        let query = format!("SELECT COUNT(*) FROM {}", table_name);
        let row: tokio_postgres::Row = self.database
            .query_one(&query, &[])
            .await
            .map_err(|e| Error::database(e.to_string()))?;

        let count: i64 = row.get(0);
        Ok(count)
    }

    /// Count expired events in a table
    async fn count_expired_events(&self, table_name: &str, cutoff_date: DateTime<Utc>) -> Result<i64> {
        let query = format!("SELECT COUNT(*) FROM {} WHERE time < $1", table_name);
        let row: tokio_postgres::Row = self.database
            .query_one(&query, &[&cutoff_date])
            .await
            .map_err(|e| Error::database(e.to_string()))?;

        let count: i64 = row.get(0);
        Ok(count)
    }
}

/// Result of a retention cleanup operation
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RetentionCleanupResult {
    /// Number of user events deleted
    pub user_events_deleted: usize,
    /// Number of admin events deleted
    pub admin_events_deleted: usize,
    /// Total number of events deleted
    pub total_events_deleted: usize,
    /// Time when cleanup was performed
    pub cleanup_time: chrono::DateTime<chrono::Utc>,
}

/// Statistics about event retention
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RetentionStats {
    /// Total number of user events in the system
    pub total_user_events: i64,
    /// Total number of admin events in the system
    pub total_admin_events: i64,
    /// Number of user events older than retention period
    pub expired_user_events: i64,
    /// Number of admin events older than retention period
    pub expired_admin_events: i64,
    /// User event retention period in days
    pub user_retention_days: u32,
    /// Admin event retention period in days
    pub admin_retention_days: u32,
    /// Cleanup interval in hours
    pub cleanup_interval_hours: u32,
    /// Last time retention stats were checked
    pub last_cleanup_check: chrono::DateTime<chrono::Utc>,
}
