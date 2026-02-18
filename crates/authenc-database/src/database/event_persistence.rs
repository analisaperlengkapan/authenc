//! EventPersistenceProvider implementation for Database

use async_trait::async_trait;
use std::sync::Arc;

use authenc_core::error::AuthencError;
use authenc_models::models::events::{AdminEvent, Event};
use authenc_spi::spi::events::{AdminEventQuery, EventQuery};
use authenc_spi::spi::store_traits::EventPersistenceProvider;

use crate::database::Database;
use crate::database::operations;

/// Wrapper around Database that implements EventPersistenceProvider
pub struct DatabaseEventPersistence {
    db: Arc<Database>,
}

impl DatabaseEventPersistence {
    /// Create a new DatabaseEventPersistence from a Database
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl EventPersistenceProvider for DatabaseEventPersistence {
    async fn store_event(&self, event: &Event) -> Result<(), AuthencError> {
        operations::store_event(&self.db, event).await
    }

    async fn store_admin_event(&self, event: &AdminEvent) -> Result<(), AuthencError> {
        operations::store_admin_event(&self.db, event).await
    }

    async fn query_events(&self, query: &EventQuery) -> Result<Vec<Event>, AuthencError> {
        operations::query_events(&self.db, query).await
    }

    async fn query_admin_events(
        &self,
        query: &AdminEventQuery,
    ) -> Result<Vec<AdminEvent>, AuthencError> {
        operations::query_admin_events(&self.db, query).await
    }
}

#[async_trait]
impl EventPersistenceProvider for Database {
    async fn store_event(&self, event: &Event) -> Result<(), AuthencError> {
        operations::store_event(self, event).await
    }

    async fn store_admin_event(&self, event: &AdminEvent) -> Result<(), AuthencError> {
        operations::store_admin_event(self, event).await
    }

    async fn query_events(&self, query: &EventQuery) -> Result<Vec<Event>, AuthencError> {
        operations::query_events(self, query).await
    }

    async fn query_admin_events(
        &self,
        query: &AdminEventQuery,
    ) -> Result<Vec<AdminEvent>, AuthencError> {
        operations::query_admin_events(self, query).await
    }
}
