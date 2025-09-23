use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::events::{Event, AdminEvent};
use crate::error::Result;

/// Event listener provider trait - SPI for custom event handlers
#[async_trait]
pub trait EventListenerProvider: Send + Sync {
    /// Handle user events (login, register, profile updates, etc.)
    async fn on_event(&self, event: &Event) -> Result<()>;

    /// Handle admin events (user creation, client updates, etc.)
    async fn on_admin_event(&self, event: &AdminEvent, include_representation: bool) -> Result<()>;
}

/// Event store provider trait - SPI for event persistence
#[async_trait]
pub trait EventStoreProvider: Send + Sync {
    /// Store a user event
    async fn store_event(&self, event: &Event) -> Result<()>;

    /// Store an admin event
    async fn store_admin_event(&self, event: &AdminEvent) -> Result<()>;

    /// Query events with filtering
    async fn query_events(
        &self,
        realm_id: Option<&str>,
        event_type: Option<&str>,
        user_id: Option<&str>,
        client_id: Option<&str>,
        date_from: Option<chrono::DateTime<chrono::Utc>>,
        date_to: Option<chrono::DateTime<chrono::Utc>>,
        first_result: usize,
        max_results: usize,
    ) -> Result<Vec<Event>>;

    /// Query admin events with filtering
    async fn query_admin_events(
        &self,
        realm_id: Option<&str>,
        operation_type: Option<&str>,
        resource_type: Option<&str>,
        auth_user: Option<&str>,
        date_from: Option<chrono::DateTime<chrono::Utc>>,
        date_to: Option<chrono::DateTime<chrono::Utc>>,
        first_result: usize,
        max_results: usize,
    ) -> Result<Vec<AdminEvent>>;

    /// Clear old events based on retention policy
    async fn clear_old_events(&self, older_than: chrono::DateTime<chrono::Utc>) -> Result<usize>;
}

/// Event builder for constructing events fluently
pub struct EventBuilder {
    event: Event,
}

impl EventBuilder {
    /// Create a new event builder
    pub fn new(event_type: crate::models::events::EventType, realm_id: String) -> Self {
        Self {
            event: Event::new(event_type, realm_id),
        }
    }

    /// Set realm name
    pub fn realm_name(mut self, name: String) -> Self {
        self.event.realm_name = Some(name);
        self
    }

    /// Set client ID
    pub fn client_id(mut self, client_id: String) -> Self {
        self.event.client_id = Some(client_id);
        self
    }

    /// Set user ID
    pub fn user_id(mut self, user_id: String) -> Self {
        self.event.user_id = Some(user_id);
        self
    }

    /// Set session ID
    pub fn session_id(mut self, session_id: String) -> Self {
        self.event.session_id = Some(session_id);
        self
    }

    /// Set IP address
    pub fn ip_address(mut self, ip: String) -> Self {
        self.event.ip_address = Some(ip);
        self
    }

    /// Set error message
    pub fn error(mut self, error: String) -> Self {
        self.event.error = Some(error);
        self
    }

    /// Add a detail
    pub fn detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.event.details.insert(key.into(), value.into());
        self
    }

    /// Add multiple details
    pub fn details(mut self, details: std::collections::HashMap<String, String>) -> Self {
        self.event.details.extend(details);
        self
    }

    /// Build the event
    pub fn build(self) -> Event {
        self.event
    }
}

/// Admin event builder for constructing admin events fluently
pub struct AdminEventBuilder {
    event: AdminEvent,
}

impl AdminEventBuilder {
    /// Create a new admin event builder
    pub fn new(
        realm_id: String,
        auth_details: crate::models::events::AuthDetails,
        resource_type: crate::models::events::ResourceType,
        operation_type: crate::models::events::OperationType,
        resource_path: String,
    ) -> Self {
        Self {
            event: AdminEvent::new(realm_id, auth_details, resource_type, operation_type, resource_path),
        }
    }

    /// Set realm name
    pub fn realm_name(mut self, name: String) -> Self {
        self.event.realm_name = Some(name);
        self
    }

    /// Set representation
    pub fn representation(mut self, representation: String) -> Self {
        self.event.representation = Some(representation);
        self
    }

    /// Set error message
    pub fn error(mut self, error: String) -> Self {
        self.event.error = Some(error);
        self
    }

    /// Build the admin event
    pub fn build(self) -> AdminEvent {
        self.event
    }
}

/// Event manager - central service for event handling
pub struct EventManager {
    /// List of registered event listeners
    listeners: Vec<Arc<dyn EventListenerProvider>>,
    /// Event store provider
    store_provider: Option<Arc<dyn EventStoreProvider>>,
}

impl EventManager {
    /// Create a new event manager
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
            store_provider: None,
        }
    }

    /// Register an event listener
    pub fn register_listener(&mut self, listener: Arc<dyn EventListenerProvider>) {
        self.listeners.push(listener);
    }

    /// Set the event store provider
    pub fn set_store_provider(&mut self, provider: Arc<dyn EventStoreProvider>) {
        self.store_provider = Some(provider);
    }

    /// Fire a user event to all listeners and store it
    pub async fn fire_event(&self, event: Event) -> Result<()> {
        // Store the event if we have a store provider
        if let Some(store) = &self.store_provider {
            store.store_event(&event).await?;
        }

        // Notify all listeners
        for listener in &self.listeners {
            if let Err(e) = listener.on_event(&event).await {
                // Log error but continue with other listeners
                tracing::error!("Event listener error: {}", e);
            }
        }

        Ok(())
    }

    /// Fire an admin event to all listeners and store it
    pub async fn fire_admin_event(&self, event: AdminEvent, include_representation: bool) -> Result<()> {
        // Store the admin event if we have a store provider
        if let Some(store) = &self.store_provider {
            store.store_admin_event(&event).await?;
        }

        // Notify all listeners
        for listener in &self.listeners {
            if let Err(e) = listener.on_admin_event(&event, include_representation).await {
                // Log error but continue with other listeners
                tracing::error!("Admin event listener error: {}", e);
            }
        }

        Ok(())
    }

    /// Query events
    pub async fn query_events(
        &self,
        realm_id: Option<&str>,
        event_type: Option<&str>,
        user_id: Option<&str>,
        client_id: Option<&str>,
        date_from: Option<chrono::DateTime<chrono::Utc>>,
        date_to: Option<chrono::DateTime<chrono::Utc>>,
        first_result: usize,
        max_results: usize,
    ) -> Result<Vec<Event>> {
        if let Some(store) = &self.store_provider {
            store.query_events(realm_id, event_type, user_id, client_id, date_from, date_to, first_result, max_results).await
        } else {
            Ok(Vec::new())
        }
    }

    /// Query admin events
    pub async fn query_admin_events(
        &self,
        realm_id: Option<&str>,
        operation_type: Option<&str>,
        resource_type: Option<&str>,
        auth_user: Option<&str>,
        date_from: Option<chrono::DateTime<chrono::Utc>>,
        date_to: Option<chrono::DateTime<chrono::Utc>>,
        first_result: usize,
        max_results: usize,
    ) -> Result<Vec<AdminEvent>> {
        if let Some(store) = &self.store_provider {
            store.query_admin_events(realm_id, operation_type, resource_type, auth_user, date_from, date_to, first_result, max_results).await
        } else {
            Ok(Vec::new())
        }
    }
}

/// Thread-safe wrapper for EventManager
pub type SharedEventManager = Arc<RwLock<EventManager>>;

/// Create a new shared event manager
pub fn create_shared_event_manager() -> SharedEventManager {
    Arc::new(RwLock::new(EventManager::new()))
}
