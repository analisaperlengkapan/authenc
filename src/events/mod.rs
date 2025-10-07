//! Event System for Authenc
//!
//! Provides event-driven architecture for audit logging, monitoring, and integrations.
//! Supports synchronous and asynchronous event listeners with retry capabilities.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Event categories for high-level classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventCategory {
    User,
    Admin,
    Auth,
    Session,
    Resource,
    System,
}

/// Event types for specific actions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventType {
    // User events
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserLogin,
    UserLogout,
    UserVerified,
    UserDisabled,
    UserEnabled,

    // Admin events
    AdminAction,
    ResourceCreated,
    ResourceUpdated,
    ResourceDeleted,
    ConfigurationChanged,

    // Auth events
    AuthSuccess,
    AuthFailure,
    TokenIssued,
    TokenRefreshed,
    TokenRevoked,
    MfaRequired,
    MfaSuccess,
    MfaFailure,

    // Session events
    SessionCreated,
    SessionExpired,
    SessionTerminated,
    SessionRefreshed,

    // System events
    SystemStartup,
    SystemShutdown,
    DatabaseMigration,
    CacheCleared,

    // Custom events
    Custom(String),
}

impl EventType {
    pub fn as_str(&self) -> &str {
        match self {
            EventType::UserCreated => "USER_CREATED",
            EventType::UserUpdated => "USER_UPDATED",
            EventType::UserDeleted => "USER_DELETED",
            EventType::UserLogin => "USER_LOGIN",
            EventType::UserLogout => "USER_LOGOUT",
            EventType::UserVerified => "USER_VERIFIED",
            EventType::UserDisabled => "USER_DISABLED",
            EventType::UserEnabled => "USER_ENABLED",
            EventType::AdminAction => "ADMIN_ACTION",
            EventType::ResourceCreated => "RESOURCE_CREATED",
            EventType::ResourceUpdated => "RESOURCE_UPDATED",
            EventType::ResourceDeleted => "RESOURCE_DELETED",
            EventType::ConfigurationChanged => "CONFIGURATION_CHANGED",
            EventType::AuthSuccess => "AUTH_SUCCESS",
            EventType::AuthFailure => "AUTH_FAILURE",
            EventType::TokenIssued => "TOKEN_ISSUED",
            EventType::TokenRefreshed => "TOKEN_REFRESHED",
            EventType::TokenRevoked => "TOKEN_REVOKED",
            EventType::MfaRequired => "MFA_REQUIRED",
            EventType::MfaSuccess => "MFA_SUCCESS",
            EventType::MfaFailure => "MFA_FAILURE",
            EventType::SessionCreated => "SESSION_CREATED",
            EventType::SessionExpired => "SESSION_EXPIRED",
            EventType::SessionTerminated => "SESSION_TERMINATED",
            EventType::SessionRefreshed => "SESSION_REFRESHED",
            EventType::SystemStartup => "SYSTEM_STARTUP",
            EventType::SystemShutdown => "SYSTEM_SHUTDOWN",
            EventType::DatabaseMigration => "DATABASE_MIGRATION",
            EventType::CacheCleared => "CACHE_CLEARED",
            EventType::Custom(s) => s,
        }
    }
}

/// Event data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Uuid,
    pub realm_id: Uuid,
    pub event_type: EventType,
    pub event_category: EventCategory,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub resource_name: Option<String>,
    pub user_id: Option<Uuid>,
    pub username: Option<String>,
    pub event_data: Option<JsonValue>,
    pub old_value: Option<JsonValue>,
    pub new_value: Option<JsonValue>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub session_id: Option<Uuid>,
    pub correlation_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
}

impl Event {
    pub fn new(realm_id: Uuid, event_type: EventType, event_category: EventCategory) -> Self {
        Self {
            id: Uuid::new_v4(),
            realm_id,
            event_type,
            event_category,
            resource_type: None,
            resource_id: None,
            resource_name: None,
            user_id: None,
            username: None,
            event_data: None,
            old_value: None,
            new_value: None,
            ip_address: None,
            user_agent: None,
            session_id: None,
            correlation_id: None,
            timestamp: Utc::now(),
        }
    }

    pub fn with_resource(mut self, resource_type: &str, resource_id: &str) -> Self {
        self.resource_type = Some(resource_type.to_string());
        self.resource_id = Some(resource_id.to_string());
        self
    }

    pub fn with_user(mut self, user_id: Uuid, username: &str) -> Self {
        self.user_id = Some(user_id);
        self.username = Some(username.to_string());
        self
    }

    pub fn with_data(mut self, data: JsonValue) -> Self {
        self.event_data = Some(data);
        self
    }

    pub fn with_changes(mut self, old: JsonValue, new: JsonValue) -> Self {
        self.old_value = Some(old);
        self.new_value = Some(new);
        self
    }
}

/// Event listener trait for handling events
#[async_trait]
pub trait EventListener: Send + Sync {
    /// Get listener name
    fn name(&self) -> &str;

    /// Get listener type
    fn listener_type(&self) -> &str;

    /// Check if listener is interested in this event type
    fn accepts(&self, event_type: &EventType) -> bool;

    /// Handle an event
    async fn handle(&self, event: &Event) -> Result<(), EventError>;

    /// Whether this listener should be executed asynchronously
    fn is_async(&self) -> bool {
        true
    }

    /// Priority (lower = higher priority)
    fn priority(&self) -> i32 {
        100
    }
}

/// Event bus for dispatching events to listeners
pub struct EventBus {
    listeners: Arc<RwLock<Vec<Arc<dyn EventListener>>>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            listeners: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register a new event listener
    pub async fn register(&self, listener: Arc<dyn EventListener>) {
        let mut listeners = self.listeners.write().await;
        listeners.push(listener);
        // Sort by priority
        listeners.sort_by_key(|l| l.priority());
    }

    /// Dispatch an event to all interested listeners
    pub async fn dispatch(&self, event: Event) -> Vec<ListenerResult> {
        let listeners = self.listeners.read().await;
        let mut results = Vec::new();

        for listener in listeners.iter() {
            if listener.accepts(&event.event_type) {
                let start = std::time::Instant::now();
                let result = listener.handle(&event).await;
                let duration = start.elapsed();

                results.push(ListenerResult {
                    listener_name: listener.name().to_string(),
                    success: result.is_ok(),
                    error: result.err().map(|e| e.to_string()),
                    duration_ms: duration.as_millis() as i32,
                });
            }
        }

        results
    }

    /// Dispatch event asynchronously (fire and forget)
    pub fn dispatch_async(&self, event: Event) {
        let listeners = self.listeners.clone();
        tokio::spawn(async move {
            let listeners = listeners.read().await;
            for listener in listeners.iter() {
                if listener.accepts(&event.event_type) && listener.is_async() {
                    let _ = listener.handle(&event).await;
                }
            }
        });
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of listener execution
#[derive(Debug, Clone)]
pub struct ListenerResult {
    pub listener_name: String,
    pub success: bool,
    pub error: Option<String>,
    pub duration_ms: i32,
}

/// Event error types
#[derive(Debug, Clone)]
pub enum EventError {
    ListenerFailed(String),
    SerializationError(String),
    NetworkError(String),
    Timeout(String),
    Other(String),
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventError::ListenerFailed(msg) => write!(f, "Listener failed: {}", msg),
            EventError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            EventError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            EventError::Timeout(msg) => write!(f, "Timeout: {}", msg),
            EventError::Other(msg) => write!(f, "Event error: {}", msg),
        }
    }
}

impl std::error::Error for EventError {}

/// Built-in logging event listener
pub struct LoggingListener {
    name: String,
    log_level: String,
}

impl LoggingListener {
    pub fn new(name: String, log_level: String) -> Self {
        Self { name, log_level }
    }
}

#[async_trait]
impl EventListener for LoggingListener {
    fn name(&self) -> &str {
        &self.name
    }

    fn listener_type(&self) -> &str {
        "logging"
    }

    fn accepts(&self, _event_type: &EventType) -> bool {
        true // Log all events
    }

    async fn handle(&self, event: &Event) -> Result<(), EventError> {
        // Log event based on level
        match self.log_level.as_str() {
            "debug" => log::debug!("Event: {:?}", event),
            "info" => log::info!(
                "Event {} for {} in realm {}",
                event.event_type.as_str(),
                event.resource_type.as_deref().unwrap_or("unknown"),
                event.realm_id
            ),
            "warn" => log::warn!("Event: {}", event.event_type.as_str()),
            _ => {}
        }
        Ok(())
    }

    fn priority(&self) -> i32 {
        10 // High priority for logging
    }
}

/// Built-in webhook event listener
pub struct WebhookListener {
    name: String,
    url: String,
    http_method: String,
    event_types: Vec<EventType>,
    client: reqwest::Client,
}

impl WebhookListener {
    pub fn new(
        name: String,
        url: String,
        http_method: String,
        event_types: Vec<EventType>,
    ) -> Self {
        Self {
            name,
            url,
            http_method,
            event_types,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
        }
    }
}

#[async_trait]
impl EventListener for WebhookListener {
    fn name(&self) -> &str {
        &self.name
    }

    fn listener_type(&self) -> &str {
        "webhook"
    }

    fn accepts(&self, event_type: &EventType) -> bool {
        self.event_types.is_empty() || self.event_types.contains(event_type)
    }

    async fn handle(&self, event: &Event) -> Result<(), EventError> {
        let method = match self.http_method.to_uppercase().as_str() {
            "POST" => reqwest::Method::POST,
            "PUT" => reqwest::Method::PUT,
            "PATCH" => reqwest::Method::PATCH,
            _ => reqwest::Method::POST,
        };

        let response = self
            .client
            .request(method, &self.url)
            .json(event)
            .send()
            .await
            .map_err(|e| EventError::NetworkError(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(EventError::ListenerFailed(format!(
                "Webhook returned status {}",
                response.status()
            )))
        }
    }

    fn is_async(&self) -> bool {
        true // Webhooks should be async
    }

    fn priority(&self) -> i32 {
        50 // Medium priority
    }
}

/// Built-in metrics event listener
pub struct MetricsListener {
    name: String,
    metrics: Arc<RwLock<HashMap<String, u64>>>,
}

impl MetricsListener {
    pub fn new(name: String) -> Self {
        Self {
            name,
            metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_metrics(&self) -> HashMap<String, u64> {
        self.metrics.read().await.clone()
    }
}

#[async_trait]
impl EventListener for MetricsListener {
    fn name(&self) -> &str {
        &self.name
    }

    fn listener_type(&self) -> &str {
        "metrics"
    }

    fn accepts(&self, _event_type: &EventType) -> bool {
        true // Collect metrics for all events
    }

    async fn handle(&self, event: &Event) -> Result<(), EventError> {
        let mut metrics = self.metrics.write().await;
        let key = event.event_type.as_str().to_string();
        *metrics.entry(key).or_insert(0) += 1;
        Ok(())
    }

    fn priority(&self) -> i32 {
        20 // High priority for metrics
    }
}
