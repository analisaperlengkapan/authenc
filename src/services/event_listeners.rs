use async_trait::async_trait;
use std::sync::Arc;

use crate::error::Result;
use crate::models::events::{AdminEvent, Event};
use crate::services::events::EventListenerProvider;

/// Logging event listener that logs events to the configured logger
pub struct LoggingEventListener;

impl Default for LoggingEventListener {
    fn default() -> Self {
        Self::new()
    }
}

impl LoggingEventListener {
    /// Create a new logging event listener
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl EventListenerProvider for LoggingEventListener {
    async fn on_event(&self, event: &Event) -> Result<()> {
        match event.event_type {
            crate::models::events::EventType::Login => {
                tracing::info!(
                    "User login: user_id={}, client_id={}, ip={}",
                    event.user_id.as_deref().unwrap_or("unknown"),
                    event.client_id.as_deref().unwrap_or("unknown"),
                    event.ip_address.as_deref().unwrap_or("unknown")
                );
            }
            crate::models::events::EventType::LoginError => {
                tracing::warn!(
                    "User login failed: user_id={}, client_id={}, ip={}, error={}",
                    event.user_id.as_deref().unwrap_or("unknown"),
                    event.client_id.as_deref().unwrap_or("unknown"),
                    event.ip_address.as_deref().unwrap_or("unknown"),
                    event.error.as_deref().unwrap_or("unknown")
                );
            }
            crate::models::events::EventType::Register => {
                tracing::info!(
                    "User registered: user_id={}, ip={}",
                    event.user_id.as_deref().unwrap_or("unknown"),
                    event.ip_address.as_deref().unwrap_or("unknown")
                );
            }
            crate::models::events::EventType::Logout => {
                tracing::info!(
                    "User logout: user_id={}, session_id={}",
                    event.user_id.as_deref().unwrap_or("unknown"),
                    event.session_id.as_deref().unwrap_or("unknown")
                );
            }
            crate::models::events::EventType::UpdateProfile => {
                tracing::info!(
                    "User profile updated: user_id={}",
                    event.user_id.as_deref().unwrap_or("unknown")
                );
            }
            crate::models::events::EventType::ResetPassword => {
                tracing::info!(
                    "User password reset: user_id={}",
                    event.user_id.as_deref().unwrap_or("unknown")
                );
            }
            // Log other events at debug level
            _ => {
                tracing::debug!(
                    "Event: type={:?}, user_id={}, client_id={}, realm_id={}",
                    event.event_type,
                    event.user_id.as_deref().unwrap_or("unknown"),
                    event.client_id.as_deref().unwrap_or("unknown"),
                    event.realm_id
                );
            }
        }

        Ok(())
    }

    async fn on_admin_event(
        &self,
        event: &AdminEvent,
        _include_representation: bool,
    ) -> Result<()> {
        tracing::info!(
            "Admin event: user={}, operation={:?}, resource={:?}, path={}",
            event
                .auth_details
                .username
                .as_deref()
                .unwrap_or(&event.auth_details.user_id),
            event.operation_type,
            event.resource_type,
            event.resource_path
        );

        Ok(())
    }
}

/// Email event listener that sends email notifications for important events
pub struct EmailEventListener {
    // In a real implementation, this would hold SMTP configuration
    _smtp_server: String,
    _smtp_username: String,
    _smtp_password: String,
}

impl EmailEventListener {
    /// Create a new email event listener
    pub fn new(smtp_server: String, smtp_username: String, smtp_password: String) -> Self {
        Self {
            _smtp_server: smtp_server,
            _smtp_username: smtp_username,
            _smtp_password: smtp_password,
        }
    }
}

#[async_trait]
impl EventListenerProvider for EmailEventListener {
    async fn on_event(&self, event: &Event) -> Result<()> {
        // Send email notifications for critical security events
        match event.event_type {
            crate::models::events::EventType::UserDisabledByPermanentLockout => {
                // Send email to admin about permanent lockout
                tracing::info!(
                    "Would send email notification: User permanently locked out: {}",
                    event.user_id.as_deref().unwrap_or("unknown")
                );
            }
            crate::models::events::EventType::UserDisabledByTemporaryLockout => {
                // Send email to admin about temporary lockout
                tracing::info!(
                    "Would send email notification: User temporarily locked out: {}",
                    event.user_id.as_deref().unwrap_or("unknown")
                );
            }
            _ => {
                // Don't send emails for other events
            }
        }

        Ok(())
    }

    async fn on_admin_event(
        &self,
        event: &AdminEvent,
        _include_representation: bool,
    ) -> Result<()> {
        // Send email notifications for important admin events
        match (&event.operation_type, &event.resource_type) {
            (
                crate::models::events::OperationType::Delete,
                crate::models::events::ResourceType::User,
            ) => {
                tracing::info!(
                    "Would send email notification: User deleted by admin {}",
                    event.auth_details.username.as_deref().unwrap_or("unknown")
                );
            }
            (
                crate::models::events::OperationType::Create,
                crate::models::events::ResourceType::Realm,
            ) => {
                tracing::info!(
                    "Would send email notification: New realm created by admin {}",
                    event.auth_details.username.as_deref().unwrap_or("unknown")
                );
            }
            _ => {
                // Don't send emails for other admin events
            }
        }

        Ok(())
    }
}

/// Metrics event listener that updates metrics counters
pub struct MetricsEventListener {
    // In a real implementation, this would integrate with a metrics system
}

impl Default for MetricsEventListener {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsEventListener {
    /// Create a new metrics event listener
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl EventListenerProvider for MetricsEventListener {
    async fn on_event(&self, event: &Event) -> Result<()> {
        // Update metrics counters based on event type
        match event.event_type {
            crate::models::events::EventType::Login => {
                // Increment login counter
                tracing::debug!("Metrics: login counter incremented");
            }
            crate::models::events::EventType::LoginError => {
                // Increment failed login counter
                tracing::debug!("Metrics: failed login counter incremented");
            }
            crate::models::events::EventType::Register => {
                // Increment registration counter
                tracing::debug!("Metrics: registration counter incremented");
            }
            _ => {
                // Other events don't affect metrics
            }
        }

        Ok(())
    }

    async fn on_admin_event(
        &self,
        _event: &AdminEvent,
        _include_representation: bool,
    ) -> Result<()> {
        // Admin events could also update metrics if needed
        Ok(())
    }
}

/// Create default event listeners
pub fn create_default_listeners() -> Vec<Arc<dyn EventListenerProvider>> {
    vec![
        Arc::new(LoggingEventListener::new()),
        Arc::new(MetricsEventListener::new()),
    ]
}
