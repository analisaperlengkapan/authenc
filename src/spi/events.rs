//! Events Service Provider Interface
//!
//! Provides comprehensive event handling, auditing, and monitoring capabilities.

use crate::spi::{Provider, ProviderConfig, ProviderFactory, Spi, SpiError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Events SPI implementation
pub struct EventsSpi;

impl Spi for EventsSpi {
    fn get_name(&self) -> &'static str {
        "events"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "org.keycloak.events.EventProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "org.keycloak.events.EventProviderFactory"
    }
}

/// Event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    Login,
    LoginError,
    Register,
    RegisterError,
    Logout,
    CodeToToken,
    RefreshToken,
    ClientLogin,
    ClientLoginError,
    RefreshTokenError,
    ValidateAccessToken,
    ValidateAccessTokenError,
    IntrospectToken,
    IntrospectTokenError,
    RevokeToken,
    UserInfoRequest,
    UserInfoRequestError,
    IdentityProviderLogin,
    IdentityProviderLoginError,
    IdentityProviderResponse,
    IdentityProviderResponseError,
    CustomGrant,
    CustomGrantError,
    UpdateProfile,
    UpdateProfileError,
    UpdatePassword,
    UpdatePasswordError,
    SendVerifyEmail,
    SendVerifyEmailError,
    SendResetPassword,
    SendResetPasswordError,
    VerifyEmail,
    VerifyEmailError,
    ResetPassword,
    ResetPasswordError,
    RemoveTotp,
    RemoveTotpError,
    UpdateTotp,
    UpdateTotpError,
    RemoveFederatedIdentity,
    RemoveFederatedIdentityError,
    UpdateFederatedIdentity,
    UpdateFederatedIdentityError,
    ImPersonate,
    ImPersonateError,
    CustomRequiredAction,
    CustomRequiredActionError,
    ExecuteActions,
    ExecuteActionsError,
    ExecuteActionToken,
    ExecuteActionTokenError,
    SendIdentityProviderLink,
    SendIdentityProviderLinkError,
    IdentityProviderLinkAccount,
    IdentityProviderLinkAccountError,
    FederationLinkAccount,
    FederationLinkAccountError,
    RemoveFederatedIdentityGroup,
    RemoveFederatedIdentityGroupError,
    UpdateFederatedIdentityGroup,
    UpdateFederatedIdentityGroupError,
    PermissionToken,
    PermissionTokenError,
    DeleteAccount,
    DeleteAccountError,
}

impl EventType {
    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::Login => "LOGIN",
            EventType::LoginError => "LOGIN_ERROR",
            EventType::Register => "REGISTER",
            EventType::RegisterError => "REGISTER_ERROR",
            EventType::Logout => "LOGOUT",
            EventType::CodeToToken => "CODE_TO_TOKEN",
            EventType::RefreshToken => "REFRESH_TOKEN",
            EventType::ClientLogin => "CLIENT_LOGIN",
            EventType::ClientLoginError => "CLIENT_LOGIN_ERROR",
            EventType::RefreshTokenError => "REFRESH_TOKEN_ERROR",
            EventType::ValidateAccessToken => "VALIDATE_ACCESS_TOKEN",
            EventType::ValidateAccessTokenError => "VALIDATE_ACCESS_TOKEN_ERROR",
            EventType::IntrospectToken => "INTROSPECT_TOKEN",
            EventType::IntrospectTokenError => "INTROSPECT_TOKEN_ERROR",
            EventType::RevokeToken => "REVOKE_TOKEN",
            EventType::UserInfoRequest => "USER_INFO_REQUEST",
            EventType::UserInfoRequestError => "USER_INFO_REQUEST_ERROR",
            EventType::IdentityProviderLogin => "IDENTITY_PROVIDER_LOGIN",
            EventType::IdentityProviderLoginError => "IDENTITY_PROVIDER_LOGIN_ERROR",
            EventType::IdentityProviderResponse => "IDENTITY_PROVIDER_RESPONSE",
            EventType::IdentityProviderResponseError => "IDENTITY_PROVIDER_RESPONSE_ERROR",
            EventType::CustomGrant => "CUSTOM_GRANT",
            EventType::CustomGrantError => "CUSTOM_GRANT_ERROR",
            EventType::UpdateProfile => "UPDATE_PROFILE",
            EventType::UpdateProfileError => "UPDATE_PROFILE_ERROR",
            EventType::UpdatePassword => "UPDATE_PASSWORD",
            EventType::UpdatePasswordError => "UPDATE_PASSWORD_ERROR",
            EventType::SendVerifyEmail => "SEND_VERIFY_EMAIL",
            EventType::SendVerifyEmailError => "SEND_VERIFY_EMAIL_ERROR",
            EventType::SendResetPassword => "SEND_RESET_PASSWORD",
            EventType::SendResetPasswordError => "SEND_RESET_PASSWORD_ERROR",
            EventType::VerifyEmail => "VERIFY_EMAIL",
            EventType::VerifyEmailError => "VERIFY_EMAIL_ERROR",
            EventType::ResetPassword => "RESET_PASSWORD",
            EventType::ResetPasswordError => "RESET_PASSWORD_ERROR",
            EventType::RemoveTotp => "REMOVE_TOTP",
            EventType::RemoveTotpError => "REMOVE_TOTP_ERROR",
            EventType::UpdateTotp => "UPDATE_TOTP",
            EventType::UpdateTotpError => "UPDATE_TOTP_ERROR",
            EventType::RemoveFederatedIdentity => "REMOVE_FEDERATED_IDENTITY",
            EventType::RemoveFederatedIdentityError => "REMOVE_FEDERATED_IDENTITY_ERROR",
            EventType::UpdateFederatedIdentity => "UPDATE_FEDERATED_IDENTITY",
            EventType::UpdateFederatedIdentityError => "UPDATE_FEDERATED_IDENTITY_ERROR",
            EventType::ImPersonate => "IMPERSONATE",
            EventType::ImPersonateError => "IMPERSONATE_ERROR",
            EventType::CustomRequiredAction => "CUSTOM_REQUIRED_ACTION",
            EventType::CustomRequiredActionError => "CUSTOM_REQUIRED_ACTION_ERROR",
            EventType::ExecuteActions => "EXECUTE_ACTIONS",
            EventType::ExecuteActionsError => "EXECUTE_ACTIONS_ERROR",
            EventType::ExecuteActionToken => "EXECUTE_ACTION_TOKEN",
            EventType::ExecuteActionTokenError => "EXECUTE_ACTION_TOKEN_ERROR",
            EventType::SendIdentityProviderLink => "SEND_IDENTITY_PROVIDER_LINK",
            EventType::SendIdentityProviderLinkError => "SEND_IDENTITY_PROVIDER_LINK_ERROR",
            EventType::IdentityProviderLinkAccount => "IDENTITY_PROVIDER_LINK_ACCOUNT",
            EventType::IdentityProviderLinkAccountError => "IDENTITY_PROVIDER_LINK_ACCOUNT_ERROR",
            EventType::FederationLinkAccount => "FEDERATION_LINK_ACCOUNT",
            EventType::FederationLinkAccountError => "FEDERATION_LINK_ACCOUNT_ERROR",
            EventType::RemoveFederatedIdentityGroup => "REMOVE_FEDERATED_IDENTITY_GROUP",
            EventType::RemoveFederatedIdentityGroupError => "REMOVE_FEDERATED_IDENTITY_GROUP_ERROR",
            EventType::UpdateFederatedIdentityGroup => "UPDATE_FEDERATED_IDENTITY_GROUP",
            EventType::UpdateFederatedIdentityGroupError => "UPDATE_FEDERATED_IDENTITY_GROUP_ERROR",
            EventType::PermissionToken => "PERMISSION_TOKEN",
            EventType::PermissionTokenError => "PERMISSION_TOKEN_ERROR",
            EventType::DeleteAccount => "DELETE_ACCOUNT",
            EventType::DeleteAccountError => "DELETE_ACCOUNT_ERROR",
        }
    }
}

/// Event representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// Event ID
    pub id: String,
    /// Event time
    pub time: DateTime<Utc>,
    /// Event type
    pub event_type: EventType,
    /// Realm ID
    pub realm_id: Option<String>,
    /// Client ID
    pub client_id: Option<String>,
    /// User ID
    pub user_id: Option<String>,
    /// Session ID
    pub session_id: Option<String>,
    /// IP address
    pub ip_address: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Error message
    pub error: Option<String>,
    /// Additional details
    pub details: HashMap<String, String>,
}

/// Admin event representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminEvent {
    /// Event ID
    pub id: String,
    /// Event time
    pub time: DateTime<Utc>,
    /// Realm ID
    pub realm_id: String,
    /// Auth details
    pub auth_details: AdminEventAuthDetails,
    /// Resource type
    pub resource_type: String,
    /// Operation type
    pub operation_type: AdminEventOperationType,
    /// Resource path
    pub resource_path: Option<String>,
    /// Representation
    pub representation: Option<String>,
    /// Error message
    pub error: Option<String>,
}

/// Admin event authentication details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminEventAuthDetails {
    /// Authenticated user ID
    pub user_id: String,
    /// IP address
    pub ip_address: String,
    /// User agent
    pub user_agent: Option<String>,
}

/// Admin event operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdminEventOperationType {
    Create,
    Update,
    Delete,
    Action,
}

/// Event listener interface
#[async_trait]
pub trait EventListenerProvider: Provider {
    /// Handle user event
    async fn on_event(&self, event: &Event) -> Result<(), EventError>;

    /// Handle admin event
    async fn on_admin_event(&self, event: &AdminEvent) -> Result<(), EventError>;

    /// Close the listener
    async fn close(&mut self) {}
}

/// Event store provider interface
#[async_trait]
pub trait EventStoreProvider: Provider {
    /// Store user event
    async fn store_event(&self, event: Event) -> Result<(), EventError>;

    /// Store admin event
    async fn store_admin_event(&self, event: AdminEvent) -> Result<(), EventError>;

    /// Query events
    async fn query_events(
        &self,
        query: EventQuery,
    ) -> Result<Vec<Event>, EventError>;

    /// Query admin events
    async fn query_admin_events(
        &self,
        query: AdminEventQuery,
    ) -> Result<Vec<AdminEvent>, EventError>;

    /// Clear events
    async fn clear_events(&self) -> Result<(), EventError>;

    /// Clear admin events
    async fn clear_admin_events(&self) -> Result<(), EventError>;

    /// Clear expired events
    async fn clear_expired_events(&self, expiration_time: DateTime<Utc>) -> Result<(), EventError>;
}

/// Event query parameters
#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    /// Realm ID
    pub realm_id: Option<String>,
    /// User ID
    pub user_id: Option<String>,
    /// Client ID
    pub client_id: Option<String>,
    /// Event types
    pub event_types: Option<Vec<EventType>>,
    /// IP address
    pub ip_address: Option<String>,
    /// Date from
    pub date_from: Option<DateTime<Utc>>,
    /// Date to
    pub date_to: Option<DateTime<Utc>>,
    /// Max results
    pub max_results: Option<usize>,
    /// First result
    pub first_result: Option<usize>,
}

/// Admin event query parameters
#[derive(Debug, Clone, Default)]
pub struct AdminEventQuery {
    /// Realm ID
    pub realm_id: Option<String>,
    /// Auth user ID
    pub auth_user_id: Option<String>,
    /// Resource type
    pub resource_type: Option<String>,
    /// Operation type
    pub operation_type: Option<AdminEventOperationType>,
    /// IP address
    pub ip_address: Option<String>,
    /// Date from
    pub date_from: Option<DateTime<Utc>>,
    /// Date to
    pub date_to: Option<DateTime<Utc>>,
    /// Max results
    pub max_results: Option<usize>,
    /// First result
    pub first_result: Option<usize>,
}

/// Event provider interface (combines listener and store)
#[async_trait]
pub trait EventProvider: EventListenerProvider + EventStoreProvider {
    /// Get event listeners
    fn get_listeners(&self) -> Vec<&dyn EventListenerProvider>;
}

/// Event provider factory
#[async_trait]
pub trait EventProviderFactory: ProviderFactory<dyn EventProvider> {
    /// Get supported event types
    fn get_supported_event_types(&self) -> Vec<EventType>;
}

/// Event-related errors
#[derive(Debug, thiserror::Error)]
pub enum EventError {
    #[error("Event storage error: {0}")]
    StorageError(String),

    #[error("Event query error: {0}")]
    QueryError(String),

    #[error("Event listener error: {0}")]
    ListenerError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

/// Default event provider implementation
pub struct DefaultEventProvider {
    events: Vec<Event>,
    admin_events: Vec<AdminEvent>,
    listeners: Vec<Box<dyn EventListenerProvider>>,
}

impl DefaultEventProvider {
    /// Create a new default event provider
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            admin_events: Vec::new(),
            listeners: Vec::new(),
        }
    }

    /// Add an event listener
    pub fn add_listener(&mut self, listener: Box<dyn EventListenerProvider>) {
        self.listeners.push(listener);
    }
}

impl Provider for DefaultEventProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[async_trait]
impl EventListenerProvider for DefaultEventProvider {
    async fn on_event(&self, event: &Event) -> Result<(), EventError> {
        for listener in &self.listeners {
            listener.on_event(event).await?;
        }
        Ok(())
    }

    async fn on_admin_event(&self, event: &AdminEvent) -> Result<(), EventError> {
        for listener in &self.listeners {
            listener.on_admin_event(event).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl EventStoreProvider for DefaultEventProvider {
    async fn store_event(&self, event: Event) -> Result<(), EventError> {
        // In a real implementation, this would store to database/Kafka
        // For now, just log the event
        tracing::info!("Storing event: {:?}", event);
        Ok(())
    }

    async fn store_admin_event(&self, event: AdminEvent) -> Result<(), EventError> {
        // In a real implementation, this would store to database/Kafka
        tracing::info!("Storing admin event: {:?}", event);
        Ok(())
    }

    async fn query_events(&self, _query: EventQuery) -> Result<Vec<Event>, EventError> {
        // Return empty results for now
        Ok(Vec::new())
    }

    async fn query_admin_events(&self, _query: AdminEventQuery) -> Result<Vec<AdminEvent>, EventError> {
        // Return empty results for now
        Ok(Vec::new())
    }

    async fn clear_events(&self) -> Result<(), EventError> {
        Ok(())
    }

    async fn clear_admin_events(&self) -> Result<(), EventError> {
        Ok(())
    }

    async fn clear_expired_events(&self, _expiration_time: DateTime<Utc>) -> Result<(), EventError> {
        Ok(())
    }
}

#[async_trait]
impl EventProvider for DefaultEventProvider {
    fn get_listeners(&self) -> Vec<&dyn EventListenerProvider> {
        self.listeners.iter().map(|l| l.as_ref()).collect()
    }
}

/// Default event provider factory
pub struct DefaultEventProviderFactory;

impl DefaultEventProviderFactory {
    /// Create a new default event provider factory
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProviderFactory<dyn EventProvider> for DefaultEventProviderFactory {
    async fn create(
        &self,
        _config: &ProviderConfig,
    ) -> Result<Box<dyn EventProvider>, SpiError> {
        Ok(Box::new(DefaultEventProvider::new()))
    }

    fn get_id(&self) -> &'static str {
        "default"
    }
}

impl EventProviderFactory for DefaultEventProviderFactory {
    fn get_supported_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::Login,
            EventType::LoginError,
            EventType::Register,
            EventType::RegisterError,
            EventType::Logout,
            EventType::UpdateProfile,
            EventType::UpdatePassword,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_event_type_strings() {
        assert_eq!(EventType::Login.as_str(), "LOGIN");
        assert_eq!(EventType::LoginError.as_str(), "LOGIN_ERROR");
        assert_eq!(EventType::Register.as_str(), "REGISTER");
    }

    #[tokio::test]
    async fn test_default_event_provider() {
        let provider = DefaultEventProvider::new();

        let event = Event {
            id: "test-id".to_string(),
            time: Utc::now(),
            event_type: EventType::Login,
            realm_id: Some("test-realm".to_string()),
            client_id: Some("test-client".to_string()),
            user_id: Some("test-user".to_string()),
            session_id: Some("test-session".to_string()),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            error: None,
            details: HashMap::new(),
        };

        // Test event handling
        provider.on_event(&event).await.unwrap();

        // Test event storage
        provider.store_event(event).await.unwrap();

        // Test querying (should return empty for now)
        let query = EventQuery::default();
        let results = provider.query_events(query).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_default_event_factory() {
        let factory = DefaultEventProviderFactory::new();

        assert_eq!(factory.get_id(), "default");

        let supported_types = factory.get_supported_event_types();
        assert!(supported_types.contains(&EventType::Login));
        assert!(supported_types.contains(&EventType::Register));
    }
}
