//! Events Service Provider Interface
//!
//! Provides comprehensive event handling, auditing, and monitoring capabilities.

use crate::spi::{Provider, ProviderConfig, ProviderFactory, Spi, SpiError};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

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
    /// User login event
    Login,
    /// User login error event
    LoginError,
    /// User registration event
    Register,
    /// User registration error event
    RegisterError,
    /// User logout event
    Logout,
    /// Code to token exchange event
    CodeToToken,
    /// Refresh token event
    RefreshToken,
    /// Client login event
    ClientLogin,
    /// Client login error event
    ClientLoginError,
    /// Refresh token error event
    RefreshTokenError,
    /// Access token validation event
    ValidateAccessToken,
    /// Access token validation error event
    ValidateAccessTokenError,
    /// Token introspection event
    IntrospectToken,
    /// Token introspection error event
    IntrospectTokenError,
    /// Token revocation event
    RevokeToken,
    /// User info request event
    UserInfoRequest,
    /// User info request error event
    UserInfoRequestError,
    /// Identity provider login event
    IdentityProviderLogin,
    /// Identity provider login error event
    IdentityProviderLoginError,
    /// Identity provider response event
    IdentityProviderResponse,
    /// Identity provider response error event
    IdentityProviderResponseError,
    /// Custom grant event
    CustomGrant,
    /// Custom grant error event
    CustomGrantError,
    /// Profile update event
    UpdateProfile,
    /// Profile update error event
    UpdateProfileError,
    /// Password update event
    UpdatePassword,
    /// Password update error event
    UpdatePasswordError,
    /// Send verify email event
    SendVerifyEmail,
    /// Send verify email error event
    SendVerifyEmailError,
    /// Send reset password event
    SendResetPassword,
    /// Send reset password error event
    SendResetPasswordError,
    /// Email verification event
    VerifyEmail,
    /// Email verification error event
    VerifyEmailError,
    /// Password reset event
    ResetPassword,
    /// Password reset error event
    ResetPasswordError,
    /// Remove TOTP event
    RemoveTotp,
    /// Remove TOTP error event
    RemoveTotpError,
    /// Update TOTP event
    UpdateTotp,
    /// Update TOTP error event
    UpdateTotpError,
    /// Remove federated identity event
    RemoveFederatedIdentity,
    /// Remove federated identity error event
    RemoveFederatedIdentityError,
    /// Update federated identity event
    UpdateFederatedIdentity,
    /// Update federated identity error event
    UpdateFederatedIdentityError,
    /// User impersonation event
    ImPersonate,
    /// User impersonation error event
    ImPersonateError,
    /// Custom required action event
    CustomRequiredAction,
    /// Custom required action error event
    CustomRequiredActionError,
    /// Execute actions event
    ExecuteActions,
    /// Execute actions error event
    ExecuteActionsError,
    /// Execute action token event
    ExecuteActionToken,
    /// Execute action token error event
    ExecuteActionTokenError,
    /// Send identity provider link event
    SendIdentityProviderLink,
    /// Send identity provider link error event
    SendIdentityProviderLinkError,
    /// Identity provider link account event
    IdentityProviderLinkAccount,
    /// Identity provider link account error event
    IdentityProviderLinkAccountError,
    /// Federation link account event
    FederationLinkAccount,
    /// Federation link account error event
    FederationLinkAccountError,
    /// Remove federated identity group event
    RemoveFederatedIdentityGroup,
    /// Remove federated identity group error event
    RemoveFederatedIdentityGroupError,
    /// Update federated identity group event
    UpdateFederatedIdentityGroup,
    /// Update federated identity group error event
    UpdateFederatedIdentityGroupError,
    /// Permission token event
    PermissionToken,
    /// Permission token error event
    PermissionTokenError,
    /// Delete account event
    DeleteAccount,
    /// Delete account error event
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
    /// Create operation
    Create,
    /// Update operation
    Update,
    /// Delete operation
    Delete,
    /// Action operation
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
    async fn query_events(&self, query: EventQuery) -> Result<Vec<Event>, EventError>;

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
    /// Event storage error
    #[error("Event storage error: {0}")]
    StorageError(String),

    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(String),

    /// Event query error
    #[error("Event query error: {0}")]
    QueryError(String),

    /// Event listener error
    #[error("Event listener error: {0}")]
    ListenerError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
}

/// Default event provider implementation
pub struct DefaultEventProvider {
    database: Option<Arc<crate::database::Database>>,
    listeners: Vec<Box<dyn EventListenerProvider>>,
}

impl Default for DefaultEventProvider {
    fn default() -> Self {
        Self::new_without_database()
    }
}

impl DefaultEventProvider {
    /// Create a new default event provider
    pub fn new(database: Arc<crate::database::Database>) -> Self {
        Self {
            database: Some(database),
            listeners: Vec::new(),
        }
    }

    /// Create a new default event provider without database (for testing)
    pub fn new_without_database() -> Self {
        Self {
            database: None,
            listeners: Vec::new(),
        }
    }

    /// Add an event listener
    pub fn add_listener(&mut self, listener: Box<dyn EventListenerProvider>) {
        self.listeners.push(listener);
    }

    /// Convert SPI EventType to Model EventType
    fn convert_event_type(spi_type: EventType) -> crate::models::events::EventType {
        use crate::models::events::EventType as ModelEventType;
        match spi_type {
            EventType::Login => ModelEventType::Login,
            EventType::LoginError => ModelEventType::LoginError,
            EventType::Register => ModelEventType::Register,
            EventType::RegisterError => ModelEventType::RegisterError,
            EventType::Logout => ModelEventType::Logout,
            EventType::CodeToToken => ModelEventType::CodeToToken,
            EventType::RefreshToken => ModelEventType::RefreshToken,
            EventType::ClientLogin => ModelEventType::ClientLogin,
            EventType::ClientLoginError => ModelEventType::ClientLoginError,
            EventType::RefreshTokenError => ModelEventType::RefreshTokenError,
            EventType::UpdateProfile => ModelEventType::UpdateProfile,
            EventType::SendVerifyEmail => ModelEventType::SendVerifyEmail,
            EventType::VerifyEmail => ModelEventType::VerifyEmail,
            EventType::ResetPassword => ModelEventType::ResetPassword,
            _ => ModelEventType::Login, // Default fallback for types not in model
        }
    }

    /// Convert Model EventType to SPI EventType
    fn convert_model_event_type(model_type: crate::models::events::EventType) -> EventType {
        use crate::models::events::EventType as ModelEventType;
        match model_type {
            ModelEventType::Login => EventType::Login,
            ModelEventType::LoginError => EventType::LoginError,
            ModelEventType::Register => EventType::Register,
            ModelEventType::RegisterError => EventType::RegisterError,
            ModelEventType::Logout => EventType::Logout,
            ModelEventType::CodeToToken => EventType::CodeToToken,
            ModelEventType::RefreshToken => EventType::RefreshToken,
            ModelEventType::ClientLogin => EventType::ClientLogin,
            ModelEventType::ClientLoginError => EventType::ClientLoginError,
            ModelEventType::RefreshTokenError => EventType::RefreshTokenError,
            ModelEventType::UpdateProfile => EventType::UpdateProfile,
            ModelEventType::SendVerifyEmail => EventType::SendVerifyEmail,
            ModelEventType::VerifyEmail => EventType::VerifyEmail,
            ModelEventType::ResetPassword => EventType::ResetPassword,
            _ => EventType::Login, // Default fallback
        }
    }

    /// Convert SPI AdminEventOperationType to Model OperationType
    fn convert_admin_operation_type(
        spi_type: AdminEventOperationType,
    ) -> crate::models::events::OperationType {
        use crate::models::events::OperationType as ModelOperationType;
        match spi_type {
            AdminEventOperationType::Create => ModelOperationType::Create,
            AdminEventOperationType::Update => ModelOperationType::Update,
            AdminEventOperationType::Delete => ModelOperationType::Delete,
            AdminEventOperationType::Action => ModelOperationType::Action,
        }
    }

    /// Convert Model OperationType to SPI AdminEventOperationType
    fn convert_model_admin_operation_type(
        model_type: crate::models::events::OperationType,
    ) -> AdminEventOperationType {
        use crate::models::events::OperationType as ModelOperationType;
        match model_type {
            ModelOperationType::Create => AdminEventOperationType::Create,
            ModelOperationType::Update => AdminEventOperationType::Update,
            ModelOperationType::Delete => AdminEventOperationType::Delete,
            ModelOperationType::Action => AdminEventOperationType::Action,
        }
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
        if let Some(db) = &self.database {
            // Convert SPI Event to Model Event
            let model_event = crate::models::events::Event {
                id: event.id.clone(),
                time: event.time,
                event_type: Self::convert_event_type(event.event_type),
                realm_id: event.realm_id.unwrap_or_else(|| "default".to_string()),
                realm_name: None,
                client_id: event.client_id.clone(),
                user_id: event.user_id.clone(),
                session_id: event.session_id.clone(),
                ip_address: event.ip_address.clone(),
                error: event.error.clone(),
                details: event.details.clone(),
            };

            crate::database::operations::store_event(db, &model_event)
                .await
                .map_err(|e| EventError::StorageError(e.to_string()))?;
        }
        Ok(())
    }

    async fn store_admin_event(&self, event: AdminEvent) -> Result<(), EventError> {
        if let Some(db) = &self.database {
            // Convert SPI AdminEvent to Model AdminEvent
            let model_event = crate::models::events::AdminEvent {
                id: event.id.clone(),
                time: event.time,
                realm_id: event.realm_id.clone(),
                realm_name: None,
                auth_details: crate::models::events::AuthDetails {
                    user_id: event.auth_details.user_id.clone(),
                    username: None,
                    ip_address: Some(event.auth_details.ip_address.clone()),
                    user_agent: event.auth_details.user_agent.clone(),
                },
                resource_type: crate::models::events::ResourceType::Custom, // Will need proper mapping
                operation_type: Self::convert_admin_operation_type(event.operation_type),
                resource_path: event.resource_path.unwrap_or_default(),
                representation: event.representation.clone(),
                error: event.error.clone(),
            };

            crate::database::operations::store_admin_event(db, &model_event)
                .await
                .map_err(|e| EventError::StorageError(e.to_string()))?;
        }
        Ok(())
    }

    async fn query_events(&self, query: EventQuery) -> Result<Vec<Event>, EventError> {
        if let Some(db) = &self.database {
            // Use database query_events operation directly with SPI query
            let model_events = crate::database::operations::query_events(db, &query)
                .await
                .map_err(|e| EventError::StorageError(e.to_string()))?;

            // Convert Model Events back to SPI Events
            let mut spi_events = Vec::new();
            for me in model_events {
                spi_events.push(Event {
                    id: me.id,
                    time: me.time,
                    event_type: Self::convert_model_event_type(me.event_type),
                    realm_id: Some(me.realm_id),
                    client_id: me.client_id,
                    user_id: me.user_id,
                    session_id: me.session_id,
                    ip_address: me.ip_address,
                    user_agent: None, // Model doesn't have user_agent
                    error: me.error,
                    details: me.details,
                });
            }

            Ok(spi_events)
        } else {
            Ok(Vec::new())
        }
    }

    async fn query_admin_events(
        &self,
        query: AdminEventQuery,
    ) -> Result<Vec<AdminEvent>, EventError> {
        if let Some(db) = &self.database {
            // Use database query_admin_events operation directly with SPI query
            let model_events = crate::database::operations::query_admin_events(db, &query)
                .await
                .map_err(|e| EventError::StorageError(e.to_string()))?;

            // Convert Model AdminEvents back to SPI AdminEvents
            let mut spi_events = Vec::new();
            for me in model_events {
                spi_events.push(AdminEvent {
                    id: me.id,
                    time: me.time,
                    realm_id: me.realm_id,
                    auth_details: AdminEventAuthDetails {
                        user_id: me.auth_details.user_id.clone(),
                        ip_address: me.auth_details.ip_address.unwrap_or_default(),
                        user_agent: me.auth_details.user_agent,
                    },
                    resource_type: me.resource_type.as_str().to_string(),
                    operation_type: Self::convert_model_admin_operation_type(me.operation_type),
                    resource_path: Some(me.resource_path),
                    representation: me.representation,
                    error: me.error,
                });
            }

            Ok(spi_events)
        } else {
            Ok(Vec::new())
        }
    }

    async fn clear_events(&self) -> Result<(), EventError> {
        Ok(())
    }

    async fn clear_admin_events(&self) -> Result<(), EventError> {
        Ok(())
    }

    async fn clear_expired_events(
        &self,
        _expiration_time: DateTime<Utc>,
    ) -> Result<(), EventError> {
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

impl Default for DefaultEventProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultEventProviderFactory {
    /// Create a new default event provider factory
    pub fn new() -> Self {
        Self
    }
}

impl ProviderFactory<dyn EventProvider> for DefaultEventProviderFactory {
    fn create(&self, _config: &ProviderConfig) -> Result<Box<dyn EventProvider>, SpiError> {
        Ok(Box::new(DefaultEventProvider::new_without_database()))
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
        let provider = DefaultEventProvider::new_without_database();

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
