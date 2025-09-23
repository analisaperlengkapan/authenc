use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::{Result, AuthencError as Error};
use crate::spi::{Provider, ProviderFactory, Spi, ProviderConfig, SpiError};
use crate::models::session::Session;
use crate::services::session_store::SessionStore;

/// Session provider types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SessionProviderType {
    User,
    Client,
}

/// Session query context for filtering and pagination
#[derive(Debug, Clone, Default)]
pub struct SessionQueryContext {
    pub realm_id: Option<String>,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub search: Option<String>,
    pub first: Option<i32>,
    pub max: Option<i32>,
    pub filters: HashMap<String, String>,
}

/// Session provider trait - base trait for all session providers
#[async_trait]
pub trait SessionProvider: Provider + Send + Sync {
    /// Get the session provider type
    fn get_type(&self) -> SessionProviderType;

    /// Get the provider name
    fn get_name(&self) -> &str;
}

/// User session provider trait
#[async_trait]
pub trait UserSessionProvider: SessionProvider {
    /// Create a new user session
    async fn create_user_session(&self, session: Session) -> Result<Session>;

    /// Get user session by ID
    async fn get_user_session(&self, session_id: Uuid) -> Result<Option<Session>>;

    /// Get user sessions by user ID
    async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>>;

    /// Update user session
    async fn update_user_session(&self, session: Session) -> Result<Session>;

    /// Remove user session
    async fn remove_user_session(&self, session_id: Uuid) -> Result<()>;

    /// Remove user sessions by user ID
    async fn remove_user_sessions_by_user(&self, user_id: Uuid) -> Result<()>;

    /// Remove expired user sessions
    async fn remove_expired_user_sessions(&self) -> Result<()>;
}

/// Session provider factory trait
#[async_trait]
pub trait SessionProviderFactory: Send + Sync {
    /// Create a session provider of the specified type
    fn create_session_provider(&self, provider_type: SessionProviderType) -> Box<dyn SessionProvider + Send + Sync>;
}

/// Default user session provider implementation
pub struct DefaultUserSessionProvider {
    session_store: Arc<SessionStore>,
}

impl DefaultUserSessionProvider {
    pub fn new(session_store: Arc<SessionStore>) -> Self {
        Self { session_store }
    }
}

#[async_trait]
impl Provider for DefaultUserSessionProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[async_trait]
impl SessionProvider for DefaultUserSessionProvider {
    fn get_type(&self) -> SessionProviderType {
        SessionProviderType::User
    }

    fn get_name(&self) -> &str {
        "default-user-session"
    }
}

#[async_trait]
impl UserSessionProvider for DefaultUserSessionProvider {
    async fn create_user_session(&self, session: Session) -> Result<Session> {
        self.session_store.store_session(session.clone()).await?;
        Ok(session)
    }

    async fn get_user_session(&self, session_id: Uuid) -> Result<Option<Session>> {
        self.session_store.get_session(session_id).await
    }

    async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>> {
        self.session_store.get_user_sessions(user_id).await
    }

    async fn update_user_session(&self, session: Session) -> Result<Session> {
        self.session_store.store_session(session.clone()).await?;
        Ok(session)
    }

    async fn remove_user_session(&self, session_id: Uuid) -> Result<()> {
        self.session_store.delete_session(session_id).await
    }

    async fn remove_user_sessions_by_user(&self, user_id: Uuid) -> Result<()> {
        let sessions = self.session_store.get_user_sessions(user_id).await?;
        for session in sessions {
            self.session_store.delete_session(session.id).await?;
        }
        Ok(())
    }

    async fn remove_expired_user_sessions(&self) -> Result<()> {
        // This would need to be implemented in SessionStore
        // For now, we'll leave it as a placeholder
        Ok(())
    }
}

/// Default session provider factory
pub struct DefaultSessionProviderFactory {
    session_store: Arc<SessionStore>,
}

impl DefaultSessionProviderFactory {
    pub fn new(session_store: Arc<SessionStore>) -> Self {
        Self { session_store }
    }
}

#[async_trait]
impl ProviderFactory<dyn SessionProvider> for DefaultSessionProviderFactory {
    async fn create(&self, _config: &ProviderConfig) -> std::result::Result<Box<dyn SessionProvider>, SpiError> {
        // Default to user session provider
        Ok(Box::new(DefaultUserSessionProvider::new(self.session_store.clone())))
    }

    async fn init(&mut self, _config: &ProviderConfig) -> std::result::Result<(), SpiError> {
        Ok(())
    }

    fn get_id(&self) -> &'static str {
        "default-session"
    }
}

impl SessionProviderFactory for DefaultSessionProviderFactory {
    fn create_session_provider(&self, provider_type: SessionProviderType) -> Box<dyn SessionProvider + Send + Sync> {
        match provider_type {
            SessionProviderType::User => Box::new(DefaultUserSessionProvider::new(self.session_store.clone())),
            SessionProviderType::Client => Box::new(DefaultUserSessionProvider::new(self.session_store.clone())), // For now, use same implementation
        }
    }
}

/// Session SPI implementation
pub struct SessionSpi;

impl Spi for SessionSpi {
    fn get_name(&self) -> &'static str {
        "session"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "SessionProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "SessionProviderFactory"
    }
}
