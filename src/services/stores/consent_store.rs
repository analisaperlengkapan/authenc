use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use crate::database::{operations, Database};
use crate::error::AuthencError;
use crate::models::{ConsentGrantRequest, UserConsent};

/// Consent store for managing user consents in the database
#[derive(Debug, Clone)]
pub struct ConsentStore {
    /// Database instance
    database: Arc<Database>,
}

impl ConsentStore {
    /// Create a new consent store
    pub fn new(database: Arc<Database>) -> Self {
        Self { database }
    }

    /// Get a reference to the database
    pub fn database(&self) -> &Arc<Database> {
        &self.database
    }
}

/// Trait for consent store operations
#[async_trait]
pub trait ConsentStoreTrait: Send + Sync {
    /// Grant user consent for a client
    async fn grant_consent(
        &self,
        user_id: Uuid,
        request: ConsentGrantRequest,
    ) -> Result<UserConsent, AuthencError>;

    /// Revoke user consent for a client
    async fn revoke_consent(&self, user_id: Uuid, client_id: &str) -> Result<(), AuthencError>;

    /// Revoke specific consent by ID
    async fn revoke_consent_by_id(
        &self,
        user_id: Uuid,
        consent_id: Uuid,
    ) -> Result<(), AuthencError>;

    /// Get all user consents
    async fn get_user_consents(&self, user_id: Uuid) -> Result<Vec<UserConsent>, AuthencError>;

    /// Get specific user consent for a client
    async fn get_user_consent(
        &self,
        user_id: Uuid,
        client_id: &str,
    ) -> Result<Option<UserConsent>, AuthencError>;

    /// Check if user has valid consent for client and scopes
    async fn has_consent(
        &self,
        user_id: Uuid,
        client_id: &str,
        scopes: &[String],
    ) -> Result<bool, AuthencError>;

    /// Clean up expired consents
    async fn cleanup_expired_consents(&self) -> Result<i64, AuthencError>;

    /// Get consent statistics for a user
    async fn get_consent_stats(&self, user_id: Uuid) -> Result<serde_json::Value, AuthencError>;
}

#[async_trait]
impl ConsentStoreTrait for ConsentStore {
    async fn grant_consent(
        &self,
        user_id: Uuid,
        request: ConsentGrantRequest,
    ) -> Result<UserConsent, AuthencError> {
        operations::consents::grant_consent(&self.database, user_id, &request)
            .await
            .map_err(|e| AuthencError::database(e.to_string()))
    }

    async fn revoke_consent(&self, user_id: Uuid, client_id: &str) -> Result<(), AuthencError> {
        operations::consents::revoke_consent(&self.database, user_id, client_id)
            .await
            .map_err(|e| AuthencError::database(e.to_string()))
    }

    async fn get_user_consents(&self, user_id: Uuid) -> Result<Vec<UserConsent>, AuthencError> {
        operations::consents::get_user_consents(&self.database, user_id)
            .await
            .map_err(|e| AuthencError::database(e.to_string()))
    }

    async fn get_user_consent(
        &self,
        user_id: Uuid,
        client_id: &str,
    ) -> Result<Option<UserConsent>, AuthencError> {
        operations::consents::get_user_consent(&self.database, user_id, client_id)
            .await
            .map_err(|e| AuthencError::database(e.to_string()))
    }

    async fn has_consent(
        &self,
        user_id: Uuid,
        client_id: &str,
        scopes: &[String],
    ) -> Result<bool, AuthencError> {
        operations::consents::has_consent(&self.database, user_id, client_id, scopes)
            .await
            .map_err(|e| AuthencError::database(e.to_string()))
    }

    async fn cleanup_expired_consents(&self) -> Result<i64, AuthencError> {
        operations::consents::cleanup_expired_consents(&self.database)
            .await
            .map_err(|e| AuthencError::database(e.to_string()))
    }

    async fn revoke_consent_by_id(
        &self,
        user_id: Uuid,
        consent_id: Uuid,
    ) -> Result<(), AuthencError> {
        operations::consents::revoke_consent_by_id(&self.database, user_id, consent_id)
            .await
            .map_err(|e| AuthencError::database(e.to_string()))
    }

    async fn get_consent_stats(&self, user_id: Uuid) -> Result<serde_json::Value, AuthencError> {
        operations::consents::get_consent_stats(&self.database, user_id)
            .await
            .map_err(|e| AuthencError::database(e.to_string()))
    }
}
