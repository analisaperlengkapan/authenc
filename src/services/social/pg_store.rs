use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;
use crate::database::Database;
use crate::database::operations::oauth2_providers;
use crate::error::Result;
use super::state_store::{SocialStateStore, SocialLoginState};

/// PostgreSQL implementation of SocialStateStore
pub struct PgSocialStateStore {
    db: Arc<Database>,
}

impl PgSocialStateStore {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Helper to find provider config ID by provider name (alias)
    /// This assumes provider configs are synced to DB
    async fn get_provider_config_id(&self, provider_alias: &str) -> Result<Option<Uuid>> {
        // We need a way to look up provider config ID by alias (e.g. "google")
        // Since we don't have a direct operation for this in `oauth2_providers`,
        // we might need to add one or query via raw SQL here.
        // For simplicity and speed, let's use raw SQL.
        let query = "SELECT id FROM oauth2_provider_configs WHERE alias = $1";
        let row = self.db.query_opt(query, &[&provider_alias]).await.map_err(|e| {
            crate::error::AuthencError::database(format!("Failed to look up provider config: {}", e))
        })?;

        Ok(row.map(|r| r.get(0)))
    }
}

#[async_trait]
impl SocialStateStore for PgSocialStateStore {
    async fn create_state(
        &self,
        state: &str,
        provider: &str,
        redirect_uri: &str,
        expires_in: i64,
    ) -> Result<()> {
        // 1. Get Provider Config ID
        let provider_config_id = self.get_provider_config_id(provider).await?
            .ok_or_else(|| crate::error::AuthencError::ConfigurationError { message: format!("Provider {} not configured in database", provider) })?;

        // 2. Get Realm ID (Assuming single tenant or context is passed - wait, context isn't passed here)
        // We need the realm_id. `oauth2_states` table requires it.
        // The `oauth2_provider_configs` table has `realm_id`. We can fetch it from there.
        let realm_id_query = "SELECT realm_id FROM oauth2_provider_configs WHERE id = $1";
        let realm_id: Uuid = self.db.query_one::<tokio_postgres::Row>(realm_id_query, &[&provider_config_id]).await
            .map_err(|e| crate::error::AuthencError::database(format!("Failed to get realm for provider: {}", e)))?
            .get(0);

        // 3. Create State
        oauth2_providers::create_oauth2_state(
            &self.db,
            state,
            provider_config_id,
            realm_id,
            redirect_uri,
            None, // code_verifier
            None, // code_challenge
            expires_in,
        ).await?;

        Ok(())
    }

    async fn validate_and_consume_state(&self, state: &str) -> Result<Option<SocialLoginState>> {
        // Uses `validate_oauth2_state` which marks it as used (consumes it)
        let state_data = oauth2_providers::validate_oauth2_state(&self.db, state).await
            .map_err(|e| crate::error::AuthencError::database(format!("Failed to validate state: {}", e)))?;

        if let Some(data) = state_data {
            // Need to fetch provider alias to return `SocialLoginState`
            let provider_id = data["provider_config_id"]
                .as_str()
                .ok_or_else(|| crate::error::AuthencError::database("Missing provider_config_id in state data"))?;

            let provider_id_uuid = Uuid::parse_str(provider_id)
                .map_err(|_| crate::error::AuthencError::database("Invalid provider_config_id format"))?;

            let query = "SELECT alias FROM oauth2_provider_configs WHERE id = $1";
            let provider_alias: String = self.db.query_one::<tokio_postgres::Row>(query, &[&provider_id_uuid]).await
                .map_err(|e| crate::error::AuthencError::database(format!("Failed to get provider alias: {}", e)))?
                .get(0);

            Ok(Some(SocialLoginState {
                state: state.to_string(),
                provider: provider_alias,
                redirect_uri: data["redirect_uri"].as_str().unwrap_or("").to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::minutes(5), // Approximate, DB handles expiry
            }))
        } else {
            Ok(None)
        }
    }

    async fn cleanup_expired(&self) -> Result<()> {
        // Database cleans up via background job or lazy expiration check in SELECT
        // But we can run a DELETE query here if we want active cleanup
        let query = "DELETE FROM oauth2_states WHERE expires_at < NOW() OR used = TRUE";
        self.db.execute(query, &[]).await.map_err(|e| {
            crate::error::AuthencError::database(format!("Failed to cleanup expired states: {}", e))
        })?;
        Ok(())
    }
}
