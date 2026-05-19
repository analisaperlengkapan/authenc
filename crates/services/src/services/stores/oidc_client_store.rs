use async_trait::async_trait;
use authenc_database::database::Database;
use authenc_core::error::{AuthencError, Result};
use authenc_models::models::oidc_client::OidcClient;
pub use authenc_spi::spi::store_traits::OidcClientStoreTrait;
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

/// OIDC client store for managing OAuth2/OIDC client registrations
pub struct OidcClientStore {
    /// Database connection
    db: Arc<Database>,
}

impl Default for OidcClientStore {
    fn default() -> Self {
        Self::new()
    }
}

impl OidcClientStore {
    /// Create new OIDC client store
    ///
    /// # Note
    /// This method requires a database connection. Use `with_database()` instead.
    ///
    /// # Panics
    /// This method will panic if called. It exists only for backward compatibility.
    pub fn new() -> Self {
        panic!(
            "OidcClientStore requires database connection. Use OidcClientStore::with_database() instead."
        );
    }

    /// Create OIDC client store with database connection (recommended for production)
    pub fn with_database(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Add new OIDC client
    pub async fn add(&self, client: OidcClient) -> Result<()> {
        use authenc_database::database::operations::oauth2;
        use authenc_models::models::OAuth2Client;

        // Convert OidcClient to OAuth2Client
        let id = Uuid::parse_str(&client.id).unwrap_or_else(|_| Uuid::new_v4());
        let oauth_client = OAuth2Client {
            id,
            client_id: client.client_id.clone(),
            client_secret_hash: client.client_secret.clone(), // In production, this should be hashed
            client_name: client.name.clone(),
            client_type: "confidential".to_string(), // Default
            redirect_uris: client.redirect_uris.clone(),
            scopes: vec!["openid".to_string(), "profile".to_string()], // Default OIDC scopes
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            owner_id: None, // No owner specified
            realm_id: Some(client.realm_id), // Default realm
            enabled: client.enabled,
            created_at: client.created_at,
            updated_at: client.updated_at,
            deleted_at: None,
        };

        oauth2::create_client(&self.db, &oauth_client).await?;
        Ok(())
    }

    /// Update OIDC client
    pub async fn update(&self, client: OidcClient) -> Result<()> {
        use authenc_database::database::operations::oauth2;

        let existing_client = oauth2::get_client_by_id(&self.db, &client.client_id).await?
            .ok_or_else(|| authenc_core::error::AuthencError::resource_not_found("Client not found"))?;

        let mut updated_oauth_client = existing_client;

        // Ensure we preserve the internal ID
        let id = Uuid::parse_str(&client.id).unwrap_or(updated_oauth_client.id);

        updated_oauth_client.id = id;
        updated_oauth_client.client_id = client.client_id.clone();
        updated_oauth_client.client_secret_hash = client.client_secret.clone(); // Note: password hash isn't updated securely if not passed in as hash
        updated_oauth_client.client_name = client.name.clone();
        updated_oauth_client.redirect_uris = client.redirect_uris.clone();
        updated_oauth_client.enabled = client.enabled;
        updated_oauth_client.updated_at = Utc::now();
        // The previous realm_id, owner_id, scopes, grant_types, response_types, etc., are kept intact

        // Call the database operation to update
        oauth2::update_client(&self.db, &updated_oauth_client).await?;
        Ok(())
    }

    /// Get OIDC client by client ID
    pub async fn get(&self, client_id: &str) -> Result<Option<OidcClient>> {
        use authenc_database::database::operations::oauth2;

        match oauth2::get_client_by_id(&self.db, client_id).await? {
            Some(oauth_client) => {
                // Convert OAuth2Client to OidcClient
                let oidc_client = OidcClient {
                    id: oauth_client.id.to_string(),
                    client_id: oauth_client.client_id.clone(),
                    client_secret: oauth_client.client_secret_hash.clone(), // In production, this should be the actual secret
                    redirect_uris: oauth_client.redirect_uris.clone(),
                    name: oauth_client.client_name.clone(),
                    realm_id: oauth_client.realm_id.unwrap_or(Uuid::nil()), // Map Option<Uuid> to Uuid
                    enabled: oauth_client.enabled,
                    created_at: oauth_client.created_at,
                    updated_at: oauth_client.updated_at,
                };
                Ok(Some(oidc_client))
            }
            None => Ok(None),
        }
    }

    /// Get all OIDC clients
    pub async fn all(&self) -> Result<Vec<OidcClient>> {
        use authenc_database::database::operations::oauth2;

        let oauth_clients = oauth2::get_all_clients(&self.db).await?;
        let mut oidc_clients = Vec::new();

        for oauth_client in oauth_clients {
            let oidc_client = OidcClient {
                id: oauth_client.id.to_string(),
                client_id: oauth_client.client_id.clone(),
                client_secret: oauth_client.client_secret_hash.clone(), // In production, this should be the actual secret
                redirect_uris: oauth_client.redirect_uris.clone(),
                name: oauth_client.client_name.clone(),
                realm_id: oauth_client.realm_id.unwrap_or(Uuid::nil()), // Map Option<Uuid> to Uuid
                enabled: oauth_client.enabled,
                created_at: oauth_client.created_at,
                updated_at: oauth_client.updated_at,
            };
            oidc_clients.push(oidc_client);
        }

        Ok(oidc_clients)
    }

    /// Delete OIDC client by client ID
    pub async fn delete(&self, client_id: &str) -> Result<bool> {
        use authenc_database::database::operations::oauth2;
        oauth2::delete_client(&self.db, client_id).await
    }
}

#[async_trait]
impl OidcClientStoreTrait for OidcClientStore {
    async fn get(&self, client_id: &str) -> std::result::Result<Option<OidcClient>, AuthencError> {
        self.get(client_id).await
    }

    async fn all(&self) -> std::result::Result<Vec<OidcClient>, AuthencError> {
        self.all().await
    }

    async fn add(&self, client: OidcClient) -> std::result::Result<(), AuthencError> {
        self.add(client).await
    }

    async fn update(&self, client: OidcClient) -> std::result::Result<(), AuthencError> {
        self.update(client).await
    }

    async fn delete(&self, client_id: &str) -> std::result::Result<bool, AuthencError> {
        self.delete(client_id).await
    }
}
