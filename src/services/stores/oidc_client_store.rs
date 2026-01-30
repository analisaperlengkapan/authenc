use crate::database::Database;
use crate::error::Result;
use crate::models::oidc_client::OidcClient;
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
        use crate::database::operations::oauth2;
        use crate::models::OAuth2Client;

        // Convert OidcClient to OAuth2Client
        let oauth_client = OAuth2Client {
            id: Uuid::new_v4(), // Generate new ID
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
            realm_id: None, // Default realm
            enabled: client.enabled,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };

        oauth2::create_client(&self.db, &oauth_client).await?;
        Ok(())
    }

    /// Get OIDC client by client ID
    pub async fn get(&self, client_id: &str) -> Result<Option<OidcClient>> {
        use crate::database::operations::oauth2;

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
        use crate::database::operations::oauth2;

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
        use crate::database::operations::oauth2;

        oauth2::delete_client(&self.db, client_id).await
    }
}
