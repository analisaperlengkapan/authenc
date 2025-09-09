use crate::database::Database;
use crate::error::Result;
use crate::AuthencError;
use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;

pub struct OidcCodeStore {
    db: Arc<Database>,
    ttl: u64,
}

impl OidcCodeStore {
    pub fn new(_ttl_secs: u64) -> Self {
        // This would need database parameter in production
        unimplemented!("Database-backed OidcCodeStore not implemented")
    }

    pub fn with_database(db: Arc<Database>, ttl_secs: u64) -> Self {
        Self { db, ttl: ttl_secs }
    }

    pub async fn insert(
        &self,
        code: String,
        client_id: String,
        user_id: String,
        redirect_uri: String,
        scopes: Vec<String>,
        code_challenge: Option<String>,
        code_challenge_method: Option<String>,
    ) -> Result<()> {
        use crate::database::operations::oauth2;
        use crate::models::OAuth2AuthorizationCode;

        // Parse client_id and user_id as UUIDs
        let client_uuid = Uuid::parse_str(&client_id)
            .map_err(|_| AuthencError::validation("Invalid client_id format"))?;
        let user_uuid = Uuid::parse_str(&user_id)
            .map_err(|_| AuthencError::validation("Invalid user_id format"))?;

        let auth_code = OAuth2AuthorizationCode {
            id: Uuid::new_v4(),
            code: code.clone(),
            client_id: client_uuid,
            user_id: user_uuid,
            redirect_uri,
            scopes,
            code_challenge,
            code_challenge_method,
            expires_at: Utc::now() + chrono::Duration::seconds(self.ttl as i64),
            used: false,
            created_at: Utc::now(),
        };

        oauth2::store_authorization_code(&self.db, &auth_code).await?;
        Ok(())
    }

    pub async fn take(&self, code: &str, client_id: &str) -> Result<Option<String>> {
        use crate::database::operations::oauth2;

        // Parse client_id as UUID
        let client_uuid = Uuid::parse_str(client_id)
            .map_err(|_| AuthencError::validation("Invalid client_id format"))?;

        match oauth2::get_authorization_code(&self.db, code).await? {
            Some(auth_code) => {
                // Verify client matches
                if auth_code.client_id != client_uuid {
                    return Ok(None);
                }

                // Mark code as used
                oauth2::mark_code_used(&self.db, code).await?;

                // Return user_id as string
                Ok(Some(auth_code.user_id.to_string()))
            }
            None => Ok(None),
        }
    }
}
