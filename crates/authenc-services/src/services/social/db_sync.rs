use authenc_database::database::Database;
use authenc_core::error::Result;
use crate::services::social::{OAuthConfig, SocialProvider};
use uuid::Uuid;

/// Sync environment-based social provider configurations to the database
/// This ensures they have IDs and can be used with `oauth2_states` table
pub async fn sync_env_configs_to_db(db: &Database, configs: &[(SocialProvider, OAuthConfig)]) -> Result<()> {
    // We need a default realm to attach these providers to.
    // In a single-tenant setup or default setup, we might look for a "master" realm or "default" realm.
    // For this implementation, we'll try to find a realm named "master" or create it/use the first one.

    // Check if "master" realm exists
    let realm_query = "SELECT id FROM realms WHERE name = 'master'";
    let realm_row = db.query_opt(realm_query, &[]).await.map_err(|e| {
        authenc_core::error::AuthencError::database(format!("Failed to query master realm: {}", e))
    })?;

    let realm_id: Uuid = if let Some(row) = realm_row {
        row.get(0)
    } else {
        // Fallback: get the oldest realm (usually the initial/default one)
        // WARNING: In multi-tenant environments, this might associate social providers with an arbitrary realm
        // if 'master' doesn't exist. This logic is intended for single-tenant or default setups.
        let any_realm_query = "SELECT id FROM realms ORDER BY created_at ASC LIMIT 1";
        let any_realm = db.query_opt(any_realm_query, &[]).await.map_err(|e| {
            authenc_core::error::AuthencError::database(format!("Failed to query any realm: {}", e))
        })?;

        if let Some(row) = any_realm {
            row.get(0)
        } else {
            // No realms exist? We can't sync.
            // This might happen during initial bootstrap.
            // We'll log a warning and skip syncing.
            tracing::warn!("No realms found. Skipping social provider sync to DB.");
            return Ok(());
        }
    };

    for (provider, config) in configs {
        let alias = provider.as_str();

        // Upsert logic for oauth2_provider_configs
        // We use alias and realm_id as unique constraint (from migration 014)

        // Check if exists
        let check_query = "SELECT id FROM oauth2_provider_configs WHERE realm_id = $1 AND alias = $2";
        let existing = db.query_opt(check_query, &[&realm_id, &alias]).await.map_err(|e| {
            authenc_core::error::AuthencError::database(format!("Failed to check existing provider: {}", e))
        })?;

        if existing.is_some() {
            // Update
            let update_query = r#"
                UPDATE oauth2_provider_configs
                SET
                    provider_name = $3,
                    display_name = $4,
                    authorization_url = $5,
                    token_url = $6,
                    user_info_url = $7,
                    client_id = $8,
                    client_secret = $9,
                    scopes = $10,
                    enabled = true,
                    updated_at = NOW()
                WHERE realm_id = $1 AND alias = $2
            "#;

            db.execute(update_query, &[
                &realm_id,
                &alias,
                &alias, // provider_name matches alias for these standard ones
                &format!("{:?} Social Login", provider), // Display Name
                &config.authorization_url,
                &config.token_url,
                &config.user_info_url,
                &config.client_id,
                &config.client_secret,
                &config.scopes.join(" "),
            ]).await.map_err(|e| {
                authenc_core::error::AuthencError::database(format!("Failed to update provider config: {}", e))
            })?;
        } else {
            // Insert
            let insert_query = r#"
                INSERT INTO oauth2_provider_configs (
                    realm_id, provider_name, alias, display_name,
                    authorization_url, token_url, user_info_url,
                    client_id, client_secret, scopes,
                    enabled, created_at, updated_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true, NOW(), NOW())
            "#;

            db.execute(insert_query, &[
                &realm_id,
                &alias,
                &alias,
                &format!("{:?} Social Login", provider),
                &config.authorization_url,
                &config.token_url,
                &config.user_info_url,
                &config.client_id,
                &config.client_secret,
                &config.scopes.join(" "),
            ]).await.map_err(|e| {
                authenc_core::error::AuthencError::database(format!("Failed to insert provider config: {}", e))
            })?;
        }

        // Handle Apple specific configuration if needed
        if provider == &SocialProvider::Apple {
            // Get the ID of the provider config we just touched
            let config_id_query = "SELECT id FROM oauth2_provider_configs WHERE realm_id = $1 AND alias = $2";
            let config_id_row = db.query_opt(config_id_query, &[&realm_id, &alias]).await.map_err(|e| {
                authenc_core::error::AuthencError::database(format!("Failed to query provider config id: {}", e))
            })?;

            if let Some(row) = config_id_row {
                let config_id: Uuid = row.get(0);

                // Check if social_login_config exists
                let check_social = "SELECT id FROM social_login_configs WHERE oauth2_config_id = $1";
                let existing_social = db.query_opt(check_social, &[&config_id]).await.map_err(|e| {
                    authenc_core::error::AuthencError::database(format!("Failed to check social config: {}", e))
                })?;

                if existing_social.is_some() {
                    let update_social = "UPDATE social_login_configs SET apple_team_id = $2, apple_key_id = $3, apple_private_key = $4, updated_at = NOW() WHERE oauth2_config_id = $1";
                    db.execute(update_social, &[&config_id, &config.team_id, &config.key_id, &config.private_key]).await.map_err(|e| {
                        authenc_core::error::AuthencError::database(format!("Failed to update social config: {}", e))
                    })?;
                } else {
                    let insert_social = "INSERT INTO social_login_configs (oauth2_config_id, provider_type, apple_team_id, apple_key_id, apple_private_key, created_at, updated_at) VALUES ($1, 'apple', $2, $3, $4, NOW(), NOW())";
                    db.execute(insert_social, &[&config_id, &config.team_id, &config.key_id, &config.private_key]).await.map_err(|e| {
                        authenc_core::error::AuthencError::database(format!("Failed to insert social config: {}", e))
                    })?;
                }
            }
        }
    }

    Ok(())
}
