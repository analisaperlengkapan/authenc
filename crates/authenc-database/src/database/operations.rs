/// Database operations for group management
pub mod groups {
    use authenc_core::error::{AuthencError, Result};

    use authenc_models::models::Group;

    use crate::database::Database;
    use chrono::Utc;
    use tracing::{error, warn};
    use uuid::Uuid;

    /// Create a new group in the database
    pub async fn create_group(
        db: &Database,
        realm_id: Uuid,
        name: &str,
        parent_id: Option<Uuid>,
        description: Option<&str>,
        attributes: &serde_json::Value,
    ) -> Result<Group> {
        let group_id = Uuid::new_v4();
        let now = Utc::now();

        // Calculate path based on parent
        let path = if let Some(pid) = parent_id {
            // Get parent path
            let parent_row: tokio_postgres::Row = db
                .query_one("SELECT path, realm_id FROM groups WHERE id = $1", &[&pid])
                .await
                .map_err(|e| {
                    error!("Failed to get parent group: {}", e);
                    AuthencError::not_found(format!("Parent group {} not found", pid))
                })?;

            let parent_path: String = parent_row.get(0);
            let parent_realm: Uuid = parent_row.get(1);

            // Verify parent is in same realm
            if parent_realm != realm_id {
                return Err(AuthencError::validation(
                    "Parent group must belong to the same realm",
                ));
            }

            format!("{}/{}", parent_path, name)
        } else {
            format!("/{}", name)
        };

        let query = r#"
            INSERT INTO groups (
                id, realm_id, parent_id, name, path,
                description, attributes, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING
                id, realm_id, parent_id, name, path,
                description, attributes, created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &group_id,
                    &realm_id,
                    &parent_id,
                    &name,
                    &path,
                    &description,
                    &attributes,
                    &now,
                    &now,
                ],
            )
            .await
            .map_err(|e| {
                error!("Group creation failed: {}", e);
                if e.to_string().contains("uq_groups_name_parent") {
                    AuthencError::conflict("Group name already exists in this parent")
                } else {
                    AuthencError::database(format!("Failed to create group: {}", e))
                }
            })?;

        Ok(Group {
            id: row.get(0),
            realm_id: row.get(1),
            parent_id: row.get(2),
            name: row.get(3),
            path: row.get(4),
            description: row.get(5),
            attributes: row.get(6),
            created_at: row.get(7),
            updated_at: row.get(8),
        })
    }

    /// Get group by ID
    pub async fn get_group_by_id(db: &Database, group_id: Uuid) -> Result<Option<Group>> {
        let query = r#"
            SELECT
                id, realm_id, parent_id, name, path,
                description, attributes, created_at, updated_at
            FROM groups
            WHERE id = $1
        "#;

        match db.query_opt(query, &[&group_id]).await {
            Ok(Some(row)) => Ok(Some(Group {
                id: row.get(0),
                realm_id: row.get(1),
                parent_id: row.get(2),
                name: row.get(3),
                path: row.get(4),
                description: row.get(5),
                attributes: row.get(6),
                created_at: row.get(7),
                updated_at: row.get(8),
            })),
            Ok(None) => Ok(None),
            Err(e) => {
                error!("Failed to get group: {}", e);
                Err(AuthencError::database(format!(
                    "Failed to get group: {}",
                    e
                )))
            }
        }
    }

    /// Get group by name in a realm
    pub async fn get_group_by_name(
        db: &Database,
        realm_id: Uuid,
        name: &str,
    ) -> Result<Option<Group>> {
        let query = r#"
            SELECT
                id, realm_id, parent_id, name, path,
                description, attributes, created_at, updated_at
            FROM groups
            WHERE realm_id = $1 AND name = $2
        "#;

        let rows: Vec<tokio_postgres::Row> =
            db.query(query, &[&realm_id, &name]).await.map_err(|e| {
                error!("Failed to get group by name: {}", e);
                AuthencError::database(format!("Failed to get group by name: {}", e))
            })?;

        if rows.is_empty() {
            Ok(None)
        } else {
            let row = &rows[0];
            Ok(Some(Group {
                id: row.get(0),
                realm_id: row.get(1),
                parent_id: row.get(2),
                name: row.get(3),
                path: row.get(4),
                description: row.get(5),
                attributes: row.get(6),
                created_at: row.get(7),
                updated_at: row.get(8),
            }))
        }
    }

    /// Get all groups in a realm
    pub async fn get_groups_by_realm(
        db: &Database,
        realm_id: Uuid,
        first: Option<i64>,
        max: Option<i64>,
    ) -> Result<Vec<Group>> {
        let query = r#"
            SELECT
                id, realm_id, parent_id, name, path,
                description, attributes, created_at, updated_at
            FROM groups
            WHERE realm_id = $1
            ORDER BY path
            LIMIT $2 OFFSET $3
        "#;

        let limit = max.unwrap_or(100).min(1000);
        let offset = first.unwrap_or(0);

        let rows = db
            .query(query, &[&realm_id, &limit, &offset])
            .await
            .map_err(|e| {
                error!("Failed to get groups by realm: {}", e);
                AuthencError::database(format!("Failed to get groups: {}", e))
            })?;

        Ok(rows
            .iter()
            .map(|row: &tokio_postgres::Row| Group {
                id: row.get::<_, Uuid>(0),
                realm_id: row.get::<_, Uuid>(1),
                parent_id: row.get::<_, Option<Uuid>>(2),
                name: row.get::<_, String>(3),
                path: row.get::<_, String>(4),
                description: row.get::<_, Option<String>>(5),
                attributes: row.get::<_, serde_json::Value>(6),
                created_at: row.get::<_, chrono::DateTime<chrono::Utc>>(7),
                updated_at: row.get::<_, chrono::DateTime<chrono::Utc>>(8),
            })
            .collect())
    }

    /// Get child groups of a parent group
    pub async fn get_subgroups(
        db: &Database,
        parent_id: Uuid,
        direct_only: bool,
    ) -> Result<Vec<Group>> {
        let query = if direct_only {
            r#"
                SELECT
                    id, realm_id, parent_id, name, path,
                    description, attributes, created_at, updated_at
                FROM groups
                WHERE parent_id = $1
                ORDER BY name
            "#
        } else {
            // Get all descendants by path prefix matching
            r#"
                SELECT
                    g.id, g.realm_id, g.parent_id, g.name, g.path,
                    g.description, g.attributes, g.created_at, g.updated_at
                FROM groups g
                INNER JOIN groups parent ON parent.id = $1
                WHERE g.path LIKE parent.path || '/%'
                ORDER BY g.path
            "#
        };

        let rows = db.query(query, &[&parent_id]).await.map_err(|e| {
            error!("Failed to get subgroups: {}", e);
            AuthencError::database(format!("Failed to get subgroups: {}", e))
        })?;

        Ok(rows
            .iter()
            .map(|row: &tokio_postgres::Row| Group {
                id: row.get::<_, Uuid>(0),
                realm_id: row.get::<_, Uuid>(1),
                parent_id: row.get::<_, Option<Uuid>>(2),
                name: row.get::<_, String>(3),
                path: row.get::<_, String>(4),
                description: row.get::<_, Option<String>>(5),
                attributes: row.get::<_, serde_json::Value>(6),
                created_at: row.get::<_, chrono::DateTime<chrono::Utc>>(7),
                updated_at: row.get::<_, chrono::DateTime<chrono::Utc>>(8),
            })
            .collect())
    }

    /// Update group
    pub async fn update_group(
        db: &Database,
        group_id: Uuid,
        name: Option<String>,
        parent_id: Option<Option<Uuid>>, // None = no change, Some(None) = set to null, Some(Some(id)) = set to id
        description: Option<Option<String>>,
        attributes: Option<serde_json::Value>,
    ) -> Result<Group> {
        let now = Utc::now();

        // Build query based on what's being updated
        let has_name = name.is_some();
        let has_parent = parent_id.is_some();
        let has_desc = description.is_some();
        let has_attrs = attributes.is_some();

        if !has_name && !has_parent && !has_desc && !has_attrs {
            // No updates, just return current group
            return get_group_by_id(db, group_id)
                .await?
                .ok_or_else(|| AuthencError::not_found("Group not found"));
        }

        // Use COALESCE for conditional updates
        let query = r#"
            UPDATE groups
            SET 
                name = COALESCE($2, name),
                parent_id = CASE WHEN $3::boolean THEN $4 ELSE parent_id END,
                description = CASE WHEN $5::boolean THEN $6 ELSE description END,
                attributes = COALESCE($7, attributes),
                updated_at = $8
            WHERE id = $1
            RETURNING
                id, realm_id, parent_id, name, path,
                description, attributes, created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &group_id,
                    &name,
                    &has_parent,
                    &parent_id.flatten(),
                    &has_desc,
                    &description.flatten(),
                    &attributes,
                    &now,
                ],
            )
            .await
            .map_err(|e| {
                error!("Group update failed: {}", e);
                AuthencError::database(format!("Failed to update group: {}", e))
            })?;

        Ok(Group {
            id: row.get(0),
            realm_id: row.get(1),
            parent_id: row.get(2),
            name: row.get(3),
            path: row.get(4),
            description: row.get(5),
            attributes: row.get(6),
            created_at: row.get(7),
            updated_at: row.get(8),
        })
    }

    /// Delete group (and all subgroups due to CASCADE)
    pub async fn delete_group(db: &Database, group_id: Uuid) -> Result<()> {
        let query = "DELETE FROM groups WHERE id = $1";

        let rows_affected = db.execute(query, &[&group_id]).await.map_err(|e| {
            error!("Group deletion failed: {}", e);
            AuthencError::database(format!("Failed to delete group: {}", e))
        })?;

        if rows_affected == 0 {
            return Err(AuthencError::not_found("Group not found"));
        }

        Ok(())
    }

    /// Add user to group
    /// Add user to group with optional expiration and attributes
    pub async fn add_user_to_group(
        db: &Database,
        user_id: Uuid,
        group_id: Uuid,
        expires_at: Option<chrono::DateTime<Utc>>,
        attributes: Option<serde_json::Value>,
    ) -> Result<()> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let attrs = attributes.unwrap_or_else(|| serde_json::json!({}));

        let query = r#"
            INSERT INTO user_groups (id, user_id, group_id, joined_at, expires_at, attributes)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (user_id, group_id) DO UPDATE
            SET expires_at = EXCLUDED.expires_at, attributes = EXCLUDED.attributes
        "#;

        db.execute(
            query,
            &[&id, &user_id, &group_id, &now, &expires_at, &attrs],
        )
        .await
        .map_err(|e| {
            error!("Failed to add user to group: {}", e);
            AuthencError::database(format!("Failed to add user to group: {}", e))
        })?;

        Ok(())
    }

    /// Remove user from group
    pub async fn remove_user_from_group(
        db: &Database,
        user_id: Uuid,
        group_id: Uuid,
    ) -> Result<()> {
        let query = "DELETE FROM user_groups WHERE user_id = $1 AND group_id = $2";

        let rows_affected = db
            .execute(query, &[&user_id, &group_id])
            .await
            .map_err(|e| {
                error!("Failed to remove user from group: {}", e);
                AuthencError::database(format!("Failed to remove user from group: {}", e))
            })?;

        if rows_affected == 0 {
            warn!(
                "Attempted to remove user {} from group {} but membership didn't exist",
                user_id, group_id
            );
        }

        Ok(())
    }

    /// Get all groups a user belongs to (including inherited from parents)
    pub async fn get_user_groups(db: &Database, user_id: Uuid) -> Result<Vec<Group>> {
        let query = r#"
            SELECT
                g.id, g.realm_id, g.parent_id, g.name, g.path,
                g.description, g.attributes, g.created_at, g.updated_at
            FROM groups g
            INNER JOIN user_groups ug ON g.id = ug.group_id
            WHERE ug.user_id = $1
              AND (ug.expires_at IS NULL OR ug.expires_at > NOW())
            ORDER BY g.path
        "#;

        let rows = db.query(query, &[&user_id]).await.map_err(|e| {
            error!("Failed to get user groups: {}", e);
            AuthencError::database(format!("Failed to get user groups: {}", e))
        })?;

        Ok(rows
            .iter()
            .map(|row: &tokio_postgres::Row| Group {
                id: row.get::<_, Uuid>(0),
                realm_id: row.get::<_, Uuid>(1),
                parent_id: row.get::<_, Option<Uuid>>(2),
                name: row.get::<_, String>(3),
                path: row.get::<_, String>(4),
                description: row.get::<_, Option<String>>(5),
                attributes: row.get::<_, serde_json::Value>(6),
                created_at: row.get::<_, chrono::DateTime<chrono::Utc>>(7),
                updated_at: row.get::<_, chrono::DateTime<chrono::Utc>>(8),
            })
            .collect())
    }

    /// Get members of a group
    pub async fn get_group_members(
        db: &Database,
        group_id: Uuid,
        first: Option<i64>,
        max: Option<i64>,
    ) -> Result<Vec<Uuid>> {
        let query = r#"
            SELECT user_id
            FROM user_groups
            WHERE group_id = $1
              AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY joined_at
            LIMIT $2 OFFSET $3
        "#;

        let limit = max.unwrap_or(100).min(1000);
        let offset = first.unwrap_or(0);

        let rows = db
            .query(query, &[&group_id, &limit, &offset])
            .await
            .map_err(|e| {
                error!("Failed to get group members: {}", e);
                AuthencError::database(format!("Failed to get group members: {}", e))
            })?;

        Ok(rows
            .iter()
            .map(|row: &tokio_postgres::Row| row.get::<_, Uuid>(0))
            .collect())
    }

    /// Count members in a group
    pub async fn count_group_members(db: &Database, group_id: Uuid) -> Result<i64> {
        let query = r#"
            SELECT COUNT(*)::bigint
            FROM user_groups
            WHERE group_id = $1
              AND (expires_at IS NULL OR expires_at > NOW())
        "#;

        let row: tokio_postgres::Row = db.query_one(query, &[&group_id]).await.map_err(|e| {
            error!("Failed to count group members: {}", e);
            AuthencError::database(format!("Failed to count group members: {}", e))
        })?;

        Ok(row.get(0))
    }

    /// Count subgroups of a group
    pub async fn count_subgroups(db: &Database, group_id: Uuid) -> Result<i64> {
        let query = r#"
            SELECT COUNT(*)::bigint
            FROM groups
            WHERE parent_id = $1
        "#;

        let row: tokio_postgres::Row = db.query_one(query, &[&group_id]).await.map_err(|e| {
            error!("Failed to count subgroups: {}", e);
            AuthencError::database(format!("Failed to count subgroups: {}", e))
        })?;

        Ok(row.get(0))
    }
}

/// Database operations for device management
pub mod devices {
    use authenc_core::error::{AuthencError, Result};

    use authenc_models::models::{Device, DeviceInfo};

    use crate::database::Database;
    use chrono::Utc;
    use log::error;
    use uuid::Uuid;

    /// Register a new device in the database
    /// Register a new device for a user
    pub async fn register_device(
        db: &Database,
        user_id: Uuid,
        device_info: &DeviceInfo,
    ) -> Result<Device> {
        let device_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO devices (
                id, user_id, device_name, device_fingerprint, trust_score,
                os, os_version, browser, browser_version, ip_address,
                user_agent, security_features, location_data, first_seen_at, last_seen_at,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            RETURNING
                id, user_id, device_name, device_fingerprint, trust_score,
                risk_level, os, os_version, browser, browser_version,
                ip_address, user_agent, location_data, security_features, last_seen_at,
                first_seen_at, created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &device_id,
                    &user_id,
                    &device_info.device_name,
                    &device_info.fingerprint,
                    &device_info.trust_score.unwrap_or(0.5f64),
                    &device_info.os,
                    &device_info.os_version,
                    &device_info.browser,
                    &device_info.browser_version,
                    &device_info.ip_address,
                    &device_info.user_agent,
                    &device_info.security_features,
                    &device_info.location_data,
                    &now,
                    &now,
                    &now,
                    &now,
                ],
            )
            .await
            .map_err(|e| {
                error!("Device registration query failed: {}", e);
                AuthencError::database(format!("Database query failed: {}", e))
            })?;

        // Convert row to Device
        row.try_into()
    }

    /// Get device by ID
    pub async fn get_device_by_id(db: &Database, device_id: Uuid) -> Result<Option<Device>> {
        let query = r#"
            SELECT
                id, user_id, device_name, device_fingerprint, trust_score,
                risk_level, os, os_version, browser, browser_version,
                ip_address, user_agent, location_data, security_features, last_seen_at,
                first_seen_at, created_at, updated_at
            FROM devices
            WHERE id = $1
        "#;

        let row: tokio_postgres::Row = db.query_one(query, &[&device_id]).await?;
        // Convert row to Device
        Ok(Some(row.try_into()?))
    }

    /// Update device trust score
    /// Update device details
    pub async fn update_device_details(
        db: &Database,
        device_id: Uuid,
        device_name: Option<String>,
    ) -> Result<()> {
        let now = Utc::now();

        // Check if there are updates
        if device_name.is_none() {
            return Ok(());
        }

        let mut query_builder = String::from("UPDATE devices SET updated_at = $2");
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        params.push(Box::new(device_id));
        params.push(Box::new(now));
        let param_index = 3;

        if let Some(name) = device_name {
            query_builder.push_str(&format!(", device_name = ${}", param_index));
            params.push(Box::new(name));
        }

        query_builder.push_str(" WHERE id = $1");

        let params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync)).collect();

        db.execute(&query_builder, &params_refs)
            .await
            .map_err(|e| {
                error!("Failed to update device details: {}", e);
                AuthencError::database(format!("Failed to update device details: {}", e))
            })?;

        Ok(())
    }

    /// Update device trust score with evaluation factors
    pub async fn update_trust_score(
        db: &Database,
        device_id: Uuid,
        new_score: f64,
        factors: serde_json::Value,
    ) -> Result<()> {
        let now = Utc::now();

        // Calculate risk level based on score
        let risk_level = if new_score >= 0.7 {
            "low"
        } else if new_score < 0.4 {
            "high"
        } else {
            "medium"
        };

        // First, get the current score for history
        let current_query = "SELECT trust_score FROM devices WHERE id = $1";
        let current_row: tokio_postgres::Row = db.query_one(current_query, &[&device_id]).await?;
        let current_score: f64 = current_row.get(0);

        // Update the device trust score and risk level
        let update_query = r#"
            UPDATE devices
            SET trust_score = $2, risk_level = $4, updated_at = $3
            WHERE id = $1
        "#;
        db.execute(
            update_query,
            &[&device_id, &new_score, &now, &risk_level],
        )
        .await?;

        // Insert trust score history
        let history_query = r#"
            INSERT INTO device_trust_history (
                device_id, previous_score, new_score, factors, changed_at
            )
            VALUES ($1, $2, $3, $4, $5)
        "#;
        db.execute(
            history_query,
            &[
                &device_id,
                &current_score,
                &new_score,
                &serde_json::to_string(&factors).unwrap_or_default(),
                &now,
            ],
        )
        .await?;

        Ok(())
    }

    /// Update device last seen timestamp
    /// Update device last seen timestamp
    pub async fn update_last_seen(db: &Database, device_id: Uuid) -> Result<()> {
        let now = Utc::now();
        let query = r#"
            UPDATE devices
            SET last_seen_at = $2, updated_at = $2
            WHERE id = $1
        "#;
        db.execute(query, &[&device_id, &now]).await?;
        Ok(())
    }

    /// List devices for a user
    pub async fn list_user_devices(db: &Database, user_id: Uuid) -> Result<Vec<Device>> {
        let query = r#"
            SELECT
                id, user_id, device_name, device_fingerprint, trust_score,
                risk_level, os, os_version, browser, browser_version,
                ip_address, user_agent, location_data, security_features, last_seen_at,
                first_seen_at, created_at, updated_at
            FROM devices
            WHERE user_id = $1
            ORDER BY last_seen_at DESC
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&user_id]).await?;
        // Convert rows to Vec<Device>
        rows.into_iter()
            .map(|row| row.try_into())
            .collect::<Result<Vec<Device>>>()
    }

    /// Delete device
    pub async fn delete_device(db: &Database, device_id: Uuid) -> Result<()> {
        let query = "DELETE FROM devices WHERE id = $1";
        db.execute(query, &[&device_id]).await?;
        Ok(())
    }
}


/// Database operations for OAuth2
pub mod oauth2 {
    use authenc_core::error::Result;

    use authenc_models::models::{OAuth2AccessToken, OAuth2AuthorizationCode, OAuth2Client};

    use crate::database::Database;
    use chrono::Utc;
    use uuid::Uuid;

    /// Create OAuth2 client
    pub async fn create_client(db: &Database, client: &OAuth2Client) -> Result<OAuth2Client> {
        let client_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO oauth2_clients (
                id, client_id, client_secret_hash, client_name, client_type,
                redirect_uris, scopes, grant_types, response_types,
                token_endpoint_auth_method, owner_id, realm_id,
                enabled, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING
                id, client_id, client_secret_hash, client_name, client_type,
                redirect_uris, scopes, grant_types, response_types,
                token_endpoint_auth_method, owner_id, realm_id,
                enabled, created_at, updated_at, deleted_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &client_id,
                    &client.client_id,
                    &client.client_secret_hash,
                    &client.client_name,
                    &client.client_type,
                    &client.redirect_uris,
                    &client.scopes,
                    &client.grant_types,
                    &client.response_types,
                    &client.token_endpoint_auth_method,
                    &client.owner_id,
                    &client.realm_id,
                    &client.enabled,
                    &now,
                    &now,
                ],
            )
            .await?;

        // Convert row to OAuth2Client
        row.try_into()
    }

    /// Get OAuth2 client by client ID
    pub async fn get_client_by_id(db: &Database, client_id: &str) -> Result<Option<OAuth2Client>> {
        let query = r#"
            SELECT
                id, client_id, client_secret_hash, client_name, client_type,
                redirect_uris, scopes, grant_types, response_types,
                token_endpoint_auth_method, owner_id, realm_id,
                enabled, created_at, updated_at, deleted_at
            FROM oauth2_clients
            WHERE client_id = $1 AND deleted_at IS NULL
        "#;

        let row_opt = db.query_opt(query, &[&client_id]).await?;

        match row_opt {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    /// Store authorization code
    pub async fn store_authorization_code(
        db: &Database,
        code: &OAuth2AuthorizationCode,
    ) -> Result<()> {
        let code_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO oauth2_authorization_codes (
                id, code, client_id, user_id, redirect_uri, scopes,
                code_challenge, code_challenge_method, expires_at,
                used, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#;

        db.execute(
            query,
            &[
                &code_id,
                &code.code,
                &code.client_id,
                &code.user_id,
                &code.redirect_uri,
                &code.scopes,
                &code.code_challenge,
                &code.code_challenge_method,
                &code.expires_at,
                &false,
                &now,
            ],
        )
        .await?;

        Ok(())
    }

    /// Get authorization code by code value
    pub async fn get_authorization_code(
        db: &Database,
        code: &str,
    ) -> Result<Option<OAuth2AuthorizationCode>> {
        let query = r#"
            SELECT
                id, code, client_id, user_id, redirect_uri, scopes,
                code_challenge, code_challenge_method, expires_at,
                used, created_at
            FROM oauth2_authorization_codes
            WHERE code = $1 AND used = false AND expires_at > NOW()
        "#;

        let row: tokio_postgres::Row = db.query_one(query, &[&code]).await?;
        // Convert row to OAuth2AuthorizationCode
        Ok(Some(row.try_into()?))
    }

    /// Mark authorization code as used
    pub async fn mark_code_used(db: &Database, code: &str) -> Result<()> {
        let query = "UPDATE oauth2_authorization_codes SET used = true WHERE code = $1";
        db.execute(query, &[&code]).await?;
        Ok(())
    }

    /// Store access token
    pub async fn store_access_token(db: &Database, token: &OAuth2AccessToken) -> Result<()> {
        let query = r#"
            INSERT INTO oauth2_access_tokens (
                id, token_hash, refresh_token_hash, client_id, user_id,
                scopes, expires_at, refresh_expires_at, revoked, revoked_at,
                created_at, last_used_at, session_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            ON CONFLICT (id) DO UPDATE SET
                revoked = EXCLUDED.revoked,
                revoked_at = EXCLUDED.revoked_at,
                last_used_at = EXCLUDED.last_used_at,
                session_id = EXCLUDED.session_id
        "#;

        db.execute(
            query,
            &[
                &token.id,
                &token.token_hash,
                &token.refresh_token_hash,
                &token.client_id,
                &token.user_id,
                &token.scopes,
                &token.expires_at,
                &token.refresh_expires_at,
                &token.revoked,
                &token.revoked_at,
                &token.created_at,
                &token.last_used_at,
                &token.session_id,
            ],
        )
        .await?;

        Ok(())
    }

    /// Get access token by hash
    pub async fn get_access_token(
        db: &Database,
        token_hash: &str,
    ) -> Result<Option<OAuth2AccessToken>> {
        let query = r#"
            SELECT
                id, token_hash, refresh_token_hash, client_id, user_id,
                scopes, expires_at, refresh_expires_at, revoked,
                revoked_at, created_at, last_used_at, session_id
            FROM oauth2_access_tokens
            WHERE token_hash = $1 AND revoked = false AND expires_at > NOW()
        "#;

        let row_opt = db.query_opt(query, &[&token_hash]).await?;

        match row_opt {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    /// Get access token by refresh token hash
    pub async fn get_access_token_by_refresh_token(
        db: &Database,
        refresh_token_hash: &str,
    ) -> Result<Option<OAuth2AccessToken>> {
        let query = r#"
            SELECT
                id, token_hash, refresh_token_hash, client_id, user_id,
                scopes, expires_at, refresh_expires_at, revoked,
                revoked_at, created_at, last_used_at, session_id
            FROM oauth2_access_tokens
            WHERE refresh_token_hash = $1 AND revoked = false
        "#;

        let row_opt = db.query_opt(query, &[&refresh_token_hash]).await?;

        match row_opt {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    /// Revoke access token
    pub async fn revoke_token(db: &Database, token_hash: &str) -> Result<()> {
        let now = Utc::now();
        let query = r#"
            UPDATE oauth2_access_tokens
            SET revoked = true, revoked_at = $2
            WHERE token_hash = $1
        "#;
        db.execute(query, &[&token_hash, &now]).await?;
        Ok(())
    }

    /// Get all OAuth2 clients
    pub async fn get_all_clients(db: &Database) -> Result<Vec<OAuth2Client>> {
        let query = r#"
            SELECT
                id, client_id, client_secret_hash, client_name, client_type,
                redirect_uris, scopes, grant_types, response_types,
                token_endpoint_auth_method, owner_id, realm_id,
                enabled, created_at, updated_at, deleted_at
            FROM oauth2_clients
            WHERE deleted_at IS NULL
            ORDER BY created_at DESC
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[]).await?;
        let mut clients = Vec::new();

        for row in rows {
            clients.push(row.try_into()?);
        }

        Ok(clients)
    }

    /// Delete OAuth2 client by client ID
    pub async fn delete_client(db: &Database, client_id: &str) -> Result<bool> {
        let now = Utc::now();
        let query = r#"
            UPDATE oauth2_clients
            SET deleted_at = $2
            WHERE client_id = $1 AND deleted_at IS NULL
        "#;

        let rows_affected = db.execute(query, &[&client_id, &now]).await?;
        Ok(rows_affected > 0)
    }

    /// Revoke all access tokens for a user
    pub async fn revoke_user_tokens(db: &Database, user_id: Uuid) -> Result<()> {
        let now = Utc::now();
        let query = r#"
            UPDATE oauth2_access_tokens
            SET revoked = true, revoked_at = $2
            WHERE user_id = $1 AND revoked = false
        "#;
        db.execute(query, &[&user_id, &now]).await?;
        Ok(())
    }
}

/// Database operations for organizations
pub mod organizations {
    use authenc_core::error::{AuthencError, Result};

    use authenc_models::models::{Organization, OrganizationInvitation, OrganizationMember};

    use authenc_spi::spi::organization::OrganizationRole;

    use crate::database::Database;
    use chrono::Utc;
    use log::error;
    use std::collections::HashMap;
    use uuid::Uuid;

    /// Create organization
    pub async fn create_organization(db: &Database, org: &Organization) -> Result<Organization> {
        let org_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO organizations (
                id, name, display_name, description, domain,
                logo_url, website_url, owner_id, realm_id,
                enabled, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING
                id, name, display_name, description, domain,
                logo_url, website_url, owner_id, realm_id,
                enabled, created_at, updated_at, deleted_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &org_id,
                    &org.name,
                    &org.display_name,
                    &org.description,
                    &org.domain,
                    &org.logo_url,
                    &org.website_url,
                    &org.owner_id,
                    &org.realm_id,
                    &org.enabled,
                    &now,
                    &now,
                ],
            )
            .await?;

        // Convert row to Organization
        row.try_into()
    }

    /// Get organization by ID
    pub async fn get_organization_by_id(
        db: &Database,
        org_id: Uuid,
    ) -> Result<Option<Organization>> {
        let query = r#"
            SELECT
                id, name, display_name, description, domain,
                logo_url, website_url, owner_id, realm_id,
                enabled, created_at, updated_at, deleted_at
            FROM organizations
            WHERE id = $1 AND deleted_at IS NULL
        "#;

        let row: tokio_postgres::Row = db.query_one(query, &[&org_id]).await?;
        // Convert row to Organization
        Ok(Some(row.try_into()?))
    }

    /// Add member to organization
    pub async fn add_member(
        db: &Database,
        org_id: Uuid,
        user_id: Uuid,
        role: &str,
        invited_by: Option<Uuid>,
    ) -> Result<()> {
        let member_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO organization_members (
                id, organization_id, user_id, role, invited_by,
                invited_at, joined_at, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        "#;

        db.execute(
            query,
            &[
                &member_id,
                &org_id,
                &user_id,
                &role,
                &invited_by,
                &now,
                &now,
                &now,
                &now,
            ],
        )
        .await?;

        Ok(())
    }

    /// Create organization invitation
    pub async fn create_invitation(
        db: &Database,
        invitation: &OrganizationInvitation,
    ) -> Result<()> {
        let invitation_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO organization_invitations (
                id, organization_id, email, role, invited_by,
                token_hash, expires_at, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        "#;

        db.execute(
            query,
            &[
                &invitation_id,
                &invitation.organization_id,
                &invitation.email,
                &invitation.role,
                &invitation.invited_by,
                &invitation.token_hash,
                &invitation.expires_at,
                &now,
            ],
        )
        .await?;

        Ok(())
    }

    /// Get invitation by token
    pub async fn get_invitation_by_token(
        db: &Database,
        token_hash: &str,
    ) -> Result<Option<OrganizationInvitation>> {
        let query = r#"
            SELECT
                id, organization_id, email, role, invited_by,
                token_hash, expires_at, accepted_at, accepted_by, created_at
            FROM organization_invitations
            WHERE token_hash = $1 AND expires_at > NOW() AND accepted_at IS NULL
        "#;

        let row: tokio_postgres::Row = db.query_one(query, &[&token_hash]).await?;
        // Convert row to OrganizationInvitation
        Ok(Some(row.try_into()?))
    }

    /// Accept organization invitation
    pub async fn accept_invitation(db: &Database, token_hash: &str, user_id: Uuid) -> Result<()> {
        let now = Utc::now();

        // First get the invitation
        let invitation = get_invitation_by_token(db, token_hash)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("Invitation not found or expired"))?;

        // Mark invitation as accepted
        let update_query = r#"
            UPDATE organization_invitations
            SET accepted_at = $2, accepted_by = $3
            WHERE token_hash = $1
        "#;
        db.execute(update_query, &[&token_hash, &now, &user_id])
            .await?;

        // Add user as organization member
        add_member(
            db,
            invitation.organization_id,
            user_id,
            &invitation.role,
            Some(invitation.invited_by),
        )
        .await?;

        Ok(())
    }

    /// Get organization by domain
    pub async fn get_organization_by_domain(
        db: &Database,
        domain: &str,
    ) -> Result<Option<Organization>> {
        let query = r#"
            SELECT
                id, name, display_name, description, domain, logo_url, website,
                enabled, created_at, updated_at, attributes
            FROM organizations
            WHERE domain = $1
        "#;

        let row = db.query_opt(query, &[&domain]).await.map_err(|e| {
            error!("Failed to get organization by domain: {}", e);
            AuthencError::database("Failed to get organization by domain")
        })?;

        if let Some(row) = row {
            // Convert row to Organization
            let attributes_json: serde_json::Value = row.get(10);
            let _attributes: HashMap<String, String> =
                serde_json::from_value(attributes_json).unwrap_or_default();

            Ok(Some(Organization {
                id: row.get(0),
                name: row.get(1),
                display_name: row.get(2),
                description: row.get(3),
                domain: row.get(4),
                logo_url: row.get(5),
                website_url: row.get(6),
                enabled: row.get(7),
                created_at: row.get(8),
                updated_at: row.get(9),
                owner_id: row.get(10),
                realm_id: row.get(11),
                deleted_at: row.get(12),
            }))
        } else {
            Ok(None)
        }
    }

    /// Update organization
    pub async fn update_organization(db: &Database, org: &Organization) -> Result<()> {
        let query = r#"
            UPDATE organizations
            SET name = $2, display_name = $3, description = $4, domain = $5,
                logo_url = $6, website_url = $7, enabled = $8, updated_at = $9
            WHERE id = $1
        "#;

        db.execute(
            query,
            &[
                &org.id,
                &org.name,
                &org.display_name,
                &org.description,
                &org.domain,
                &org.logo_url,
                &org.website_url,
                &org.enabled,
                &org.updated_at,
            ],
        )
        .await
        .map_err(|e| {
            error!("Failed to update organization: {}", e);
            AuthencError::database("Failed to update organization")
        })?;

        Ok(())
    }

    /// Delete organization
    pub async fn delete_organization(db: &Database, organization_id: &Uuid) -> Result<()> {
        let query = "DELETE FROM organizations WHERE id = $1";

        db.execute(query, &[organization_id]).await.map_err(|e| {
            error!("Failed to delete organization: {}", e);
            AuthencError::database("Failed to delete organization")
        })?;

        Ok(())
    }

    /// Get organization members
    pub async fn get_organization_members(
        db: &Database,
        organization_id: &Uuid,
    ) -> Result<Vec<OrganizationMember>> {
        let query = r#"
            SELECT om.user_id, om.organization_id, om.role, om.joined_at, om.invited_by
            FROM organization_members om
            WHERE om.organization_id = $1
            ORDER BY om.joined_at
        "#;

        let rows: Vec<tokio_postgres::Row> =
            db.query(query, &[organization_id]).await.map_err(|e| {
                error!("Failed to get organization members: {}", e);
                AuthencError::database("Failed to get organization members")
            })?;

        let mut members = Vec::new();
        for row in rows {
            members.push(OrganizationMember {
                id: row.get(0),
                organization_id: row.get(1),
                user_id: row.get(2),
                role: OrganizationRole::parse(&row.get::<_, String>(3))
                    .unwrap_or(OrganizationRole::Member)
                    .as_str()
                    .to_string(),
                invited_by: row.get(4),
                invited_at: row.get(5),
                joined_at: row.get(6),
                created_at: row.get(7),
                updated_at: row.get(8),
            });
        }

        Ok(members)
    }

    /// Get user organizations
    pub async fn get_user_organizations(
        db: &Database,
        user_id: &Uuid,
    ) -> Result<Vec<Organization>> {
        let query = r#"
            SELECT
                o.id, o.name, o.display_name, o.description, o.domain, o.logo_url, o.website_url,
                o.enabled, o.created_at, o.updated_at, o.owner_id, o.realm_id, o.deleted_at
            FROM organizations o
            JOIN organization_members om ON o.id = om.organization_id
            WHERE om.user_id = $1
            ORDER BY o.created_at
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[user_id]).await.map_err(|e| {
            error!("Failed to get user organizations: {}", e);
            AuthencError::database("Failed to get user organizations")
        })?;

        let mut organizations = Vec::new();
        for row in rows {
            organizations.push(Organization {
                id: row.get(0),
                name: row.get(1),
                display_name: row.get(2),
                description: row.get(3),
                domain: row.get(4),
                logo_url: row.get(5),
                website_url: row.get(6),
                enabled: row.get(7),
                created_at: row.get(8),
                updated_at: row.get(9),
                owner_id: row.get(10),
                realm_id: row.get(11),
                deleted_at: row.get(12),
            });
        }

        Ok(organizations)
    }

    /// Remove member from organization
    pub async fn remove_organization_member(
        db: &Database,
        organization_id: &Uuid,
        user_id: &Uuid,
    ) -> Result<()> {
        let query = "DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2";

        db.execute(query, &[organization_id, user_id])
            .await
            .map_err(|e| {
                error!("Failed to remove organization member: {}", e);
                AuthencError::database("Failed to remove organization member")
            })?;

        Ok(())
    }

    /// Update member role
    pub async fn update_member_role(
        db: &Database,
        organization_id: &Uuid,
        user_id: &Uuid,
        role: OrganizationRole,
    ) -> Result<()> {
        let query = r#"
            UPDATE organization_members
            SET role = $3
            WHERE organization_id = $1 AND user_id = $2
        "#;

        db.execute(query, &[organization_id, user_id, &role.as_str()])
            .await
            .map_err(|e| {
                error!("Failed to update member role: {}", e);
                AuthencError::database("Failed to update member role")
            })?;

        Ok(())
    }

    /// Organization domain for verification
    #[derive(Debug, Clone)]
    pub struct OrganizationDomain {
        /// Unique identifier for the organization domain
        pub id: Uuid,
        /// ID of the organization this domain belongs to
        pub organization_id: Uuid,
        /// The domain name (e.g., "example.com")
        pub domain: String,
        /// Whether the domain has been verified
        pub verified: bool,
        /// Token used for domain verification
        pub verification_token: Option<String>,
        /// Method used for domain verification
        pub verification_method: String,
        /// Timestamp when the domain was verified
        pub verified_at: Option<chrono::DateTime<Utc>>,
        /// Timestamp when the domain was created
        pub created_at: chrono::DateTime<Utc>,
        /// Timestamp when the domain was last updated
        pub updated_at: chrono::DateTime<Utc>,
    }

    /// Add domain to organization
    pub async fn add_domain(
        db: &Database,
        organization_id: Uuid,
        domain: &str,
        verification_method: &str,
    ) -> Result<OrganizationDomain> {
        let domain_id = Uuid::new_v4();
        let verification_token = Uuid::new_v4().to_string();
        let now = Utc::now();

        let query = r#"
            INSERT INTO organization_domains (
                id, organization_id, domain, verified, verification_token,
                verification_method, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id, organization_id, domain, verified, verification_token,
                      verification_method, verified_at, created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &domain_id,
                    &organization_id,
                    &domain,
                    &false,
                    &verification_token,
                    &verification_method,
                    &now,
                    &now,
                ],
            )
            .await
            .map_err(|e| {
                error!("Failed to add organization domain: {}", e);
                AuthencError::database("Failed to add organization domain")
            })?;

        Ok(OrganizationDomain {
            id: row.get(0),
            organization_id: row.get(1),
            domain: row.get(2),
            verified: row.get(3),
            verification_token: row.get(4),
            verification_method: row.get(5),
            verified_at: row.get(6),
            created_at: row.get(7),
            updated_at: row.get(8),
        })
    }

    /// Verify organization domain
    pub async fn verify_domain(db: &Database, domain_id: Uuid) -> Result<()> {
        let now = Utc::now();

        let query = r#"
            UPDATE organization_domains
            SET verified = true, verified_at = $2, updated_at = $3
            WHERE id = $1
        "#;

        db.execute(query, &[&domain_id, &now, &now])
            .await
            .map_err(|e| {
                error!("Failed to verify domain: {}", e);
                AuthencError::database("Failed to verify domain")
            })?;

        Ok(())
    }

    /// Get organization domains
    pub async fn get_domains(
        db: &Database,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationDomain>> {
        let query = r#"
            SELECT id, organization_id, domain, verified, verification_token,
                   verification_method, verified_at, created_at, updated_at
            FROM organization_domains
            WHERE organization_id = $1
            ORDER BY created_at DESC
        "#;

        let rows: Vec<tokio_postgres::Row> =
            db.query(query, &[&organization_id]).await.map_err(|e| {
                error!("Failed to get organization domains: {}", e);
                AuthencError::database("Failed to get organization domains")
            })?;

        let mut domains = Vec::new();
        for row in rows {
            domains.push(OrganizationDomain {
                id: row.get(0),
                organization_id: row.get(1),
                domain: row.get(2),
                verified: row.get(3),
                verification_token: row.get(4),
                verification_method: row.get(5),
                verified_at: row.get(6),
                created_at: row.get(7),
                updated_at: row.get(8),
            });
        }

        Ok(domains)
    }

    /// Link identity provider to organization
    pub async fn link_identity_provider(
        db: &Database,
        organization_id: Uuid,
        identity_provider_id: Uuid,
        priority: i32,
    ) -> Result<()> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO organization_identity_providers (
                id, organization_id, identity_provider_id, priority, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (organization_id, identity_provider_id)
            DO UPDATE SET priority = $4, updated_at = $6
        "#;

        db.execute(
            query,
            &[
                &id,
                &organization_id,
                &identity_provider_id,
                &priority,
                &now,
                &now,
            ],
        )
        .await
        .map_err(|e| {
            error!("Failed to link identity provider: {}", e);
            AuthencError::database("Failed to link identity provider")
        })?;

        Ok(())
    }

    /// Unlink identity provider from organization
    pub async fn unlink_identity_provider(
        db: &Database,
        organization_id: Uuid,
        identity_provider_id: Uuid,
    ) -> Result<()> {
        let query = r#"
            DELETE FROM organization_identity_providers
            WHERE organization_id = $1 AND identity_provider_id = $2
        "#;

        db.execute(query, &[&organization_id, &identity_provider_id])
            .await
            .map_err(|e| {
                error!("Failed to unlink identity provider: {}", e);
                AuthencError::database("Failed to unlink identity provider")
            })?;

        Ok(())
    }
}

/// Database operations for SAML
pub mod saml {
    use authenc_core::error::Result;

    use authenc_models::models::{SamlServiceProvider, SamlSession};

    use crate::database::Database;
    use chrono::Utc;
    use uuid::Uuid;

    /// Create SAML service provider
    pub async fn create_service_provider(
        db: &Database,
        sp: &SamlServiceProvider,
    ) -> Result<SamlServiceProvider> {
        let sp_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO saml_service_providers (
                id, entity_id, metadata_url, metadata_xml,
                signing_certificate, encryption_certificate,
                assertion_consumer_service_url, single_logout_service_url,
                name_id_format, realm_id, enabled, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING
                id, entity_id, metadata_url, metadata_xml,
                signing_certificate, encryption_certificate,
                assertion_consumer_service_url, single_logout_service_url,
                name_id_format, realm_id, enabled, created_at, updated_at, deleted_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &sp_id,
                    &sp.entity_id,
                    &sp.metadata_url,
                    &sp.metadata_xml,
                    &sp.signing_certificate,
                    &sp.encryption_certificate,
                    &sp.assertion_consumer_service_url,
                    &sp.single_logout_service_url,
                    &sp.name_id_format,
                    &sp.realm_id,
                    &sp.enabled,
                    &now,
                    &now,
                ],
            )
            .await?;

        // Convert row to SamlServiceProvider
        row.try_into()
    }

    /// Get SAML service provider by entity ID
    pub async fn get_service_provider_by_entity_id(
        db: &Database,
        entity_id: &str,
    ) -> Result<Option<SamlServiceProvider>> {
        let query = r#"
            SELECT
                id, entity_id, metadata_url, metadata_xml,
                signing_certificate, encryption_certificate,
                assertion_consumer_service_url, single_logout_service_url,
                name_id_format, realm_id, enabled, created_at, updated_at, deleted_at
            FROM saml_service_providers
            WHERE entity_id = $1 AND deleted_at IS NULL
        "#;

        let row: tokio_postgres::Row = db.query_one(query, &[&entity_id]).await?;
        // Convert row to SamlServiceProvider
        Ok(Some(row.try_into()?))
    }

    /// Create SAML session
    pub async fn create_session(db: &Database, session: &SamlSession) -> Result<()> {
        let session_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO saml_sessions (
                id, session_id, user_id, identity_provider_id,
                service_provider_id, name_id, name_id_format,
                session_index, authn_instant, expires_at, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#;

        db.execute(
            query,
            &[
                &session_id,
                &session.session_id,
                &session.user_id,
                &session.identity_provider_id,
                &session.service_provider_id,
                &session.name_id,
                &session.name_id_format,
                &session.session_index,
                &session.authn_instant,
                &session.expires_at,
                &now,
            ],
        )
        .await?;

        Ok(())
    }

    /// Get SAML session by session ID
    pub async fn get_session_by_id(db: &Database, session_id: &str) -> Result<Option<SamlSession>> {
        let query = r#"
            SELECT
                id, session_id, user_id, identity_provider_id,
                service_provider_id, name_id, name_id_format,
                session_index, authn_instant, expires_at, created_at
            FROM saml_sessions
            WHERE session_id = $1 AND expires_at > NOW()
        "#;

        let row: tokio_postgres::Row = db.query_one(query, &[&session_id]).await?;
        // Convert row to SamlSession
        Ok(Some(row.try_into()?))
    }

    /// Delete expired SAML sessions
    pub async fn cleanup_expired_sessions(db: &Database) -> Result<u64> {
        let query = "DELETE FROM saml_sessions WHERE expires_at < NOW()";
        db.execute(query, &[]).await
    }
}

/// Database operations for audit logging
pub mod audit {
    use authenc_core::error::Result;

    use authenc_models::models::AuditEvent;

    use crate::database::Database;

    use uuid::Uuid;

    /// Create audit log entry
    pub async fn create_audit_log(db: &Database, event: &AuditEvent) -> Result<()> {
        let event_id = Uuid::new_v4();

        let query = r#"
            INSERT INTO audit_logs (
                id, timestamp, event_type, user_id, session_id,
                client_id, resource_type, resource_id, action,
                status, details, ip_address, user_agent,
                location_data, error_message, request_id, correlation_id,
                realm_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
        "#;

        db.execute(
            query,
            &[
                &event_id,
                &event.timestamp,
                &event.event_type,
                &event.user_id,
                &event.session_id,
                &event.client_id,
                &event.resource_type,
                &event.resource_id,
                &event.action,
                &event.status,
                &event
                    .details
                    .as_ref()
                    .map(|v| serde_json::to_string(v).unwrap_or_default()),
                &event.ip_address,
                &event.user_agent,
                &event.location_data,
                &event.error_message,
                &event.request_id,
                &event.correlation_id,
                &event.realm_id,
            ],
        )
        .await?;

        Ok(())
    }

    /// Get audit logs with filtering
    pub async fn get_audit_logs(
        db: &Database,
        user_id: Option<Uuid>,
        event_type: Option<&str>,
        realm_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditEvent>> {
        let query = r#"
            SELECT
                id, timestamp, event_type, user_id, session_id,
                client_id, resource_type, resource_id, action,
                status, details, ip_address, user_agent,
                location_data, error_message, request_id, correlation_id,
                realm_id
            FROM audit_logs
            WHERE ($1::uuid IS NULL OR user_id = $1)
            AND ($2::text IS NULL OR event_type = $2)
            AND ($3::uuid IS NULL OR realm_id = $3)
            ORDER BY timestamp DESC
            LIMIT $4 OFFSET $5
        "#;

        let rows = db
            .query(query, &[&user_id, &event_type, &realm_id, &limit, &offset])
            .await?;
        // Convert rows to Vec<AuditEvent>
        rows.into_iter()
            .map(|row: tokio_postgres::Row| row.try_into())
            .collect::<Result<Vec<AuditEvent>>>()
    }

    /// Get audit log count
    pub async fn get_audit_log_count(
        db: &Database,
        user_id: Option<Uuid>,
        event_type: Option<&str>,
        realm_id: Option<Uuid>,
    ) -> Result<i64> {
        let query = r#"
            SELECT COUNT(*) FROM audit_logs
            WHERE ($1::uuid IS NULL OR user_id = $1)
            AND ($2::text IS NULL OR event_type = $2)
            AND ($3::uuid IS NULL OR realm_id = $3)
        "#;

        let client = db.get_connection().await?;
        let count: i64 = client
            .query_one(query, &[&user_id, &event_type, &realm_id])
            .await?
            .try_get(0)?;
        Ok(count)
    }

    /// Cleanup old audit logs (keep last 90 days)
    pub async fn cleanup_old_logs(db: &Database) -> Result<u64> {
        let query = "DELETE FROM audit_logs WHERE timestamp < NOW() - INTERVAL '90 days'";
        db.execute(query, &[]).await
    }
}

/// Database operations for users
pub mod users {
    use authenc_core::error::{AuthencError, Result};

    use authenc_models::models::{User, user::CreateUserRequest, user::UpdateUserRequest};

    use crate::database::Database;
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    /// Create a new user
    pub async fn create_user(db: &Database, request: &CreateUserRequest) -> Result<User> {
        // Prepare all data outside the async block
        let username = request.username.clone();
        let email = request.email.clone();
        let first_name = request.first_name.clone();
        let last_name = request.last_name.clone();
        let phone_number = request.phone_number.clone();
        let password_hash = if let Some(p) = &request.password {
            Some(authenc_crypto::utils::crypto::password::hash_password(p).await.unwrap_or_default())
        } else {
            None
        };
        let realm_id = request.realm_id;
        let organization_id = request.organization_id;
        let _attributes_json = request
            .attributes
            .as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());

        // Create user ID and timestamp outside
        let _user_id = Uuid::new_v4();
        let _now = Utc::now();

        let client = db.get_connection().await?;
        let user_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO users (
                id, username, email, first_name, last_name,
                phone_number, phone_verified, password_hash, totp_secret,
                totp_backup_codes, webauthn_enabled, account_locked,
                account_locked_until, failed_login_attempts, last_failed_login_at,
                password_changed_at, password_expires_at, require_password_change,
                organization_id, attributes, email_verified, enabled,
                realm_id, federated, created_at, updated_at, deleted_at,
                last_login_at, login_count
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29)
            RETURNING
                id, username, email, first_name, last_name,
                phone_number, phone_verified, password_hash, totp_secret,
                totp_backup_codes, webauthn_enabled, account_locked,
                account_locked_until, failed_login_attempts, last_failed_login_at,
                password_changed_at, password_expires_at, require_password_change,
                organization_id, attributes, email_verified, enabled,
                realm_id, federated, created_at, updated_at, deleted_at,
                last_login_at, login_count
        "#;

        let row = client
            .query_one(
                query,
                &[
                    &user_id,
                    &username,
                    &email,
                    &first_name,
                    &last_name,
                    &phone_number,
                    &false, // phone_verified
                    &password_hash,
                    &None::<String>,                // totp_secret
                    &None::<Vec<String>>,           // totp_backup_codes
                    &false,                         // webauthn_enabled
                    &false,                         // account_locked
                    &None::<chrono::DateTime<Utc>>, // account_locked_until
                    &0i32,                          // failed_login_attempts
                    &None::<chrono::DateTime<Utc>>, // last_failed_login_at
                    &None::<chrono::DateTime<Utc>>, // password_changed_at
                    &None::<chrono::DateTime<Utc>>, // password_expires_at
                    &false,                         // require_password_change
                    &organization_id,
                    &request.attributes,
                    &true, // email_verified
                    &true, // enabled
                    &realm_id,
                    &false, // federated (default to false for regular user creation)
                    &now,
                    &now,
                    &None::<chrono::DateTime<Utc>>, // deleted_at
                    &None::<chrono::DateTime<Utc>>, // last_login_at
                    &0i32,                          // login_count
                ],
            )
            .await?;

        // Convert row to User by extracting values directly
        let user = User {
            id: row.get("id"),
            username: row.get("username"),
            email: row.get("email"),
            email_verified: row.get("email_verified"),
            first_name: row.get("first_name"),
            last_name: row.get("last_name"),
            phone_number: row.get("phone_number"),
            phone_verified: row.get("phone_verified"),
            password_hash: row.get("password_hash"),
            totp_secret: row.get("totp_secret"),
            totp_backup_codes: row.get("totp_backup_codes"),
            webauthn_enabled: row.get("webauthn_enabled"),
            account_locked: row.get("account_locked"),
            account_locked_until: row.get("account_locked_until"),
            failed_login_attempts: row.get("failed_login_attempts"),
            last_failed_login_at: row.get("last_failed_login_at"),
            password_changed_at: row.get("password_changed_at"),
            password_expires_at: row.get("password_expires_at"),
            require_password_change: row.get("require_password_change"),
            organization_id: row.get("organization_id"),
            attributes: row.get("attributes"),
            enabled: row.get("enabled"),
            realm_id: row.get("realm_id"),
            federated: row.get("federated"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            deleted_at: row.get("deleted_at"),
            last_login_at: row.get("last_login_at"),
            login_count: row.get("login_count"),
            reset_token_hash: None,
            reset_token_expires_at: None,
            verification_token_hash: None,
            verification_token_expires_at: None,
        };

        Ok(user)
    }

    /// Get user by ID
    pub async fn get_user_by_id(db: &Database, user_id: Uuid) -> Result<Option<User>> {
        let client = db.get_connection().await?;
        let query = r#"
            SELECT
                id, username, email, email_verified, first_name, last_name,
                phone_number, phone_verified, password_hash, totp_secret,
                totp_backup_codes, webauthn_enabled, account_locked,
                account_locked_until, failed_login_attempts, last_login_at,
                last_failed_login_at, password_changed_at, password_expires_at,
                require_password_change, realm_id, organization_id, attributes,
                enabled, federated, created_at, updated_at, deleted_at, login_count
            FROM users
            WHERE id = $1 AND deleted_at IS NULL
        "#;

        let row = client.query_opt(query, &[&user_id]).await?;
        Ok(row.map(|r| User {
            id: r.get("id"),
            username: r.get("username"),
            email: r.get("email"),
            email_verified: r.get("email_verified"),
            first_name: r.get("first_name"),
            last_name: r.get("last_name"),
            phone_number: r.get("phone_number"),
            phone_verified: r.get("phone_verified"),
            password_hash: r.get("password_hash"),
            totp_secret: r.get("totp_secret"),
            totp_backup_codes: r.get("totp_backup_codes"),
            webauthn_enabled: r.get("webauthn_enabled"),
            account_locked: r.get("account_locked"),
            account_locked_until: r.get("account_locked_until"),
            failed_login_attempts: r.get("failed_login_attempts"),
            last_failed_login_at: r.get("last_failed_login_at"),
            password_changed_at: r.get("password_changed_at"),
            password_expires_at: r.get("password_expires_at"),
            require_password_change: r.get("require_password_change"),
            organization_id: r.get("organization_id"),
            attributes: r.get("attributes"),
            enabled: r.get("enabled"),
            realm_id: r.get("realm_id"),
            federated: r.get("federated"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
            deleted_at: r.get("deleted_at"),
            last_login_at: r.get("last_login_at"),
            login_count: r.get("login_count"),
            reset_token_hash: None,
            reset_token_expires_at: None,
            verification_token_hash: r.try_get("verification_token_hash").ok().flatten(),
            verification_token_expires_at: r.try_get("verification_token_expires_at").ok().flatten(),
        }))
    }

    /// Get user by username
    pub async fn get_user_by_username(
        db: &Database,
        realm_id: &Uuid,
        username: &str,
    ) -> Result<Option<User>> {
        let client = db.get_connection().await?;
        let query = r#"
            SELECT
                id, username, email, email_verified, first_name, last_name,
                phone_number, phone_verified, password_hash, totp_secret,
                totp_backup_codes, webauthn_enabled, account_locked,
                account_locked_until, failed_login_attempts, last_login_at,
                last_failed_login_at, password_changed_at, password_expires_at,
                require_password_change, realm_id, organization_id, attributes,
                enabled, federated, created_at, updated_at, deleted_at, login_count
            FROM users
            WHERE username = $2 AND realm_id = $1 AND deleted_at IS NULL
        "#;

        let row = client.query_opt(query, &[realm_id, &username]).await?;
        Ok(row.map(|r| User {
            id: r.get("id"),
            username: r.get("username"),
            email: r.get("email"),
            email_verified: r.get("email_verified"),
            first_name: r.get("first_name"),
            last_name: r.get("last_name"),
            phone_number: r.get("phone_number"),
            phone_verified: r.get("phone_verified"),
            password_hash: r.get("password_hash"),
            totp_secret: r.get("totp_secret"),
            totp_backup_codes: r.get("totp_backup_codes"),
            webauthn_enabled: r.get("webauthn_enabled"),
            account_locked: r.get("account_locked"),
            account_locked_until: r.get("account_locked_until"),
            failed_login_attempts: r.get("failed_login_attempts"),
            last_failed_login_at: r.get("last_failed_login_at"),
            password_changed_at: r.get("password_changed_at"),
            password_expires_at: r.get("password_expires_at"),
            require_password_change: r.get("require_password_change"),
            organization_id: r.get("organization_id"),
            attributes: r.get("attributes"),
            enabled: r.get("enabled"),
            realm_id: r.get("realm_id"),
            federated: r.get("federated"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
            deleted_at: r.get("deleted_at"),
            last_login_at: r.get("last_login_at"),
            login_count: r.get("login_count"),
            reset_token_hash: None,
            reset_token_expires_at: None,
            verification_token_hash: r.try_get("verification_token_hash").ok().flatten(),
            verification_token_expires_at: r.try_get("verification_token_expires_at").ok().flatten(),
        }))
    }

    /// Get user by email
    pub async fn get_user_by_email(
        db: &Database,
        realm_id: &Uuid,
        email: &str,
    ) -> Result<Option<User>> {
        let query = r#"
            SELECT
                id, username, email, email_verified, first_name, last_name,
                phone_number, phone_verified, password_hash, totp_secret,
                totp_backup_codes, webauthn_enabled, account_locked,
                account_locked_until, failed_login_attempts, last_login_at,
                last_failed_login_at, password_changed_at, password_expires_at,
                require_password_change, realm_id, organization_id, attributes,
                enabled, federated, created_at, updated_at, deleted_at, last_login_at, login_count
            FROM users
            WHERE email = $2 AND realm_id = $1 AND deleted_at IS NULL
        "#;

        let row = db.query_opt(query, &[realm_id, &email]).await?;
        Ok(row.map(|r| row_to_user(&r)))
    }

    /// Update user
    pub async fn update_user(
        db: &Database,
        user_id: Uuid,
        request: &UpdateUserRequest,
    ) -> Result<User> {
        let now = Utc::now();

        let query = r#"
            UPDATE users SET
                username = COALESCE($2, username),
                email = COALESCE($3, email),
                first_name = COALESCE($4, first_name),
                last_name = COALESCE($5, last_name),
                phone_number = COALESCE($6, phone_number),
                enabled = COALESCE($7, enabled),
                email_verified = COALESCE($8, email_verified),
                phone_verified = COALESCE($9, phone_verified),
                require_password_change = COALESCE($10, require_password_change),
                attributes = COALESCE($11, attributes),
                updated_at = $12
            WHERE id = $1 AND deleted_at IS NULL
            RETURNING
                id, username, email, first_name, last_name,
                phone_number, phone_verified, password_hash, totp_secret,
                totp_backup_codes, webauthn_enabled, account_locked,
                account_locked_until, failed_login_attempts, last_failed_login_at,
                password_changed_at, password_expires_at, require_password_change,
                organization_id, attributes, email_verified, enabled,
                realm_id, federated, created_at, updated_at, deleted_at,
                last_login_at, login_count
        "#;

        let row = db
            .query_one(
                query,
                &[
                    &user_id,
                    &request.username,
                    &request.email,
                    &request.first_name,
                    &request.last_name,
                    &request.phone_number,
                    &request.enabled,
                    &request.email_verified,
                    &request.phone_verified,
                    &request.require_password_change,
                    &request
                        .attributes
                        .as_ref()
                        .map(|v| serde_json::to_string(v).unwrap_or_default()),
                    &now,
                ],
            )
            .await?;

        Ok(row_to_user(&row))
    }

    /// Delete user (soft delete)
    pub async fn delete_user(db: &Database, user_id: Uuid) -> Result<()> {
        let now = Utc::now();
        let query = "UPDATE users SET deleted_at = $2, updated_at = $2 WHERE id = $1";
        db.execute(query, &[&user_id, &now]).await?;
        Ok(())
    }

    /// Record successful login
    pub async fn record_login(db: &Database, user_id: Uuid) -> Result<()> {
        let now = Utc::now();
        let query = r#"
            UPDATE users SET
                last_login_at = $2,
                login_count = login_count + 1,
                failed_login_attempts = 0,
                account_locked = false,
                account_locked_until = NULL,
                updated_at = $2
            WHERE id = $1
        "#;
        db.execute(query, &[&user_id, &now]).await?;
        Ok(())
    }

    /// Record failed login attempt
    pub async fn record_failed_login(db: &Database, user_id: Uuid) -> Result<i32> {
        let now = Utc::now();
        let query = r#"
            UPDATE users SET
                failed_login_attempts = failed_login_attempts + 1,
                last_failed_login_at = $2,
                updated_at = $2
            WHERE id = $1
            RETURNING failed_login_attempts
        "#;
        let row: tokio_postgres::Row = db.query_one(query, &[&user_id, &now]).await?;
        Ok(row.get(0))
    }

    /// Update password
    pub async fn update_password(db: &Database, user_id: Uuid, password_hash: &str) -> Result<()> {
        let now = Utc::now();
        let query = r#"
            UPDATE users SET
                password_hash = $2,
                password_changed_at = $3,
                require_password_change = false,
                updated_at = $3
            WHERE id = $1
        "#;
        db.execute(query, &[&user_id, &password_hash, &now]).await?;
        Ok(())
    }

    /// Enable WebAuthn for user
    pub async fn enable_webauthn(db: &Database, user_id: Uuid) -> Result<()> {
        let now = Utc::now();
        let query = "UPDATE users SET webauthn_enabled = true, updated_at = $2 WHERE id = $1";
        db.execute(query, &[&user_id, &now]).await?;
        Ok(())
    }

    /// Disable WebAuthn for user
    pub async fn disable_webauthn(db: &Database, user_id: Uuid) -> Result<()> {
        let now = Utc::now();
        let query = "UPDATE users SET webauthn_enabled = false, updated_at = $2 WHERE id = $1";
        db.execute(query, &[&user_id, &now]).await?;
        Ok(())
    }

    /// Lock user account
    pub async fn lock_account(
        db: &Database,
        user_id: Uuid,
        until: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let now = Utc::now();
        let query = r#"
            UPDATE users SET
                account_locked = true,
                account_locked_until = $2,
                updated_at = $3
            WHERE id = $1
        "#;
        db.execute(query, &[&user_id, &until, &now]).await?;
        Ok(())
    }

    /// Unlock user account
    pub async fn unlock_account(db: &Database, user_id: Uuid) -> Result<()> {
        let now = Utc::now();
        let query = r#"
            UPDATE users SET
                account_locked = false,
                account_locked_until = NULL,
                failed_login_attempts = 0,
                updated_at = $2
            WHERE id = $1
        "#;
        db.execute(query, &[&user_id, &now]).await?;
        Ok(())
    }

    /// Set verification token for a user
    pub async fn set_verification_token(
        db: &Database,
        user_id: Uuid,
        token_hash: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let now = Utc::now();
        let query = r#"
            UPDATE users SET
                verification_token_hash = $2,
                verification_token_expires_at = $3,
                updated_at = $4
            WHERE id = $1
        "#;
        db.execute(query, &[&user_id, &token_hash, &expires_at, &now])
            .await?;
        Ok(())
    }

    /// Get user by verification token
    pub async fn get_user_by_verification_token(
        db: &Database,
        token_hash: &str,
    ) -> Result<Option<User>> {
        let query = r#"
            SELECT
                id, username, email, email_verified, first_name, last_name,
                phone_number, phone_verified, password_hash, totp_secret,
                totp_backup_codes, webauthn_enabled, account_locked,
                account_locked_until, failed_login_attempts, last_login_at,
                last_failed_login_at, password_changed_at, password_expires_at,
                require_password_change, realm_id, organization_id, attributes,
                enabled, federated, created_at, updated_at, deleted_at, login_count,
                reset_token_hash, reset_token_expires_at,
                verification_token_hash, verification_token_expires_at
            FROM users
            WHERE verification_token_hash = $1 AND deleted_at IS NULL AND enabled = true
        "#;

        let row_opt = db.query_opt(query, &[&token_hash]).await?;
        Ok(row_opt.map(|r| row_to_user(&r)))
    }

    /// Verify email and clear token atomically
    pub async fn verify_email_transaction(
        db: &Database,
        user_id: Uuid,
        token_hash: &str,
    ) -> Result<()> {
        let now = Utc::now();
        let query = r#"
            UPDATE users SET
                email_verified = true,
                verification_token_hash = NULL,
                verification_token_expires_at = NULL,
                updated_at = $2
            WHERE id = $1 AND verification_token_hash = $3 AND enabled = true
        "#;
        let rows_affected = db
            .execute(query, &[&user_id, &now, &token_hash])
            .await?;

        if rows_affected == 0 {
            return Err(AuthencError::validation("Verification token invalid"));
        }

        Ok(())
    }

    /// Set password reset token for a user
    pub async fn set_reset_token(
        db: &Database,
        user_id: Uuid,
        token_hash: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let now = Utc::now();
        let query = r#"
            UPDATE users SET
                reset_token_hash = $2,
                reset_token_expires_at = $3,
                updated_at = $4
            WHERE id = $1
        "#;
        db.execute(query, &[&user_id, &token_hash, &expires_at, &now])
            .await?;
        Ok(())
    }

    /// Get user by password reset token
    pub async fn get_user_by_reset_token(db: &Database, token_hash: &str) -> Result<Option<User>> {
        let query = r#"
            SELECT
                id, username, email, email_verified, first_name, last_name,
                phone_number, phone_verified, password_hash, totp_secret,
                totp_backup_codes, webauthn_enabled, account_locked,
                account_locked_until, failed_login_attempts, last_login_at,
                last_failed_login_at, password_changed_at, password_expires_at,
                require_password_change, realm_id, organization_id, attributes,
                enabled, federated, created_at, updated_at, deleted_at, login_count,
                reset_token_hash, reset_token_expires_at
            FROM users
            WHERE reset_token_hash = $1 AND deleted_at IS NULL AND enabled = true
        "#;

        let row_opt = db.query_opt(query, &[&token_hash]).await?;
        Ok(row_opt.map(|r| row_to_user(&r)))
    }

    /// Reset password and clear reset token atomically
    pub async fn reset_password_transaction(
        db: &Database,
        user_id: Uuid,
        password_hash: &str,
        token_hash: &str,
    ) -> Result<()> {
        let now = Utc::now();
        let query = r#"
            UPDATE users SET
                password_hash = $2,
                password_changed_at = $3,
                require_password_change = false,
                reset_token_hash = NULL,
                reset_token_expires_at = NULL,
                updated_at = $3,
                failed_login_attempts = 0,
                account_locked = false,
                account_locked_until = NULL
            WHERE id = $1 AND reset_token_hash = $4 AND enabled = true AND reset_token_expires_at > $3
        "#;
        let rows_affected = db
            .execute(query, &[&user_id, &password_hash, &now, &token_hash])
            .await?;

        if rows_affected == 0 {
            return Err(AuthencError::validation("Reset token already used or expired"));
        }

        Ok(())
    }

    /// Helper function to convert database row to User
    fn row_to_user(row: &tokio_postgres::Row) -> User {
        User {
            id: row.get("id"),
            username: row.get("username"),
            email: row.get("email"),
            email_verified: row.get("email_verified"),
            first_name: row.get("first_name"),
            last_name: row.get("last_name"),
            phone_number: row.get("phone_number"),
            phone_verified: row.get("phone_verified"),
            password_hash: row.get("password_hash"),
            totp_secret: row.get("totp_secret"),
            totp_backup_codes: row.get("totp_backup_codes"),
            webauthn_enabled: row.get("webauthn_enabled"),
            account_locked: row.get("account_locked"),
            account_locked_until: row.get("account_locked_until"),
            failed_login_attempts: row.get("failed_login_attempts"),
            last_failed_login_at: row.get("last_failed_login_at"),
            password_changed_at: row.get("password_changed_at"),
            password_expires_at: row.get("password_expires_at"),
            require_password_change: row.get("require_password_change"),
            realm_id: row.get("realm_id"),
            organization_id: row.get("organization_id"),
            attributes: row.get("attributes"),
            enabled: row.get("enabled"),
            federated: row.get("federated"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            deleted_at: row.get("deleted_at"),
            last_login_at: row.get("last_login_at"),
            login_count: row.get("login_count"),
            reset_token_hash: row.try_get("reset_token_hash").ok().flatten(),
            reset_token_expires_at: row.try_get("reset_token_expires_at").ok().flatten(),
            verification_token_hash: row.try_get("verification_token_hash").ok().flatten(),
            verification_token_expires_at: row.try_get("verification_token_expires_at").ok().flatten(),
        }
    }

    /// Get all users
    pub async fn get_all_users(db: &Database) -> Result<Vec<User>> {
        let client = db.get_connection().await?;
        let query = r#"
            SELECT
                id, username, email, first_name, last_name,
                phone_number, phone_verified, password_hash, totp_secret,
                totp_backup_codes, webauthn_enabled, account_locked,
                account_locked_until, failed_login_attempts, last_failed_login_at,
                password_changed_at, password_expires_at, require_password_change,
                organization_id, attributes, email_verified, enabled,
                realm_id, federated, created_at, updated_at, deleted_at,
                last_login_at, login_count
            FROM users
            WHERE deleted_at IS NULL
            ORDER BY created_at DESC
        "#;

        let rows = client.query(query, &[]).await?;
        let mut users = Vec::new();

        for row in rows {
            users.push(User {
                id: row.get("id"),
                username: row.get("username"),
                email: row.get("email"),
                email_verified: row.get("email_verified"),
                first_name: row.get("first_name"),
                last_name: row.get("last_name"),
                phone_number: row.get("phone_number"),
                phone_verified: row.get("phone_verified"),
                password_hash: row.get("password_hash"),
                totp_secret: row.get("totp_secret"),
                totp_backup_codes: row.get("totp_backup_codes"),
                webauthn_enabled: row.get("webauthn_enabled"),
                account_locked: row.get("account_locked"),
                account_locked_until: row.get("account_locked_until"),
                failed_login_attempts: row.get("failed_login_attempts"),
                last_failed_login_at: row.get("last_failed_login_at"),
                password_changed_at: row.get("password_changed_at"),
                password_expires_at: row.get("password_expires_at"),
                require_password_change: row.get("require_password_change"),
                organization_id: row.get("organization_id"),
                attributes: row.get("attributes"),
                enabled: row.get("enabled"),
                realm_id: row.get("realm_id"),
                federated: row.get("federated"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                deleted_at: row.get("deleted_at"),
                last_login_at: row.get("last_login_at"),
                login_count: row.get("login_count"),
            reset_token_hash: None,
                reset_token_expires_at: None,
            verification_token_hash: row.try_get("verification_token_hash").ok().flatten(),
            verification_token_expires_at: row.try_get("verification_token_expires_at").ok().flatten(),
            });
        }

        Ok(users)
    }

    /// Get users by realm
    pub async fn get_users_by_realm(db: &Database, realm_id: Uuid) -> Result<Vec<User>> {
        let client = db.get_connection().await?;
        let query = r#"
            SELECT
                id, username, email, first_name, last_name,
                phone_number, phone_verified, password_hash, totp_secret,
                totp_backup_codes, webauthn_enabled, account_locked,
                account_locked_until, failed_login_attempts, last_failed_login_at,
                password_changed_at, password_expires_at, require_password_change,
                organization_id, attributes, email_verified, enabled,
                realm_id, federated, created_at, updated_at, deleted_at,
                last_login_at, login_count
            FROM users
            WHERE realm_id = $1 AND deleted_at IS NULL
            ORDER BY created_at DESC
        "#;

        let rows = client.query(query, &[&realm_id]).await?;
        let mut users = Vec::new();

        for row in rows {
            users.push(User {
                id: row.get("id"),
                username: row.get("username"),
                email: row.get("email"),
                email_verified: row.get("email_verified"),
                first_name: row.get("first_name"),
                last_name: row.get("last_name"),
                phone_number: row.get("phone_number"),
                phone_verified: row.get("phone_verified"),
                password_hash: row.get("password_hash"),
                totp_secret: row.get("totp_secret"),
                totp_backup_codes: row.get("totp_backup_codes"),
                webauthn_enabled: row.get("webauthn_enabled"),
                account_locked: row.get("account_locked"),
                account_locked_until: row.get("account_locked_until"),
                failed_login_attempts: row.get("failed_login_attempts"),
                last_failed_login_at: row.get("last_failed_login_at"),
                password_changed_at: row.get("password_changed_at"),
                password_expires_at: row.get("password_expires_at"),
                require_password_change: row.get("require_password_change"),
                organization_id: row.get("organization_id"),
                attributes: row.get("attributes"),
                enabled: row.get("enabled"),
                realm_id: row.get("realm_id"),
                federated: row.get("federated"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                deleted_at: row.get("deleted_at"),
                last_login_at: row.get("last_login_at"),
                login_count: row.get("login_count"),
            reset_token_hash: None,
                reset_token_expires_at: None,
            verification_token_hash: row.try_get("verification_token_hash").ok().flatten(),
            verification_token_expires_at: row.try_get("verification_token_expires_at").ok().flatten(),
            });
        }

        Ok(users)
    }

    /// Bulk create users
    pub async fn bulk_create_users(
        db: &Database,
        users: Vec<CreateUserRequest>,
    ) -> Result<Vec<User>> {
        if users.is_empty() {
            return Ok(Vec::new());
        }

        let mut client = db.get_connection().await?;
        let transaction = client.transaction().await?;

        let mut created_users = Vec::new();

        for user_req in users {
            let query = r#"
                INSERT INTO users (
                    username, email, email_verified, first_name, last_name,
                    phone_number, phone_verified, password_hash, enabled,
                    realm_id, organization_id, attributes, federated
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                RETURNING
                    id, username, email, first_name, last_name,
                    phone_number, phone_verified, password_hash, totp_secret,
                    totp_backup_codes, webauthn_enabled, account_locked,
                    account_locked_until, failed_login_attempts, last_failed_login_at,
                    password_changed_at, password_expires_at, require_password_change,
                    organization_id, attributes, email_verified, enabled,
                    realm_id, federated, created_at, updated_at, deleted_at,
                    last_login_at, login_count
            "#;

            // Hash password if provided
            let password_hash = if let Some(password) = &user_req.password {
                authenc_crypto::utils::crypto::password::hash_password(password).await.map_err(|e| {
                    authenc_core::error::AuthencError::database(format!("Password hashing failed: {}", e))
                })?
            } else {
                String::new() // Empty password hash if not provided
            };

            let attributes_json =
                serde_json::to_string(&user_req.attributes.clone().unwrap_or_default())
                    .map_err(|e| authenc_core::error::AuthencError::database(e.to_string()))?;

            let row = transaction
                .query_one(
                    query,
                    &[
                        &user_req.username,
                        &user_req.email,
                        &false, // email_verified - default false
                        &user_req.first_name,
                        &user_req.last_name,
                        &user_req.phone_number,
                        &false, // phone_verified - default false
                        &password_hash,
                        &true, // enabled - default true
                        &user_req.realm_id,
                        &user_req.organization_id,
                        &attributes_json,
                        &false, // federated - default false
                    ],
                )
                .await?;

            created_users.push(row_to_user(&row));
        }

        transaction.commit().await?;
        Ok(created_users)
    }

    /// Bulk update users
    pub async fn bulk_update_users(
        db: &Database,
        updates: Vec<(Uuid, serde_json::Value)>,
    ) -> Result<usize> {
        if updates.is_empty() {
            return Ok(0);
        }

        let mut client = db.get_connection().await?;
        let transaction = client.transaction().await?;

        let mut updated_count = 0;
        let now = Utc::now();

        for (user_id, update_data) in updates {
            let mut set_clauses = Vec::new();
            let mut param_index = 2; // Start from 2 since $1 is user_id
            let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
                vec![Box::new(user_id)];

            // Build dynamic UPDATE query based on provided fields
            if let Some(email) = update_data.get("email").and_then(|v| v.as_str()) {
                set_clauses.push(format!("email = ${}", param_index));
                params.push(Box::new(email.to_string()));
                param_index += 1;
            }

            if let Some(first_name) = update_data.get("first_name").and_then(|v| v.as_str()) {
                set_clauses.push(format!("first_name = ${}", param_index));
                params.push(Box::new(first_name.to_string()));
                param_index += 1;
            }

            if let Some(last_name) = update_data.get("last_name").and_then(|v| v.as_str()) {
                set_clauses.push(format!("last_name = ${}", param_index));
                params.push(Box::new(last_name.to_string()));
                param_index += 1;
            }

            if let Some(enabled) = update_data.get("enabled").and_then(|v| v.as_bool()) {
                set_clauses.push(format!("enabled = ${}", param_index));
                params.push(Box::new(enabled));
                param_index += 1;
            }

            if let Some(email_verified) =
                update_data.get("email_verified").and_then(|v| v.as_bool())
            {
                set_clauses.push(format!("email_verified = ${}", param_index));
                params.push(Box::new(email_verified));
                param_index += 1;
            }

            if set_clauses.is_empty() {
                continue; // No fields to update
            }

            set_clauses.push(format!("updated_at = ${}", param_index));
            params.push(Box::new(now));

            let query = format!("UPDATE users SET {} WHERE id = $1", set_clauses.join(", "));

            let params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
                params.iter().map(|p| p.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync)).collect();

            let affected = transaction.execute(query.as_str(), &params_refs).await?;
            updated_count += affected as usize;
        }

        transaction.commit().await?;
        Ok(updated_count)
    }

    /// Bulk delete users (soft delete)
    pub async fn bulk_delete_users(db: &Database, user_ids: Vec<Uuid>) -> Result<usize> {
        if user_ids.is_empty() {
            return Ok(0);
        }

        let now = Utc::now();
        let query = r#"
            UPDATE users
            SET deleted_at = $1, updated_at = $1
            WHERE id = ANY($2) AND deleted_at IS NULL
        "#;

        let count = db.execute(query, &[&now, &user_ids]).await?;
        Ok(count as usize)
    }

    /// Bulk assign roles to users
    pub async fn bulk_assign_roles(
        db: &Database,
        assignments: Vec<(Uuid, Uuid)>, // (user_id, role_id) pairs
    ) -> Result<usize> {
        if assignments.is_empty() {
            return Ok(0);
        }

        let mut client = db.get_connection().await?;
        let transaction = client.transaction().await?;

        let query = r#"
            INSERT INTO user_roles (user_id, role_id)
            VALUES ($1, $2)
            ON CONFLICT (user_id, role_id) DO NOTHING
        "#;

        let mut assigned_count = 0;
        for (user_id, role_id) in assignments {
            let affected = transaction.execute(query, &[&user_id, &role_id]).await?;
            assigned_count += affected as usize;
        }

        transaction.commit().await?;
        Ok(assigned_count)
    }

    /// Bulk remove roles from users
    pub async fn bulk_remove_roles(
        db: &Database,
        removals: Vec<(Uuid, Uuid)>, // (user_id, role_id) pairs
    ) -> Result<usize> {
        if removals.is_empty() {
            return Ok(0);
        }

        let mut client = db.get_connection().await?;
        let transaction = client.transaction().await?;

        let query = "DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2";

        let mut removed_count = 0;
        for (user_id, role_id) in removals {
            let affected = transaction.execute(query, &[&user_id, &role_id]).await?;
            removed_count += affected as usize;
        }

        transaction.commit().await?;
        Ok(removed_count)
    }

    /// Export users to JSON (for backup/migration)
    pub async fn export_users(
        db: &Database,
        realm_id: Option<Uuid>,
    ) -> Result<Vec<serde_json::Value>> {
        let query = if realm_id.is_some() {
            r#"
                SELECT
                    id, username, email, first_name, last_name,
                    phone_number, phone_verified, email_verified,
                    enabled, realm_id, organization_id, attributes,
                    federated, created_at, updated_at
                FROM users
                WHERE realm_id = $1 AND deleted_at IS NULL
                ORDER BY created_at ASC
            "#
        } else {
            r#"
                SELECT
                    id, username, email, first_name, last_name,
                    phone_number, phone_verified, email_verified,
                    enabled, realm_id, organization_id, attributes,
                    federated, created_at, updated_at
                FROM users
                WHERE deleted_at IS NULL
                ORDER BY created_at ASC
            "#
        };

        let rows: Vec<tokio_postgres::Row> = if let Some(rid) = realm_id {
            db.query(query, &[&rid]).await?
        } else {
            db.query(query, &[]).await?
        };

        let mut users = Vec::new();
        for row in rows {
            users.push(serde_json::json!({
                "id": row.get::<_, Uuid>("id"),
                "username": row.get::<_, String>("username"),
                "email": row.get::<_, String>("email"),
                "first_name": row.get::<_, Option<String>>("first_name"),
                "last_name": row.get::<_, Option<String>>("last_name"),
                "phone_number": row.get::<_, Option<String>>("phone_number"),
                "phone_verified": row.get::<_, bool>("phone_verified"),
                "email_verified": row.get::<_, bool>("email_verified"),
                "enabled": row.get::<_, bool>("enabled"),
                "realm_id": row.get::<_, Uuid>("realm_id"),
                "organization_id": row.get::<_, Option<Uuid>>("organization_id"),
                "attributes": row.get::<_, Option<String>>("attributes"),
                "federated": row.get::<_, bool>("federated"),
                "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at"),
                "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>("updated_at"),
            }));
        }

        Ok(users)
    }

    /// Advanced user query with filtering, sorting, and pagination
    #[allow(clippy::too_many_arguments)]
    pub async fn query_users_advanced(
        db: &Database,
        realm_id: Option<Uuid>,
        search: Option<&str>,
        email_filter: Option<&str>,
        enabled_filter: Option<bool>,
        email_verified_filter: Option<bool>,
        organization_id_filter: Option<Uuid>,
        sort_by: Option<&str>, // "username", "email", "created_at", "last_login_at"
        sort_order: Option<&str>, // "asc" or "desc"
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> Result<(Vec<serde_json::Value>, i64)> {
        let mut where_clauses: Vec<String> = vec!["deleted_at IS NULL".to_string()];
        let mut param_index = 1;
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();

        // Realm filter
        if let Some(rid) = realm_id {
            where_clauses.push(format!("realm_id = ${}", param_index));
            params.push(Box::new(rid));
            param_index += 1;
        }

        // Full-text search across username, email, first_name, last_name
        if let Some(search_term) = search
            && !search_term.is_empty() {
                where_clauses.push(format!(
                    "(username ILIKE ${} OR email ILIKE ${} OR first_name ILIKE ${} OR last_name ILIKE ${})",
                    param_index, param_index, param_index, param_index
                ));
                let search_pattern = format!("%{}%", search_term);
                params.push(Box::new(search_pattern));
                param_index += 1;
            }

        // Email filter
        if let Some(email_pattern) = email_filter
            && !email_pattern.is_empty() {
                where_clauses.push(format!("email ILIKE ${}", param_index));
                params.push(Box::new(format!("%{}%", email_pattern)));
                param_index += 1;
            }

        // Enabled filter
        if let Some(enabled) = enabled_filter {
            where_clauses.push(format!("enabled = ${}", param_index));
            params.push(Box::new(enabled));
            param_index += 1;
        }

        // Email verified filter
        if let Some(verified) = email_verified_filter {
            where_clauses.push(format!("email_verified = ${}", param_index));
            params.push(Box::new(verified));
            param_index += 1;
        }

        // Organization filter
        if let Some(org_id) = organization_id_filter {
            where_clauses.push(format!("organization_id = ${}", param_index));
            params.push(Box::new(org_id));
            param_index += 1;
        }

        let where_clause = where_clauses.join(" AND ");

        // Sorting
        let sort_column = match sort_by {
            Some("email") => "email",
            Some("created_at") => "created_at",
            Some("last_login_at") => "last_login_at",
            Some("updated_at") => "updated_at",
            _ => "username",
        };

        let sort_direction = match sort_order {
            Some("desc") => "DESC",
            _ => "ASC",
        };

        // Count query
        let count_query = format!("SELECT COUNT(*) FROM users WHERE {}", where_clause);

        let params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync)).collect();

        let count_row: tokio_postgres::Row = db.query_one(&count_query, &params_refs).await?;
        let total_count: i64 = count_row.get(0);

        // Data query with pagination
        let data_query = format!(
            r#"
                SELECT
                    id, username, email, first_name, last_name,
                    phone_number, phone_verified, email_verified,
                    enabled, realm_id, organization_id, attributes,
                    federated, created_at, updated_at, last_login_at, login_count
                FROM users
                WHERE {}
                ORDER BY {} {}
                LIMIT ${} OFFSET ${}
            "#,
            where_clause,
            sort_column,
            sort_direction,
            param_index,
            param_index + 1
        );

        let limit_val = limit.unwrap_or(20);
        let offset_val = offset.unwrap_or(0);

        let mut data_params = params;
        data_params.push(Box::new(limit_val));
        data_params.push(Box::new(offset_val));

        let data_params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            data_params.iter().map(|p| p.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync)).collect();

        let rows: Vec<tokio_postgres::Row> = db.query(&data_query, &data_params_refs).await?;

        let mut users = Vec::new();
        for row in rows {
            users.push(serde_json::json!({
                "id": row.get::<_, Uuid>("id"),
                "username": row.get::<_, String>("username"),
                "email": row.get::<_, String>("email"),
                "first_name": row.get::<_, Option<String>>("first_name"),
                "last_name": row.get::<_, Option<String>>("last_name"),
                "phone_number": row.get::<_, Option<String>>("phone_number"),
                "phone_verified": row.get::<_, bool>("phone_verified"),
                "email_verified": row.get::<_, bool>("email_verified"),
                "enabled": row.get::<_, bool>("enabled"),
                "realm_id": row.get::<_, Uuid>("realm_id"),
                "organization_id": row.get::<_, Option<Uuid>>("organization_id"),
                "attributes": row.get::<_, Option<String>>("attributes"),
                "federated": row.get::<_, bool>("federated"),
                "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at"),
                "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>("updated_at"),
                "last_login_at": row.get::<_, Option<chrono::DateTime<chrono::Utc>>>("last_login_at"),
                "login_count": row.get::<_, i32>("login_count"),
            }));
        }

        Ok((users, total_count))
    }

    /// Full-text search users with ranking
    pub async fn search_users_fulltext(
        db: &Database,
        realm_id: Uuid,
        search_query: &str,
        limit: Option<i64>,
    ) -> Result<Vec<serde_json::Value>> {
        let query = r#"
            SELECT
                id, username, email, first_name, last_name,
                phone_number, phone_verified, email_verified,
                enabled, realm_id, organization_id, attributes,
                federated, created_at, updated_at, last_login_at, login_count,
                ts_rank(
                    to_tsvector('english', 
                        COALESCE(username, '') || ' ' || 
                        COALESCE(email, '') || ' ' || 
                        COALESCE(first_name, '') || ' ' || 
                        COALESCE(last_name, '')
                    ),
                    plainto_tsquery('english', $2)
                ) AS rank
            FROM users
            WHERE realm_id = $1 
                AND deleted_at IS NULL
                AND to_tsvector('english',
                    COALESCE(username, '') || ' ' || 
                    COALESCE(email, '') || ' ' || 
                    COALESCE(first_name, '') || ' ' || 
                    COALESCE(last_name, '')
                ) @@ plainto_tsquery('english', $2)
            ORDER BY rank DESC
            LIMIT $3
        "#;

        let limit_val = limit.unwrap_or(20);
        let rows: Vec<tokio_postgres::Row> = db
            .query(query, &[&realm_id, &search_query, &limit_val])
            .await?;

        let mut users = Vec::new();
        for row in rows {
            users.push(serde_json::json!({
                "id": row.get::<_, Uuid>("id"),
                "username": row.get::<_, String>("username"),
                "email": row.get::<_, String>("email"),
                "first_name": row.get::<_, Option<String>>("first_name"),
                "last_name": row.get::<_, Option<String>>("last_name"),
                "phone_number": row.get::<_, Option<String>>("phone_number"),
                "phone_verified": row.get::<_, bool>("phone_verified"),
                "email_verified": row.get::<_, bool>("email_verified"),
                "enabled": row.get::<_, bool>("enabled"),
                "realm_id": row.get::<_, Uuid>("realm_id"),
                "organization_id": row.get::<_, Option<Uuid>>("organization_id"),
                "federated": row.get::<_, bool>("federated"),
                "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at"),
                "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>("updated_at"),
                "last_login_at": row.get::<_, Option<chrono::DateTime<chrono::Utc>>>("last_login_at"),
                "login_count": row.get::<_, i32>("login_count"),
                "relevance_score": row.get::<_, f32>("rank"),
            }));
        }

        Ok(users)
    }

    /// Get users by attribute filter (JSONB query)
    pub async fn query_users_by_attributes(
        db: &Database,
        realm_id: Uuid,
        attribute_filters: serde_json::Value,
        limit: Option<i64>,
    ) -> Result<Vec<serde_json::Value>> {
        // Build JSONB containment query
        let query = r#"
            SELECT
                id, username, email, first_name, last_name,
                phone_number, phone_verified, email_verified,
                enabled, realm_id, organization_id, attributes,
                federated, created_at, updated_at
            FROM users
            WHERE realm_id = $1 
                AND deleted_at IS NULL
                AND attributes @> $2::jsonb
            ORDER BY created_at DESC
            LIMIT $3
        "#;

        let limit_val = limit.unwrap_or(100);
        let rows: Vec<tokio_postgres::Row> = db
            .query(
                query,
                &[&realm_id, &attribute_filters.to_string(), &limit_val],
            )
            .await?;

        let mut users = Vec::new();
        for row in rows {
            users.push(serde_json::json!({
                "id": row.get::<_, Uuid>("id"),
                "username": row.get::<_, String>("username"),
                "email": row.get::<_, String>("email"),
                "first_name": row.get::<_, Option<String>>("first_name"),
                "last_name": row.get::<_, Option<String>>("last_name"),
                "phone_number": row.get::<_, Option<String>>("phone_number"),
                "phone_verified": row.get::<_, bool>("phone_verified"),
                "email_verified": row.get::<_, bool>("email_verified"),
                "enabled": row.get::<_, bool>("enabled"),
                "realm_id": row.get::<_, Uuid>("realm_id"),
                "organization_id": row.get::<_, Option<Uuid>>("organization_id"),
                "attributes": row.get::<_, Option<String>>("attributes"),
                "federated": row.get::<_, bool>("federated"),
                "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at"),
                "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>("updated_at"),
            }));
        }

        Ok(users)
    }

    /// Get user statistics for a realm
    pub async fn get_user_statistics(db: &Database, realm_id: Uuid) -> Result<serde_json::Value> {
        let query = r#"
            SELECT
                COUNT(*) as total_users,
                COUNT(*) FILTER (WHERE enabled = true) as enabled_users,
                COUNT(*) FILTER (WHERE enabled = false) as disabled_users,
                COUNT(*) FILTER (WHERE email_verified = true) as verified_emails,
                COUNT(*) FILTER (WHERE email_verified = false) as unverified_emails,
                COUNT(*) FILTER (WHERE federated = true) as federated_users,
                COUNT(*) FILTER (WHERE last_login_at IS NOT NULL) as users_with_login,
                COUNT(*) FILTER (WHERE last_login_at > NOW() - INTERVAL '30 days') as active_last_30_days,
                COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days') as new_users_last_7_days
            FROM users
            WHERE realm_id = $1 AND deleted_at IS NULL
        "#;

        let row: tokio_postgres::Row = db.query_one(query, &[&realm_id]).await?;

        Ok(serde_json::json!({
            "total_users": row.get::<_, i64>("total_users"),
            "enabled_users": row.get::<_, i64>("enabled_users"),
            "disabled_users": row.get::<_, i64>("disabled_users"),
            "verified_emails": row.get::<_, i64>("verified_emails"),
            "unverified_emails": row.get::<_, i64>("unverified_emails"),
            "federated_users": row.get::<_, i64>("federated_users"),
            "users_with_login": row.get::<_, i64>("users_with_login"),
            "active_last_30_days": row.get::<_, i64>("active_last_30_days"),
            "new_users_last_7_days": row.get::<_, i64>("new_users_last_7_days"),
        }))
    }

    /// Import users from JSON (for backup/migration)
    pub async fn import_users(db: &Database, users_data: Vec<serde_json::Value>) -> Result<usize> {
        if users_data.is_empty() {
            return Ok(0);
        }

        let mut client = db.get_connection().await?;
        let transaction = client.transaction().await?;

        let query = r#"
            INSERT INTO users (
                username, email, first_name, last_name,
                phone_number, phone_verified, email_verified,
                enabled, realm_id, organization_id, attributes,
                federated
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (username, realm_id) DO UPDATE
            SET email = EXCLUDED.email,
                first_name = EXCLUDED.first_name,
                last_name = EXCLUDED.last_name,
                updated_at = NOW()
        "#;

        let mut imported_count = 0;
        for user_data in users_data {
            let affected = transaction
                .execute(
                    query,
                    &[
                        &user_data["username"].as_str().unwrap_or(""),
                        &user_data["email"].as_str().unwrap_or(""),
                        &user_data.get("first_name").and_then(|v| v.as_str()),
                        &user_data.get("last_name").and_then(|v| v.as_str()),
                        &user_data.get("phone_number").and_then(|v| v.as_str()),
                        &user_data["phone_verified"].as_bool().unwrap_or(false),
                        &user_data["email_verified"].as_bool().unwrap_or(false),
                        &user_data["enabled"].as_bool().unwrap_or(true),
                        &user_data["realm_id"]
                            .as_str()
                            .and_then(|s| Uuid::parse_str(s).ok())
                            .unwrap_or(Uuid::nil()),
                        &user_data
                            .get("organization_id")
                            .and_then(|v| v.as_str())
                            .and_then(|s| Uuid::parse_str(s).ok()),
                        &user_data.get("attributes").and_then(|v| v.as_str()),
                        &user_data["federated"].as_bool().unwrap_or(false),
                    ],
                )
                .await?;
            imported_count += affected as usize;
        }

        transaction.commit().await?;
        Ok(imported_count)
    }
}

/// Database operations for social accounts
pub mod social_accounts {
    use authenc_core::error::Result;

    use authenc_models::models::social_account::{CreateSocialAccountRequest, SocialAccount};

    use authenc_models::models::social_account::SocialProvider;

    use crate::database::Database;
    use chrono::Utc;
    use std::str::FromStr;
    use uuid::Uuid;

    /// Get social account by ID
    pub async fn get_social_account(
        db: &Database,
        account_id: Uuid,
    ) -> Result<Option<SocialAccount>> {
        let query = r#"
            SELECT id, user_id, provider, provider_user_id, display_name, email,
                   profile_picture_url, access_token, refresh_token, token_expires_at,
                   linked_at, updated_at
            FROM user_social_accounts
            WHERE id = $1 AND deleted_at IS NULL
        "#;

        let row = db.query_opt(query, &[&account_id]).await?;
        match row {
            Some(row) => {
                let provider_str: String = row.get(2);
                let provider =
                    SocialProvider::from_str(&provider_str).unwrap_or(SocialProvider::Google);

                Ok(Some(SocialAccount {
                    id: row.get(0),
                    user_id: row.get(1),
                    provider,
                    provider_user_id: row.get(3),
                    display_name: row.get(4),
                    email: row.get(5),
                    profile_picture_url: row.get(6),
                    access_token: row.get(7),
                    refresh_token: row.get(8),
                    token_expires_at: row.get(9),
                    linked_at: row.get(10),
                    updated_at: row.get(11),
                }))
            }
            None => Ok(None),
        }
    }

    /// Get user's social accounts
    pub async fn get_user_social_accounts(
        db: &Database,
        user_id: Uuid,
    ) -> Result<Vec<SocialAccount>> {
        let query = r#"
            SELECT id, user_id, provider, provider_user_id, display_name, email,
                   profile_picture_url, access_token, refresh_token, token_expires_at,
                   linked_at, updated_at
            FROM user_social_accounts
            WHERE user_id = $1 AND deleted_at IS NULL
            ORDER BY linked_at DESC
        "#;

        let rows = db.query(query, &[&user_id]).await?;
        let accounts = rows
            .into_iter()
            .map(|row: tokio_postgres::Row| {
                let provider_str: String = row.get(2);
                let provider =
                    SocialProvider::from_str(&provider_str).unwrap_or(SocialProvider::Google);

                SocialAccount {
                    id: row.get(0),
                    user_id: row.get(1),
                    provider,
                    provider_user_id: row.get(3),
                    display_name: row.get(4),
                    email: row.get(5),
                    profile_picture_url: row.get(6),
                    access_token: row.get(7),
                    refresh_token: row.get(8),
                    token_expires_at: row.get(9),
                    linked_at: row.get(10),
                    updated_at: row.get(11),
                }
            })
            .collect();

        Ok(accounts)
    }

    /// Get social account by provider and provider user ID
    pub async fn get_social_account_by_provider(
        db: &Database,
        provider: &SocialProvider,
        provider_user_id: &str,
    ) -> Result<Option<SocialAccount>> {
        let query = r#"
            SELECT id, user_id, provider, provider_user_id, display_name, email,
                   profile_picture_url, access_token, refresh_token, token_expires_at,
                   linked_at, updated_at
            FROM user_social_accounts
            WHERE provider = $1 AND provider_user_id = $2 AND deleted_at IS NULL
        "#;

        let row = db
            .query_opt(query, &[&provider.as_str(), &provider_user_id])
            .await?;
        match row {
            Some(row) => {
                let provider_str: String = row.get(2);
                let provider =
                    SocialProvider::from_str(&provider_str).unwrap_or(SocialProvider::Google);

                Ok(Some(SocialAccount {
                    id: row.get(0),
                    user_id: row.get(1),
                    provider,
                    provider_user_id: row.get(3),
                    display_name: row.get(4),
                    email: row.get(5),
                    profile_picture_url: row.get(6),
                    access_token: row.get(7),
                    refresh_token: row.get(8),
                    token_expires_at: row.get(9),
                    linked_at: row.get(10),
                    updated_at: row.get(11),
                }))
            }
            None => Ok(None),
        }
    }

    /// Check if user has social account for provider
    pub async fn has_social_account(
        db: &Database,
        user_id: Uuid,
        provider: &SocialProvider,
    ) -> Result<bool> {
        let query = r#"
            SELECT COUNT(*) FROM user_social_accounts
            WHERE user_id = $1 AND provider = $2 AND deleted_at IS NULL
        "#;

        let row: tokio_postgres::Row = db.query_one(query, &[&user_id, &provider.as_str()]).await?;
        let count: i64 = row.get(0);

        Ok(count > 0)
    }

    /// Add social account
    pub async fn add_social_account(
        db: &Database,
        user_id: Uuid,
        request: CreateSocialAccountRequest,
    ) -> Result<SocialAccount> {
        let account_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO user_social_accounts (
                id, user_id, provider, provider_user_id, display_name, email,
                profile_picture_url, access_token, refresh_token, token_expires_at,
                linked_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id
        "#;

        db.execute(
            query,
            &[
                &account_id,
                &user_id,
                &request.provider.as_str(),
                &request.provider_user_id,
                &request.display_name,
                &request.email,
                &request.profile_picture_url,
                &request.access_token,
                &request.refresh_token,
                &request.token_expires_at,
                &now,
                &now,
            ],
        )
        .await?;

        Ok(SocialAccount {
            id: account_id,
            user_id,
            provider: request.provider,
            provider_user_id: request.provider_user_id,
            display_name: request.display_name,
            email: request.email,
            profile_picture_url: request.profile_picture_url,
            access_token: request.access_token,
            refresh_token: request.refresh_token,
            token_expires_at: request.token_expires_at,
            linked_at: now,
            updated_at: now,
        })
    }

    /// Update social account
    pub async fn update_social_account(
        db: &Database,
        account_id: Uuid,
        request: CreateSocialAccountRequest,
    ) -> Result<SocialAccount> {
        let now = Utc::now();

        let query = r#"
            UPDATE user_social_accounts SET
                provider = $2, provider_user_id = $3, display_name = $4, email = $5,
                profile_picture_url = $6, access_token = $7, refresh_token = $8,
                token_expires_at = $9, updated_at = $10
            WHERE id = $1
        "#;

        db.execute(
            query,
            &[
                &account_id,
                &request.provider.as_str(),
                &request.provider_user_id,
                &request.display_name,
                &request.email,
                &request.profile_picture_url,
                &request.access_token,
                &request.refresh_token,
                &request.token_expires_at,
                &now,
            ],
        )
        .await?;

        Ok(SocialAccount {
            id: account_id,
            user_id: Uuid::nil(), // This will be filled by the caller if needed
            provider: request.provider,
            provider_user_id: request.provider_user_id,
            display_name: request.display_name,
            email: request.email,
            profile_picture_url: request.profile_picture_url,
            access_token: request.access_token,
            refresh_token: request.refresh_token,
            token_expires_at: request.token_expires_at,
            linked_at: now,
            updated_at: now,
        })
    }

    /// Remove social account
    pub async fn remove_social_account(db: &Database, account_id: Uuid) -> Result<()> {
        let now = Utc::now();

        let query = "UPDATE user_social_accounts SET deleted_at = $2 WHERE id = $1";
        db.execute(query, &[&account_id, &now]).await?;

        Ok(())
    }

    /// Remove social account by provider
    pub async fn remove_social_account_by_provider(
        db: &Database,
        user_id: Uuid,
        provider: SocialProvider,
    ) -> Result<()> {
        let now = Utc::now();

        let query = r#"
            UPDATE user_social_accounts
            SET deleted_at = $3
            WHERE user_id = $1 AND provider = $2 AND deleted_at IS NULL
        "#;

        db.execute(query, &[&user_id, &provider.as_str(), &now])
            .await?;

        Ok(())
    }
}

/// OAuth2 Social Provider operations (for authentication via external providers)
pub mod oauth2_providers {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Create OAuth2 provider configuration
    pub async fn create_provider_config(
        db: &Database,
        realm_id: Uuid,
        provider_name: &str,
        alias: &str,
        display_name: Option<&str>,
        authorization_url: &str,
        token_url: &str,
        user_info_url: Option<&str>,
        client_id: &str,
        client_secret: &str,
        scopes: &str,
    ) -> Result<serde_json::Value> {
        let query = r#"
            INSERT INTO oauth2_provider_configs (
                realm_id, provider_name, alias, display_name,
                authorization_url, token_url, user_info_url,
                client_id, client_secret, scopes
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, realm_id, provider_name, alias, enabled, created_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &realm_id,
                    &provider_name,
                    &alias,
                    &display_name,
                    &authorization_url,
                    &token_url,
                    &user_info_url,
                    &client_id,
                    &client_secret,
                    &scopes,
                ],
            )
            .await?;

        Ok(serde_json::json!({
            "id": row.get::<_, Uuid>("id"),
            "realm_id": row.get::<_, Uuid>("realm_id"),
            "provider_name": row.get::<_, String>("provider_name"),
            "alias": row.get::<_, String>("alias"),
            "enabled": row.get::<_, bool>("enabled"),
            "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at")
        }))
    }

    /// Get OAuth2 provider config
    pub async fn get_provider_config(
        db: &Database,
        config_id: Uuid,
    ) -> Result<Option<serde_json::Value>> {
        let query = r#"
            SELECT id, realm_id, provider_name, alias, display_name,
                   authorization_url, token_url, user_info_url, jwks_url, issuer,
                   client_id, client_secret, scopes, response_type, response_mode,
                   pkce_enabled, pkce_method, trust_email, link_only, store_tokens,
                   enabled, created_at, updated_at
            FROM oauth2_provider_configs
            WHERE id = $1
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&config_id]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = &rows[0];
        Ok(Some(serde_json::json!({
            "id": row.get::<_, Uuid>("id"),
            "realm_id": row.get::<_, Uuid>("realm_id"),
            "provider_name": row.get::<_, String>("provider_name"),
            "alias": row.get::<_, String>("alias"),
            "display_name": row.get::<_, Option<String>>("display_name"),
            "authorization_url": row.get::<_, String>("authorization_url"),
            "token_url": row.get::<_, String>("token_url"),
            "user_info_url": row.get::<_, Option<String>>("user_info_url"),
            "jwks_url": row.get::<_, Option<String>>("jwks_url"),
            "issuer": row.get::<_, Option<String>>("issuer"),
            "client_id": row.get::<_, String>("client_id"),
            "client_secret": row.get::<_, String>("client_secret"),
            "scopes": row.get::<_, String>("scopes"),
            "response_type": row.get::<_, String>("response_type"),
            "response_mode": row.get::<_, String>("response_mode"),
            "pkce_enabled": row.get::<_, bool>("pkce_enabled"),
            "pkce_method": row.get::<_, String>("pkce_method"),
            "trust_email": row.get::<_, bool>("trust_email"),
            "link_only": row.get::<_, bool>("link_only"),
            "store_tokens": row.get::<_, bool>("store_tokens"),
            "enabled": row.get::<_, bool>("enabled"),
            "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at"),
            "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>("updated_at")
        })))
    }

    /// Get provider configs for realm
    pub async fn get_realm_provider_configs(
        db: &Database,
        realm_id: Uuid,
        enabled_only: bool,
    ) -> Result<Vec<serde_json::Value>> {
        let query = if enabled_only {
            r#"
                SELECT id, realm_id, provider_name, alias, display_name,
                       authorization_url, scopes, enabled
                FROM oauth2_provider_configs
                WHERE realm_id = $1 AND enabled = TRUE
                ORDER BY provider_name ASC
            "#
        } else {
            r#"
                SELECT id, realm_id, provider_name, alias, display_name,
                       authorization_url, scopes, enabled
                FROM oauth2_provider_configs
                WHERE realm_id = $1
                ORDER BY provider_name ASC
            "#
        };

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&realm_id]).await?;

        let mut configs = Vec::new();
        for row in rows {
            configs.push(serde_json::json!({
                "id": row.get::<_, Uuid>("id"),
                "realm_id": row.get::<_, Uuid>("realm_id"),
                "provider_name": row.get::<_, String>("provider_name"),
                "alias": row.get::<_, String>("alias"),
                "display_name": row.get::<_, Option<String>>("display_name"),
                "authorization_url": row.get::<_, String>("authorization_url"),
                "scopes": row.get::<_, String>("scopes"),
                "enabled": row.get::<_, bool>("enabled")
            }));
        }

        Ok(configs)
    }

    /// Create OAuth2 state
    pub async fn create_oauth2_state(
        db: &Database,
        state_token: &str,
        provider_config_id: Uuid,
        realm_id: Uuid,
        redirect_uri: &str,
        code_verifier: Option<&str>,
        code_challenge: Option<&str>,
        expires_in_seconds: i64,
    ) -> Result<Uuid> {
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(expires_in_seconds);

        let query = r#"
            INSERT INTO oauth2_states (
                state_token, provider_config_id, realm_id, redirect_uri,
                code_verifier, code_challenge, code_challenge_method, expires_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
        "#;

        let code_challenge_method = if code_challenge.is_some() {
            Some("S256")
        } else {
            None
        };

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &state_token,
                    &provider_config_id,
                    &realm_id,
                    &redirect_uri,
                    &code_verifier,
                    &code_challenge,
                    &code_challenge_method,
                    &expires_at,
                ],
            )
            .await?;

        Ok(row.get(0))
    }

    /// Get and validate OAuth2 state
    pub async fn validate_oauth2_state(
        db: &Database,
        state_token: &str,
    ) -> Result<Option<serde_json::Value>> {
        let query = r#"
            SELECT id, state_token, provider_config_id, realm_id, redirect_uri,
                   code_verifier, expires_at, used
            FROM oauth2_states
            WHERE state_token = $1 AND expires_at > NOW() AND used = FALSE
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&state_token]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = &rows[0];

        // Mark as used
        let update_query = r#"
            UPDATE oauth2_states
            SET used = TRUE, used_at = NOW()
            WHERE id = $1
        "#;

        db.execute(update_query, &[&row.get::<_, Uuid>("id")])
            .await?;

        Ok(Some(serde_json::json!({
            "id": row.get::<_, Uuid>("id"),
            "provider_config_id": row.get::<_, Uuid>("provider_config_id"),
            "realm_id": row.get::<_, Uuid>("realm_id"),
            "redirect_uri": row.get::<_, String>("redirect_uri"),
            "code_verifier": row.get::<_, Option<String>>("code_verifier"),
        })))
    }

    /// Record token exchange
    pub async fn record_token_exchange(
        db: &Database,
        provider_config_id: Uuid,
        user_id: Option<Uuid>,
        authorization_code: Option<&str>,
        access_token: Option<&str>,
        refresh_token: Option<&str>,
        expires_in: Option<i32>,
        scope: Option<&str>,
        provider_user_id: Option<&str>,
        provider_email: Option<&str>,
        user_info_raw: Option<serde_json::Value>,
        success: bool,
        error_message: Option<&str>,
    ) -> Result<()> {
        let access_token_hash = access_token.map(|t| {
            let mut hasher = Sha256::new();
            hasher.update(t.as_bytes());
            format!("{:x}", hasher.finalize())
        });

        let refresh_token_hash = refresh_token.map(|t| {
            let mut hasher = Sha256::new();
            hasher.update(t.as_bytes());
            format!("{:x}", hasher.finalize())
        });

        let query = r#"
            INSERT INTO oauth2_token_exchanges (
                provider_config_id, user_id, authorization_code,
                access_token_hash, refresh_token_hash, expires_in, scope,
                provider_user_id, provider_email, user_info_raw,
                success, error_message
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#;

        db.execute(
            query,
            &[
                &provider_config_id,
                &user_id,
                &authorization_code,
                &access_token_hash,
                &refresh_token_hash,
                &expires_in,
                &scope,
                &provider_user_id,
                &provider_email,
                &user_info_raw,
                &success,
                &error_message,
            ],
        )
        .await?;

        Ok(())
    }

    /// Cleanup expired OAuth2 states
    pub async fn cleanup_expired_states(db: &Database) -> Result<i64> {
        let query = "DELETE FROM oauth2_states WHERE expires_at < NOW()";
        let count = db.execute(query, &[]).await?;
        Ok(count as i64)
    }

    /// Get token exchange history for user
    pub async fn get_user_token_exchanges(
        db: &Database,
        user_id: Uuid,
        limit: Option<i64>,
    ) -> Result<Vec<serde_json::Value>> {
        let query = r#"
            SELECT ote.id, ote.provider_config_id, opc.provider_name,
                   ote.provider_user_id, ote.provider_email, ote.scope,
                   ote.success, ote.error_message, ote.created_at
            FROM oauth2_token_exchanges ote
            JOIN oauth2_provider_configs opc ON ote.provider_config_id = opc.id
            WHERE ote.user_id = $1
            ORDER BY ote.created_at DESC
            LIMIT $2
        "#;

        let limit_val = limit.unwrap_or(50);
        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&user_id, &limit_val]).await?;

        let mut exchanges = Vec::new();
        for row in rows {
            exchanges.push(serde_json::json!({
                "id": row.get::<_, Uuid>("id"),
                "provider_config_id": row.get::<_, Uuid>("provider_config_id"),
                "provider_name": row.get::<_, String>("provider_name"),
                "provider_user_id": row.get::<_, Option<String>>("provider_user_id"),
                "provider_email": row.get::<_, Option<String>>("provider_email"),
                "scope": row.get::<_, Option<String>>("scope"),
                "success": row.get::<_, bool>("success"),
                "error_message": row.get::<_, Option<String>>("error_message"),
                "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at")
            }));
        }

        Ok(exchanges)
    }
}

/// Database operations for realms
pub mod realms {
    use authenc_core::error::Result;

    use authenc_models::models::{Realm, realm::CreateRealmRequest, realm::UpdateRealmRequest};

    use crate::database::Database;
    use chrono::Utc;
    use uuid::Uuid;

    /// Create a new realm
    pub async fn create_realm(db: &Database, request: &CreateRealmRequest) -> Result<Realm> {
        let realm_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO realms (
                id, name, display_name, description, enabled, ssl_required,
                registration_allowed, registration_email_as_username, remember_me,
                verify_email, login_with_email_allowed, duplicate_emails_allowed,
                reset_password_allowed, edit_username_allowed, brute_force_protected,
                max_failure_wait_seconds, minimum_quick_login_wait_seconds,
                wait_increment_seconds, quick_login_check_milli_seconds,
                max_delta_time_seconds, failure_factor, default_signature_algorithm,
                revoke_refresh_token, refresh_token_max_reuse, access_token_lifespan,
                access_token_lifespan_for_implicit_flow, sso_session_idle_timeout,
                sso_session_max_lifespan, sso_session_idle_timeout_remember_me,
                sso_session_max_lifespan_remember_me, offline_session_idle_timeout,
                offline_session_max_lifespan, client_session_idle_timeout,
                client_session_max_lifespan, access_code_lifespan,
                access_code_lifespan_user_action, access_code_lifespan_login,
                action_token_generated_by_admin_lifespan,
                action_token_generated_by_user_lifespan, oauth2_device_code_lifespan,
                oauth2_device_polling_interval, attributes, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29)
            RETURNING *
        "#;

        let row = db
            .query_one(
                query,
                &[
                    &realm_id,
                    &request.name,
                    &request.display_name,
                    &request.description,
                    &request.enabled.unwrap_or(true),
                    &"external", // ssl_required
                    &false,      // registration_allowed
                    &false,      // registration_email_as_username
                    &true,       // remember_me
                    &false,      // verify_email
                    &true,       // login_with_email_allowed
                    &false,      // duplicate_emails_allowed
                    &true,       // reset_password_allowed
                    &false,      // edit_username_allowed
                    &true,       // brute_force_protected
                    &900i32,     // max_failure_wait_seconds
                    &60i32,      // minimum_quick_login_wait_seconds
                    &60i32,      // wait_increment_seconds
                    &1000i64,    // quick_login_check_milli_seconds
                    &43200i32,   // max_delta_time_seconds (12 hours)
                    &30i32,      // failure_factor
                    &"RS256",    // default_signature_algorithm
                    &false,      // revoke_refresh_token
                    &0i32,       // refresh_token_max_reuse
                    &300i32,     // access_token_lifespan (5 minutes)
                    &900i32,     // access_token_lifespan_for_implicit_flow (15 minutes)
                    &1800i32,    // sso_session_idle_timeout (30 minutes)
                    &36000i32,   // sso_session_max_lifespan (10 hours)
                    &0i32,       // sso_session_idle_timeout_remember_me
                    &0i32,       // sso_session_max_lifespan_remember_me
                    &2592000i32, // offline_session_idle_timeout (30 days)
                    &5184000i32, // offline_session_max_lifespan (60 days)
                    &0i32,       // client_session_idle_timeout
                    &0i32,       // client_session_max_lifespan
                    &60i32,      // access_code_lifespan (1 minute)
                    &300i32,     // access_code_lifespan_user_action (5 minutes)
                    &1800i32,    // access_code_lifespan_login (30 minutes)
                    &43200i32,   // action_token_generated_by_admin_lifespan (12 hours)
                    &300i32,     // action_token_generated_by_user_lifespan (5 minutes)
                    &600i32,     // oauth2_device_code_lifespan (10 minutes)
                    &5i32,       // oauth2_device_polling_interval
                    &request
                        .attributes
                        .as_ref()
                        .map(|v| serde_json::to_string(v).unwrap_or_default()),
                    &now,
                    &now,
                ],
            )
            .await?;

        Ok(row_to_realm(row))
    }

    /// Get realm by ID
    pub async fn get_realm_by_id(db: &Database, realm_id: Uuid) -> Result<Option<Realm>> {
        let query = r#"
            SELECT * FROM realms
            WHERE id = $1 AND deleted_at IS NULL
        "#;

        let row = db.query_one(query, &[&realm_id]).await?;
        Ok(Some(row_to_realm(row)))
    }

    /// Get realm by name
    pub async fn get_realm_by_name(db: &Database, name: &str) -> Result<Option<Realm>> {
        let query = r#"
            SELECT * FROM realms
            WHERE name = $1 AND deleted_at IS NULL
        "#;

        let row = db.query_one(query, &[&name]).await?;
        Ok(Some(row_to_realm(row)))
    }

    /// Update realm
    pub async fn update_realm(
        db: &Database,
        realm_id: Uuid,
        request: &UpdateRealmRequest,
    ) -> Result<Realm> {
        let now = Utc::now();

        let query = r#"
            UPDATE realms SET
                display_name = COALESCE($2, display_name),
                description = COALESCE($3, description),
                enabled = COALESCE($4, enabled),
                ssl_required = COALESCE($5, ssl_required),
                registration_allowed = COALESCE($6, registration_allowed),
                verify_email = COALESCE($7, verify_email),
                reset_password_allowed = COALESCE($8, reset_password_allowed),
                brute_force_protected = COALESCE($9, brute_force_protected),
                attributes = COALESCE($10, attributes),
                updated_at = $11
            WHERE id = $1 AND deleted_at IS NULL
            RETURNING *
        "#;

        let row = db
            .query_one(
                query,
                &[
                    &realm_id,
                    &request.display_name,
                    &request.description,
                    &request.enabled,
                    &request.ssl_required,
                    &request.registration_allowed,
                    &request.verify_email,
                    &request.reset_password_allowed,
                    &request.brute_force_protected,
                    &request
                        .attributes
                        .as_ref()
                        .map(|v| serde_json::to_string(v).unwrap_or_default()),
                    &now,
                ],
            )
            .await?;

        Ok(row_to_realm(row))
    }

    /// Delete realm (soft delete)
    pub async fn delete_realm(db: &Database, realm_id: Uuid) -> Result<()> {
        let now = Utc::now();
        let query = "UPDATE realms SET deleted_at = $2, updated_at = $2 WHERE id = $1";
        db.execute(query, &[&realm_id, &now]).await?;
        Ok(())
    }

    /// List all realms
    pub async fn list_realms(db: &Database) -> Result<Vec<Realm>> {
        let query = r#"
            SELECT * FROM realms
            WHERE deleted_at IS NULL
            ORDER BY name
        "#;

        let rows = db.query(query, &[]).await?;
        Ok(rows.into_iter().map(row_to_realm).collect())
    }

    /// Helper function to convert database row to Realm
    fn row_to_realm(row: tokio_postgres::Row) -> Realm {
        Realm {
            id: row.get(0),
            name: row.get(1),
            display_name: row.get(2),
            description: row.get(3),
            enabled: row.get(4),
            ssl_required: row.get(5),
            registration_allowed: row.get(6),
            registration_email_as_username: row.get(7),
            remember_me: row.get(8),
            verify_email: row.get(9),
            login_with_email_allowed: row.get(10),
            duplicate_emails_allowed: row.get(11),
            reset_password_allowed: row.get(12),
            edit_username_allowed: row.get(13),
            brute_force_protected: row.get(14),
            max_failure_wait_seconds: row.get(15),
            minimum_quick_login_wait_seconds: row.get(16),
            wait_increment_seconds: row.get(17),
            quick_login_check_milli_seconds: row.get(18),
            max_delta_time_seconds: row.get(19),
            failure_factor: row.get(20),
            default_signature_algorithm: row.get(21),
            revoke_refresh_token: row.get(22),
            refresh_token_max_reuse: row.get(23),
            access_token_lifespan: row.get(24),
            access_token_lifespan_for_implicit_flow: row.get(25),
            sso_session_idle_timeout: row.get(26),
            sso_session_max_lifespan: row.get(27),
            sso_session_idle_timeout_remember_me: row.get(28),
            sso_session_max_lifespan_remember_me: row.get(29),
            offline_session_idle_timeout: row.get(30),
            offline_session_max_lifespan: row.get(31),
            client_session_idle_timeout: row.get(32),
            client_session_max_lifespan: row.get(33),
            access_code_lifespan: row.get(34),
            access_code_lifespan_user_action: row.get(35),
            access_code_lifespan_login: row.get(36),
            action_token_generated_by_admin_lifespan: row.get(37),
            action_token_generated_by_user_lifespan: row.get(38),
            oauth2_device_code_lifespan: row.get(39),
            oauth2_device_polling_interval: row.get(40),
            attributes: row
                .get::<_, Option<String>>(41)
                .and_then(|s: String| serde_json::from_str(&s).ok()),
            created_at: row.get(42),
            updated_at: row.get(43),
            deleted_at: row.get(44),
        }
    }
}

/// Federated Identity Management operations (for identity brokering and linking)
pub mod federated_identity {
    use authenc_core::error::Result;

    use crate::database::Database;
    use chrono::{DateTime, Duration, Utc};
    use serde_json::Value as JsonValue;
    use uuid::Uuid;

    /// Link a user account to a federated identity provider
    pub async fn link_federated_identity(
        db: &Database,
        user_id: Uuid,
        realm_id: Uuid,
        identity_provider_alias: &str,
        federated_user_id: &str,
        federated_username: Option<&str>,
        token: Option<&str>,
        token_expires_at: Option<DateTime<Utc>>,
        refresh_token: Option<&str>,
        federated_attributes: Option<&JsonValue>,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO federated_identity_links (
                user_id, realm_id, identity_provider_alias, federated_user_id,
                federated_username, token, token_expires_at, refresh_token,
                federated_attributes, last_authenticated_at, authentication_count
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), 1)
            ON CONFLICT (user_id, identity_provider_alias)
            DO UPDATE SET
                federated_user_id = EXCLUDED.federated_user_id,
                federated_username = EXCLUDED.federated_username,
                token = EXCLUDED.token,
                token_expires_at = EXCLUDED.token_expires_at,
                refresh_token = EXCLUDED.refresh_token,
                federated_attributes = EXCLUDED.federated_attributes,
                last_authenticated_at = NOW(),
                authentication_count = federated_identity_links.authentication_count + 1,
                updated_at = NOW()
            RETURNING id
        "#;

        let rows = db
            .query_raw(
                query,
                &[
                    &user_id,
                    &realm_id,
                    &identity_provider_alias,
                    &federated_user_id,
                    &federated_username,
                    &token,
                    &token_expires_at,
                    &refresh_token,
                    &federated_attributes,
                ],
            )
            .await?;

        Ok(rows[0].get(0))
    }

    /// Unlink a federated identity from a user account
    pub async fn unlink_federated_identity(
        db: &Database,
        user_id: Uuid,
        identity_provider_alias: &str,
    ) -> Result<bool> {
        let query = r#"
            DELETE FROM federated_identity_links
            WHERE user_id = $1 AND identity_provider_alias = $2
        "#;

        let rows_affected = db
            .execute(query, &[&user_id, &identity_provider_alias])
            .await?;
        Ok(rows_affected > 0)
    }

    /// Get all federated identities for a user
    pub async fn get_user_federated_identities(
        db: &Database,
        user_id: Uuid,
    ) -> Result<Vec<JsonValue>> {
        let query = r#"
            SELECT 
                id, identity_provider_alias, federated_user_id, federated_username,
                federated_attributes, linked_at, last_authenticated_at,
                authentication_count, token_expires_at
            FROM federated_identity_links
            WHERE user_id = $1
            ORDER BY last_authenticated_at DESC
        "#;

        let rows = db.query_raw(query, &[&user_id]).await?;
        Ok(rows
            .into_iter()
            .map(|row: tokio_postgres::Row| {
                serde_json::json!({
                    "id": row.get::<_, Uuid>(0),
                    "identity_provider_alias": row.get::<_, String>(1),
                    "federated_user_id": row.get::<_, String>(2),
                    "federated_username": row.get::<_, Option<String>>(3),
                    "federated_attributes": row.get::<_, Option<JsonValue>>(4),
                    "linked_at": row.get::<_, DateTime<Utc>>(5),
                    "last_authenticated_at": row.get::<_, Option<DateTime<Utc>>>(6),
                    "authentication_count": row.get::<_, i32>(7),
                    "token_expires_at": row.get::<_, Option<DateTime<Utc>>>(8),
                })
            })
            .collect())
    }

    /// Find user by federated identity
    pub async fn find_user_by_federated_identity(
        db: &Database,
        identity_provider_alias: &str,
        federated_user_id: &str,
    ) -> Result<Option<Uuid>> {
        let query = r#"
            SELECT user_id FROM federated_identity_links
            WHERE identity_provider_alias = $1 AND federated_user_id = $2
        "#;

        match db
            .query_opt(query, &[&identity_provider_alias, &federated_user_id])
            .await?
        {
            Some(row) => Ok(Some(row.get(0))),
            None => Ok(None),
        }
    }

    /// Update federated identity tokens
    pub async fn update_federated_tokens(
        db: &Database,
        user_id: Uuid,
        identity_provider_alias: &str,
        token: &str,
        token_expires_at: Option<DateTime<Utc>>,
        refresh_token: Option<&str>,
    ) -> Result<bool> {
        let query = r#"
            UPDATE federated_identity_links
            SET token = $1, token_expires_at = $2, refresh_token = $3,
                last_authenticated_at = NOW(), authentication_count = authentication_count + 1,
                updated_at = NOW()
            WHERE user_id = $4 AND identity_provider_alias = $5
        "#;

        let rows_affected = db
            .execute(
                query,
                &[
                    &token,
                    &token_expires_at,
                    &refresh_token,
                    &user_id,
                    &identity_provider_alias,
                ],
            )
            .await?;

        Ok(rows_affected > 0)
    }

    /// Create identity provider mapper
    pub async fn create_identity_provider_mapper(
        db: &Database,
        realm_id: Uuid,
        name: &str,
        identity_provider_alias: &str,
        mapper_type: &str,
        config: &JsonValue,
        sync_mode: &str,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO identity_provider_mappers (
                realm_id, name, identity_provider_alias, mapper_type, config, sync_mode
            ) VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
        "#;

        let rows = db
            .query_raw(
                query,
                &[
                    &realm_id,
                    &name,
                    &identity_provider_alias,
                    &mapper_type,
                    &config,
                    &sync_mode,
                ],
            )
            .await?;

        Ok(rows[0].get(0))
    }

    /// Get identity provider mappers
    pub async fn get_identity_provider_mappers(
        db: &Database,
        realm_id: Uuid,
        identity_provider_alias: Option<&str>,
    ) -> Result<Vec<JsonValue>> {
        let query = if identity_provider_alias.is_some() {
            r#"
                SELECT id, name, identity_provider_alias, mapper_type, config, sync_mode, created_at
                FROM identity_provider_mappers
                WHERE realm_id = $1 AND identity_provider_alias = $2
                ORDER BY name
            "#
        } else {
            r#"
                SELECT id, name, identity_provider_alias, mapper_type, config, sync_mode, created_at
                FROM identity_provider_mappers
                WHERE realm_id = $1
                ORDER BY identity_provider_alias, name
            "#
        };

        let rows = if let Some(alias) = identity_provider_alias {
            db.query_raw(query, &[&realm_id, &alias]).await?
        } else {
            db.query_raw(query, &[&realm_id]).await?
        };

        Ok(rows
            .into_iter()
            .map(|row: tokio_postgres::Row| {
                serde_json::json!({
                    "id": row.get::<_, Uuid>(0),
                    "name": row.get::<_, String>(1),
                    "identity_provider_alias": row.get::<_, String>(2),
                    "mapper_type": row.get::<_, String>(3),
                    "config": row.get::<_, JsonValue>(4),
                    "sync_mode": row.get::<_, String>(5),
                    "created_at": row.get::<_, DateTime<Utc>>(6),
                })
            })
            .collect())
    }

    /// Create identity broker configuration
    pub async fn create_identity_broker_config(
        db: &Database,
        realm_id: Uuid,
        alias: &str,
        display_name: Option<&str>,
        provider_type: &str,
        first_broker_login_flow: Option<&str>,
        post_broker_login_flow: Option<&str>,
        trust_email: bool,
        store_token: bool,
        link_only: bool,
        config: &JsonValue,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO identity_broker_configs (
                realm_id, alias, display_name, provider_type,
                first_broker_login_flow, post_broker_login_flow,
                trust_email, store_token, link_only, config
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id
        "#;

        let rows = db
            .query_raw(
                query,
                &[
                    &realm_id,
                    &alias,
                    &display_name,
                    &provider_type,
                    &first_broker_login_flow,
                    &post_broker_login_flow,
                    &trust_email,
                    &store_token,
                    &link_only,
                    &config,
                ],
            )
            .await?;

        Ok(rows[0].get(0))
    }

    /// Get identity broker configuration
    pub async fn get_identity_broker_config(
        db: &Database,
        realm_id: Uuid,
        alias: &str,
    ) -> Result<Option<JsonValue>> {
        let query = r#"
            SELECT 
                id, alias, display_name, enabled, provider_type,
                first_broker_login_flow, post_broker_login_flow,
                trust_email, store_token, add_read_token_role_on_create,
                link_only, config, created_at, updated_at
            FROM identity_broker_configs
            WHERE realm_id = $1 AND alias = $2
        "#;

        match db.query_opt(query, &[&realm_id, &alias]).await? {
            Some(row) => Ok(Some(serde_json::json!({
                "id": row.get::<_, Uuid>(0),
                "alias": row.get::<_, String>(1),
                "display_name": row.get::<_, Option<String>>(2),
                "enabled": row.get::<_, bool>(3),
                "provider_type": row.get::<_, String>(4),
                "first_broker_login_flow": row.get::<_, Option<String>>(5),
                "post_broker_login_flow": row.get::<_, Option<String>>(6),
                "trust_email": row.get::<_, bool>(7),
                "store_token": row.get::<_, bool>(8),
                "add_read_token_role_on_create": row.get::<_, bool>(9),
                "link_only": row.get::<_, bool>(10),
                "config": row.get::<_, JsonValue>(11),
                "created_at": row.get::<_, DateTime<Utc>>(12),
                "updated_at": row.get::<_, DateTime<Utc>>(13),
            }))),
            None => Ok(None),
        }
    }

    /// Get all identity broker configs for realm
    pub async fn get_realm_identity_broker_configs(
        db: &Database,
        realm_id: Uuid,
        enabled_only: bool,
    ) -> Result<Vec<JsonValue>> {
        let query = if enabled_only {
            r#"
                SELECT 
                    id, alias, display_name, enabled, provider_type,
                    trust_email, store_token, link_only, created_at
                FROM identity_broker_configs
                WHERE realm_id = $1 AND enabled = TRUE
                ORDER BY alias
            "#
        } else {
            r#"
                SELECT 
                    id, alias, display_name, enabled, provider_type,
                    trust_email, store_token, link_only, created_at
                FROM identity_broker_configs
                WHERE realm_id = $1
                ORDER BY alias
            "#
        };

        let rows = db.query_raw(query, &[&realm_id]).await?;

        Ok(rows
            .into_iter()
            .map(|row: tokio_postgres::Row| {
                serde_json::json!({
                    "id": row.get::<_, Uuid>(0),
                    "alias": row.get::<_, String>(1),
                    "display_name": row.get::<_, Option<String>>(2),
                    "enabled": row.get::<_, bool>(3),
                    "provider_type": row.get::<_, String>(4),
                    "trust_email": row.get::<_, bool>(5),
                    "store_token": row.get::<_, bool>(6),
                    "link_only": row.get::<_, bool>(7),
                    "created_at": row.get::<_, DateTime<Utc>>(8),
                })
            })
            .collect())
    }

    /// Log federated authentication attempt
    pub async fn log_federated_authentication(
        db: &Database,
        user_id: Option<Uuid>,
        realm_id: Uuid,
        identity_provider_alias: &str,
        federated_user_id: Option<&str>,
        success: bool,
        error_code: Option<&str>,
        error_message: Option<&str>,
        action: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        session_id: Option<Uuid>,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO federated_auth_log (
                user_id, realm_id, identity_provider_alias, federated_user_id,
                success, error_code, error_message, action,
                ip_address, user_agent, session_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
        "#;

        let ip_parsed = ip_address.and_then(|ip| ip.parse::<std::net::IpAddr>().ok());

        let rows = db
            .query_raw(
                query,
                &[
                    &user_id,
                    &realm_id,
                    &identity_provider_alias,
                    &federated_user_id,
                    &success,
                    &error_code,
                    &error_message,
                    &action,
                    &ip_parsed,
                    &user_agent,
                    &session_id,
                ],
            )
            .await?;

        Ok(rows[0].get(0))
    }

    /// Create account linking request (requires user confirmation)
    pub async fn create_account_linking_request(
        db: &Database,
        user_id: Uuid,
        realm_id: Uuid,
        identity_provider_alias: &str,
        federated_user_id: &str,
        federated_username: Option<&str>,
        federated_email: Option<&str>,
        federated_attributes: Option<&JsonValue>,
        confirmation_token: &str,
        expires_in_seconds: i64,
    ) -> Result<Uuid> {
        let expires_at = Utc::now() + Duration::seconds(expires_in_seconds);

        let query = r#"
            INSERT INTO account_linking_requests (
                user_id, realm_id, identity_provider_alias, federated_user_id,
                federated_username, federated_email, federated_attributes,
                confirmation_token, expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
        "#;

        let rows = db
            .query_raw(
                query,
                &[
                    &user_id,
                    &realm_id,
                    &identity_provider_alias,
                    &federated_user_id,
                    &federated_username,
                    &federated_email,
                    &federated_attributes,
                    &confirmation_token,
                    &expires_at,
                ],
            )
            .await?;

        Ok(rows[0].get(0))
    }

    /// Confirm account linking request
    pub async fn confirm_account_linking_request(
        db: &Database,
        confirmation_token: &str,
        resolved_by: &str,
    ) -> Result<Option<(Uuid, Uuid, String, String)>> {
        // First, get the request details
        let query = r#"
            SELECT id, user_id, realm_id, identity_provider_alias, federated_user_id, expires_at, status
            FROM account_linking_requests
            WHERE confirmation_token = $1
        "#;

        match db.query_opt(query, &[&confirmation_token]).await? {
            Some(row) => {
                let request_id: Uuid = row.get(0);
                let user_id: Uuid = row.get(1);
                let realm_id: Uuid = row.get(2);
                let identity_provider_alias: String = row.get(3);
                let federated_user_id: String = row.get(4);
                let expires_at: DateTime<Utc> = row.get(5);
                let status: String = row.get(6);

                // Check if expired or already resolved
                if status != "PENDING" {
                    return Ok(None);
                }

                if Utc::now() > expires_at {
                    // Update status to expired
                    let update_query = r#"
                        UPDATE account_linking_requests
                        SET status = 'EXPIRED', resolved_at = NOW(), resolved_by = $1
                        WHERE id = $2
                    "#;
                    db.execute(update_query, &[&"SYSTEM", &request_id]).await?;
                    return Ok(None);
                }

                // Update status to approved
                let update_query = r#"
                    UPDATE account_linking_requests
                    SET status = 'APPROVED', resolved_at = NOW(), resolved_by = $1
                    WHERE id = $2
                "#;
                db.execute(update_query, &[&resolved_by, &request_id])
                    .await?;

                Ok(Some((
                    user_id,
                    realm_id,
                    identity_provider_alias,
                    federated_user_id,
                )))
            }
            None => Ok(None),
        }
    }

    /// Reject account linking request
    pub async fn reject_account_linking_request(
        db: &Database,
        confirmation_token: &str,
        resolved_by: &str,
    ) -> Result<bool> {
        let query = r#"
            UPDATE account_linking_requests
            SET status = 'REJECTED', resolved_at = NOW(), resolved_by = $1
            WHERE confirmation_token = $2 AND status = 'PENDING'
        "#;

        let rows_affected = db
            .execute(query, &[&resolved_by, &confirmation_token])
            .await?;
        Ok(rows_affected > 0)
    }

    /// Cleanup expired account linking requests
    pub async fn cleanup_expired_linking_requests(db: &Database) -> Result<u64> {
        let query = r#"
            UPDATE account_linking_requests
            SET status = 'EXPIRED', resolved_at = NOW(), resolved_by = 'SYSTEM'
            WHERE status = 'PENDING' AND expires_at < NOW()
        "#;

        db.execute(query, &[]).await
    }
}

/// Admin Console Advanced Features operations (for admin dashboard, monitoring, audit logging)
pub mod admin_console {
    use authenc_core::error::Result;

    use crate::database::Database;
    use chrono::{DateTime, Duration, Utc};
    use serde_json::Value as JsonValue;
    use uuid::Uuid;

    /// Log an admin operation for audit trail
    #[allow(clippy::too_many_arguments)]
    pub async fn log_admin_operation(
        db: &Database,
        realm_id: Uuid,
        admin_user_id: Option<Uuid>,
        admin_username: &str,
        admin_ip_address: Option<&str>,
        operation_type: &str,
        resource_type: &str,
        resource_id: Option<&str>,
        resource_name: Option<&str>,
        action: &str,
        status: &str,
        error_message: Option<&str>,
        request_method: Option<&str>,
        request_path: Option<&str>,
        request_body: Option<&JsonValue>,
        response_status: Option<i32>,
        response_body: Option<&JsonValue>,
        duration_ms: Option<i32>,
        user_agent: Option<&str>,
        session_id: Option<Uuid>,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO admin_audit_log (
                realm_id, admin_user_id, admin_username, admin_ip_address,
                operation_type, resource_type, resource_id, resource_name,
                action, status, error_message, request_method, request_path,
                request_body, response_status, response_body, duration_ms,
                user_agent, session_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
            RETURNING id
        "#;

        let ip_parsed = admin_ip_address.and_then(|ip| ip.parse::<std::net::IpAddr>().ok());

        let rows = db
            .query_raw(
                query,
                &[
                    &realm_id,
                    &admin_user_id,
                    &admin_username,
                    &ip_parsed,
                    &operation_type,
                    &resource_type,
                    &resource_id,
                    &resource_name,
                    &action,
                    &status,
                    &error_message,
                    &request_method,
                    &request_path,
                    &request_body,
                    &response_status,
                    &response_body,
                    &duration_ms,
                    &user_agent,
                    &session_id,
                ],
            )
            .await?;

        Ok(rows[0].get(0))
    }

    /// Query admin audit log with filtering
    pub async fn query_admin_audit_log(
        db: &Database,
        realm_id: Uuid,
        admin_user_id: Option<Uuid>,
        operation_type: Option<String>,
        resource_type: Option<String>,
        status: Option<String>,
        from_date: Option<DateTime<Utc>>,
        to_date: Option<DateTime<Utc>>,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<JsonValue>> {
        let mut where_clauses = vec![String::from("realm_id = $1")];
        let mut param_index = 2;

        if admin_user_id.is_some() {
            where_clauses.push(format!("admin_user_id = ${}", param_index));
            param_index += 1;
        }

        if operation_type.is_some() {
            where_clauses.push(format!("operation_type = ${}", param_index));
            param_index += 1;
        }

        if resource_type.is_some() {
            where_clauses.push(format!("resource_type = ${}", param_index));
            param_index += 1;
        }

        if status.is_some() {
            where_clauses.push(format!("status = ${}", param_index));
            param_index += 1;
        }

        if from_date.is_some() {
            where_clauses.push(format!("created_at >= ${}", param_index));
            param_index += 1;
        }

        if to_date.is_some() {
            where_clauses.push(format!("created_at <= ${}", param_index));
            param_index += 1;
        }

        let where_clause = where_clauses.join(" AND ");

        let query = format!(
            r#"
            SELECT 
                id, admin_user_id, admin_username, admin_ip_address, operation_type,
                resource_type, resource_id, resource_name, action, status,
                error_message, duration_ms, created_at
            FROM admin_audit_log
            WHERE {}
            ORDER BY created_at DESC
            LIMIT ${} OFFSET ${}
        "#,
            where_clause,
            param_index,
            param_index + 1
        );

        let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = vec![&realm_id];

        if let Some(ref user_id) = admin_user_id {
            params.push(user_id);
        }
        if let Some(ref op_type) = operation_type {
            params.push(op_type);
        }
        if let Some(ref res_type) = resource_type {
            params.push(res_type);
        }
        if let Some(ref st) = status {
            params.push(st);
        }
        if let Some(ref from) = from_date {
            params.push(from);
        }
        if let Some(ref to) = to_date {
            params.push(to);
        }

        params.push(&limit);
        params.push(&offset);

        let rows = db.query_raw(&query, &params).await?;

        Ok(rows
            .into_iter()
            .map(|row: tokio_postgres::Row| {
                serde_json::json!({
                    "id": row.get::<_, Uuid>(0),
                    "admin_user_id": row.get::<_, Option<Uuid>>(1),
                    "admin_username": row.get::<_, String>(2),
                    "admin_ip_address": row.get::<_, Option<std::net::IpAddr>>(3),
                    "operation_type": row.get::<_, String>(4),
                    "resource_type": row.get::<_, String>(5),
                    "resource_id": row.get::<_, Option<String>>(6),
                    "resource_name": row.get::<_, Option<String>>(7),
                    "action": row.get::<_, String>(8),
                    "status": row.get::<_, String>(9),
                    "error_message": row.get::<_, Option<String>>(10),
                    "duration_ms": row.get::<_, Option<i32>>(11),
                    "created_at": row.get::<_, DateTime<Utc>>(12),
                })
            })
            .collect())
    }

    /// Record dashboard metric
    pub async fn record_dashboard_metric(
        db: &Database,
        realm_id: Uuid,
        metric_type: &str,
        metric_name: &str,
        metric_value: f64,
        metric_unit: Option<&str>,
        aggregation_period: &str,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
        metadata: Option<&JsonValue>,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO admin_dashboard_metrics (
                realm_id, metric_type, metric_name, metric_value, metric_unit,
                aggregation_period, period_start, period_end, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (realm_id, metric_type, metric_name, period_start)
            DO UPDATE SET
                metric_value = EXCLUDED.metric_value,
                metric_unit = EXCLUDED.metric_unit,
                period_end = EXCLUDED.period_end,
                metadata = EXCLUDED.metadata
            RETURNING id
        "#;

        let rows = db
            .query_raw(
                query,
                &[
                    &realm_id,
                    &metric_type,
                    &metric_name,
                    &metric_value,
                    &metric_unit,
                    &aggregation_period,
                    &period_start,
                    &period_end,
                    &metadata,
                ],
            )
            .await?;

        Ok(rows[0].get(0))
    }

    /// Get dashboard metrics
    pub async fn get_dashboard_metrics(
        db: &Database,
        realm_id: Uuid,
        metric_type: Option<&str>,
        aggregation_period: &str,
        from_date: DateTime<Utc>,
        to_date: DateTime<Utc>,
    ) -> Result<Vec<JsonValue>> {
        let query = if metric_type.is_some() {
            r#"
                SELECT 
                    id, metric_type, metric_name, metric_value, metric_unit,
                    aggregation_period, period_start, period_end, metadata, created_at
                FROM admin_dashboard_metrics
                WHERE realm_id = $1 AND metric_type = $2 AND aggregation_period = $3
                    AND period_start >= $4 AND period_end <= $5
                ORDER BY period_start
            "#
        } else {
            r#"
                SELECT 
                    id, metric_type, metric_name, metric_value, metric_unit,
                    aggregation_period, period_start, period_end, metadata, created_at
                FROM admin_dashboard_metrics
                WHERE realm_id = $1 AND aggregation_period = $2
                    AND period_start >= $3 AND period_end <= $4
                ORDER BY metric_type, period_start
            "#
        };

        let rows = if let Some(m_type) = metric_type {
            db.query_raw(
                query,
                &[
                    &realm_id,
                    &m_type,
                    &aggregation_period,
                    &from_date,
                    &to_date,
                ],
            )
            .await?
        } else {
            db.query_raw(
                query,
                &[&realm_id, &aggregation_period, &from_date, &to_date],
            )
            .await?
        };

        Ok(rows
            .into_iter()
            .map(|row: tokio_postgres::Row| {
                serde_json::json!({
                    "id": row.get::<_, Uuid>(0),
                    "metric_type": row.get::<_, String>(1),
                    "metric_name": row.get::<_, String>(2),
                    "metric_value": row.get::<_, f64>(3),
                    "metric_unit": row.get::<_, Option<String>>(4),
                    "aggregation_period": row.get::<_, String>(5),
                    "period_start": row.get::<_, DateTime<Utc>>(6),
                    "period_end": row.get::<_, DateTime<Utc>>(7),
                    "metadata": row.get::<_, Option<JsonValue>>(8),
                    "created_at": row.get::<_, DateTime<Utc>>(9),
                })
            })
            .collect())
    }

    /// Create admin console session
    pub async fn create_admin_session(
        db: &Database,
        realm_id: Uuid,
        admin_user_id: Uuid,
        username: &str,
        session_token: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        login_method: &str,
        mfa_verified: bool,
        expires_in_seconds: i64,
    ) -> Result<Uuid> {
        let expires_at = Utc::now() + Duration::seconds(expires_in_seconds);

        let query = r#"
            INSERT INTO admin_console_sessions (
                realm_id, admin_user_id, username, session_token,
                ip_address, user_agent, login_method, mfa_verified, expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
        "#;

        let ip_parsed = ip_address.and_then(|ip| ip.parse::<std::net::IpAddr>().ok());

        let rows = db
            .query_raw(
                query,
                &[
                    &realm_id,
                    &admin_user_id,
                    &username,
                    &session_token,
                    &ip_parsed,
                    &user_agent,
                    &login_method,
                    &mfa_verified,
                    &expires_at,
                ],
            )
            .await?;

        Ok(rows[0].get(0))
    }

    /// Validate and update admin session
    pub async fn validate_admin_session(
        db: &Database,
        session_token: &str,
    ) -> Result<Option<JsonValue>> {
        let query = r#"
            UPDATE admin_console_sessions
            SET last_activity_at = NOW()
            WHERE session_token = $1 AND is_active = TRUE AND expires_at > NOW()
            RETURNING id, realm_id, admin_user_id, username, mfa_verified, expires_at
        "#;

        match db.query_opt(query, &[&session_token]).await? {
            Some(row) => Ok(Some(serde_json::json!({
                "id": row.get::<_, Uuid>(0),
                "realm_id": row.get::<_, Uuid>(1),
                "admin_user_id": row.get::<_, Uuid>(2),
                "username": row.get::<_, String>(3),
                "mfa_verified": row.get::<_, bool>(4),
                "expires_at": row.get::<_, DateTime<Utc>>(5),
            }))),
            None => Ok(None),
        }
    }

    /// Terminate admin session
    pub async fn terminate_admin_session(
        db: &Database,
        session_token: &str,
        logout_reason: &str,
    ) -> Result<bool> {
        let query = r#"
            UPDATE admin_console_sessions
            SET is_active = FALSE, terminated_at = NOW(), logout_reason = $1
            WHERE session_token = $2 AND is_active = TRUE
        "#;

        let rows_affected = db.execute(query, &[&logout_reason, &session_token]).await?;
        Ok(rows_affected > 0)
    }

    /// Create admin notification
    pub async fn create_admin_notification(
        db: &Database,
        realm_id: Uuid,
        notification_type: &str,
        title: &str,
        message: &str,
        target_admin_user_id: Option<Uuid>,
        target_role: Option<&str>,
        action_url: Option<&str>,
        action_label: Option<&str>,
        priority: i32,
        expires_in_seconds: Option<i64>,
        metadata: Option<&JsonValue>,
    ) -> Result<Uuid> {
        let expires_at = expires_in_seconds.map(|seconds| Utc::now() + Duration::seconds(seconds));

        let query = r#"
            INSERT INTO admin_notifications (
                realm_id, notification_type, title, message, target_admin_user_id,
                target_role, action_url, action_label, priority, expires_at, metadata
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
        "#;

        let rows = db
            .query_raw(
                query,
                &[
                    &realm_id,
                    &notification_type,
                    &title,
                    &message,
                    &target_admin_user_id,
                    &target_role,
                    &action_url,
                    &action_label,
                    &priority,
                    &expires_at,
                    &metadata,
                ],
            )
            .await?;

        Ok(rows[0].get(0))
    }

    /// Get admin notifications
    pub async fn get_admin_notifications(
        db: &Database,
        realm_id: Uuid,
        admin_user_id: Option<Uuid>,
        unread_only: bool,
    ) -> Result<Vec<JsonValue>> {
        let query = if unread_only {
            r#"
                SELECT 
                    id, notification_type, title, message, action_url, action_label,
                    priority, is_read, created_at
                FROM admin_notifications
                WHERE realm_id = $1 
                    AND (target_admin_user_id = $2 OR target_admin_user_id IS NULL)
                    AND is_read = FALSE
                    AND (expires_at IS NULL OR expires_at > NOW())
                ORDER BY priority ASC, created_at DESC
            "#
        } else {
            r#"
                SELECT 
                    id, notification_type, title, message, action_url, action_label,
                    priority, is_read, created_at
                FROM admin_notifications
                WHERE realm_id = $1 
                    AND (target_admin_user_id = $2 OR target_admin_user_id IS NULL)
                    AND (expires_at IS NULL OR expires_at > NOW())
                ORDER BY priority ASC, created_at DESC
            "#
        };

        let rows = db.query_raw(query, &[&realm_id, &admin_user_id]).await?;

        Ok(rows
            .into_iter()
            .map(|row: tokio_postgres::Row| {
                serde_json::json!({
                    "id": row.get::<_, Uuid>(0),
                    "notification_type": row.get::<_, String>(1),
                    "title": row.get::<_, String>(2),
                    "message": row.get::<_, String>(3),
                    "action_url": row.get::<_, Option<String>>(4),
                    "action_label": row.get::<_, Option<String>>(5),
                    "priority": row.get::<_, i32>(6),
                    "is_read": row.get::<_, bool>(7),
                    "created_at": row.get::<_, DateTime<Utc>>(8),
                })
            })
            .collect())
    }

    /// Mark notification as read
    pub async fn mark_notification_read(
        db: &Database,
        notification_id: Uuid,
        admin_user_id: Uuid,
    ) -> Result<bool> {
        let query = r#"
            UPDATE admin_notifications
            SET is_read = TRUE, read_at = NOW(), read_by_user_id = $1
            WHERE id = $2
        "#;

        let rows_affected = db
            .execute(query, &[&admin_user_id, &notification_id])
            .await?;
        Ok(rows_affected > 0)
    }

    /// Get or create admin console preferences
    pub async fn get_admin_preferences(
        db: &Database,
        admin_user_id: Uuid,
        realm_id: Uuid,
    ) -> Result<JsonValue> {
        let query = r#"
            SELECT 
                id, theme, language, timezone, items_per_page, compact_mode,
                sidebar_collapsed, email_notifications, desktop_notifications,
                notification_frequency, dashboard_layout, favorite_pages,
                developer_mode, show_advanced_options, preferences
            FROM admin_console_preferences
            WHERE admin_user_id = $1 AND realm_id = $2
        "#;

        match db.query_opt(query, &[&admin_user_id, &realm_id]).await? {
            Some(row) => Ok(serde_json::json!({
                "id": row.get::<_, Uuid>(0),
                "theme": row.get::<_, String>(1),
                "language": row.get::<_, String>(2),
                "timezone": row.get::<_, String>(3),
                "items_per_page": row.get::<_, i32>(4),
                "compact_mode": row.get::<_, bool>(5),
                "sidebar_collapsed": row.get::<_, bool>(6),
                "email_notifications": row.get::<_, bool>(7),
                "desktop_notifications": row.get::<_, bool>(8),
                "notification_frequency": row.get::<_, String>(9),
                "dashboard_layout": row.get::<_, Option<JsonValue>>(10),
                "favorite_pages": row.get::<_, Option<Vec<String>>>(11),
                "developer_mode": row.get::<_, bool>(12),
                "show_advanced_options": row.get::<_, bool>(13),
                "preferences": row.get::<_, Option<JsonValue>>(14),
            })),
            None => {
                // Create default preferences
                let insert_query = r#"
                    INSERT INTO admin_console_preferences (admin_user_id, realm_id)
                    VALUES ($1, $2)
                    RETURNING id
                "#;
                let rows = db
                    .query_raw(insert_query, &[&admin_user_id, &realm_id])
                    .await?;
                let id: Uuid = rows[0].get(0);

                Ok(serde_json::json!({
                    "id": id,
                    "theme": "light",
                    "language": "en",
                    "timezone": "UTC",
                    "items_per_page": 25,
                    "compact_mode": false,
                    "sidebar_collapsed": false,
                    "email_notifications": true,
                    "desktop_notifications": true,
                    "notification_frequency": "realtime",
                    "dashboard_layout": null,
                    "favorite_pages": null,
                    "developer_mode": false,
                    "show_advanced_options": false,
                    "preferences": null,
                }))
            }
        }
    }

    /// Update admin console preferences
    pub async fn update_admin_preferences(
        db: &Database,
        admin_user_id: Uuid,
        realm_id: Uuid,
        preferences: &JsonValue,
    ) -> Result<bool> {
        let query = r#"
            UPDATE admin_console_preferences
            SET 
                theme = COALESCE($3, theme),
                language = COALESCE($4, language),
                timezone = COALESCE($5, timezone),
                items_per_page = COALESCE($6, items_per_page),
                compact_mode = COALESCE($7, compact_mode),
                sidebar_collapsed = COALESCE($8, sidebar_collapsed),
                email_notifications = COALESCE($9, email_notifications),
                desktop_notifications = COALESCE($10, desktop_notifications),
                notification_frequency = COALESCE($11, notification_frequency),
                dashboard_layout = COALESCE($12, dashboard_layout),
                favorite_pages = COALESCE($13, favorite_pages),
                developer_mode = COALESCE($14, developer_mode),
                show_advanced_options = COALESCE($15, show_advanced_options),
                preferences = COALESCE($16, preferences),
                updated_at = NOW()
            WHERE admin_user_id = $1 AND realm_id = $2
        "#;

        let rows_affected = db
            .execute(
                query,
                &[
                    &admin_user_id,
                    &realm_id,
                    &preferences.get("theme").and_then(|v| v.as_str()),
                    &preferences.get("language").and_then(|v| v.as_str()),
                    &preferences.get("timezone").and_then(|v| v.as_str()),
                    &preferences
                        .get("items_per_page")
                        .and_then(|v| v.as_i64())
                        .map(|v| v as i32),
                    &preferences.get("compact_mode").and_then(|v| v.as_bool()),
                    &preferences
                        .get("sidebar_collapsed")
                        .and_then(|v| v.as_bool()),
                    &preferences
                        .get("email_notifications")
                        .and_then(|v| v.as_bool()),
                    &preferences
                        .get("desktop_notifications")
                        .and_then(|v| v.as_bool()),
                    &preferences
                        .get("notification_frequency")
                        .and_then(|v| v.as_str()),
                    &preferences.get("dashboard_layout"),
                    &preferences.get("favorite_pages").and_then(|v| {
                        v.as_array().map(|arr| {
                            arr.iter()
                                .filter_map(|s| s.as_str().map(|s| s.to_string()))
                                .collect::<Vec<String>>()
                        })
                    }),
                    &preferences.get("developer_mode").and_then(|v| v.as_bool()),
                    &preferences
                        .get("show_advanced_options")
                        .and_then(|v| v.as_bool()),
                    &preferences.get("preferences"),
                ],
            )
            .await?;

        Ok(rows_affected > 0)
    }
}

/// Event System operations (for event-driven architecture and audit logging)
pub mod events {
    use authenc_core::error::Result;

    use crate::database::Database;
    use chrono::{DateTime, Utc};
    use serde_json::Value as JsonValue;
    use uuid::Uuid;

    /// Register an event listener
    pub async fn register_event_listener(
        db: &Database,
        realm_id: Uuid,
        name: &str,
        listener_type: &str,
        enabled: bool,
        config: Option<&JsonValue>,
        event_types: Option<Vec<String>>,
        priority: i32,
        is_async: bool,
        retry_on_failure: bool,
        max_retries: i32,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO event_listeners (
                realm_id, name, listener_type, enabled, config,
                event_types, priority, is_async, retry_on_failure, max_retries
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id
        "#;

        let rows = db
            .query_raw(
                query,
                &[
                    &realm_id,
                    &name,
                    &listener_type,
                    &enabled,
                    &config,
                    &event_types,
                    &priority,
                    &is_async,
                    &retry_on_failure,
                    &max_retries,
                ],
            )
            .await?;

        Ok(rows[0].get(0))
    }

    /// Get enabled event listeners for a realm
    pub async fn get_enabled_listeners(db: &Database, realm_id: Uuid) -> Result<Vec<JsonValue>> {
        let query = r#"
            SELECT 
                id, name, listener_type, config, event_types, priority,
                is_async, retry_on_failure, max_retries
            FROM event_listeners
            WHERE realm_id = $1 AND enabled = TRUE
            ORDER BY priority ASC
        "#;

        let rows = db.query_raw(query, &[&realm_id]).await?;

        Ok(rows
            .into_iter()
            .map(|row: tokio_postgres::Row| {
                serde_json::json!({
                    "id": row.get::<_, Uuid>(0),
                    "name": row.get::<_, String>(1),
                    "listener_type": row.get::<_, String>(2),
                    "config": row.get::<_, Option<JsonValue>>(3),
                    "event_types": row.get::<_, Option<Vec<String>>>(4),
                    "priority": row.get::<_, i32>(5),
                    "is_async": row.get::<_, bool>(6),
                    "retry_on_failure": row.get::<_, bool>(7),
                    "max_retries": row.get::<_, i32>(8),
                })
            })
            .collect())
    }

    /// Log an event
    #[allow(clippy::too_many_arguments)]
    pub async fn log_event(
        db: &Database,
        realm_id: Uuid,
        event_type: &str,
        event_category: &str,
        resource_type: Option<&str>,
        resource_id: Option<&str>,
        resource_name: Option<&str>,
        user_id: Option<Uuid>,
        username: Option<&str>,
        event_data: Option<&JsonValue>,
        old_value: Option<&JsonValue>,
        new_value: Option<&JsonValue>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        session_id: Option<Uuid>,
        success: bool,
        error_message: Option<&str>,
        operation_id: Option<Uuid>,
        correlation_id: Option<Uuid>,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO event_log (
                realm_id, event_type, event_category, resource_type, resource_id,
                resource_name, user_id, username, event_data, old_value, new_value,
                ip_address, user_agent, session_id, success, error_message,
                operation_id, correlation_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
            RETURNING id
        "#;

        let ip_parsed = ip_address.and_then(|ip| ip.parse::<std::net::IpAddr>().ok());

        let rows = db
            .query_raw(
                query,
                &[
                    &realm_id,
                    &event_type,
                    &event_category,
                    &resource_type,
                    &resource_id,
                    &resource_name,
                    &user_id,
                    &username,
                    &event_data,
                    &old_value,
                    &new_value,
                    &ip_parsed,
                    &user_agent,
                    &session_id,
                    &success,
                    &error_message,
                    &operation_id,
                    &correlation_id,
                ],
            )
            .await?;

        Ok(rows[0].get(0))
    }

    /// Parameters for querying event log
    pub struct QueryEventLogParams {
        /// Realm ID
        pub realm_id: Uuid,
        /// Event category
        pub event_category: Option<String>,
        /// Event type
        pub event_type: Option<String>,
        /// Resource type
        pub resource_type: Option<String>,
        /// Resource ID
        pub resource_id: Option<String>,
        /// User ID
        pub user_id: Option<Uuid>,
        /// Start date
        pub from_date: Option<DateTime<Utc>>,
        /// End date
        pub to_date: Option<DateTime<Utc>>,
        /// Filter for successful events only
        pub success_only: Option<bool>,
        /// Offset for pagination
        pub offset: i64,
        /// Limit for pagination
        pub limit: i64,
    }

    /// Query event log with filtering
    pub async fn query_event_log(
        db: &Database,
        params: QueryEventLogParams,
    ) -> Result<Vec<JsonValue>> {
        let mut where_clauses = vec![String::from("realm_id = $1")];
        let mut param_index = 2;

        if params.event_category.is_some() {
            where_clauses.push(format!("event_category = ${}", param_index));
            param_index += 1;
        }

        if params.event_type.is_some() {
            where_clauses.push(format!("event_type = ${}", param_index));
            param_index += 1;
        }

        if params.resource_type.is_some() {
            where_clauses.push(format!("resource_type = ${}", param_index));
            param_index += 1;
        }

        if params.resource_id.is_some() {
            where_clauses.push(format!("resource_id = ${}", param_index));
            param_index += 1;
        }

        if params.user_id.is_some() {
            where_clauses.push(format!("user_id = ${}", param_index));
            param_index += 1;
        }

        if params.from_date.is_some() {
            where_clauses.push(format!("created_at >= ${}", param_index));
            param_index += 1;
        }

        if params.to_date.is_some() {
            where_clauses.push(format!("created_at <= ${}", param_index));
            param_index += 1;
        }

        if let Some(true) = params.success_only {
            where_clauses.push(String::from("success = TRUE"));
        }

        let where_clause = where_clauses.join(" AND ");

        let query = format!(
            r#"
            SELECT 
                id, event_type, event_category, resource_type, resource_id,
                resource_name, user_id, username, success, error_message,
                correlation_id, created_at
            FROM event_log
            WHERE {}
            ORDER BY created_at DESC
            LIMIT ${} OFFSET ${}
        "#,
            where_clause,
            param_index,
            param_index + 1
        );

        let mut sql_params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
            vec![Box::new(params.realm_id)];

        if let Some(cat) = params.event_category {
            sql_params.push(Box::new(cat));
        }
        if let Some(et) = params.event_type {
            sql_params.push(Box::new(et));
        }
        if let Some(rt) = params.resource_type {
            sql_params.push(Box::new(rt));
        }
        if let Some(rid) = params.resource_id {
            sql_params.push(Box::new(rid));
        }
        if let Some(uid) = params.user_id {
            sql_params.push(Box::new(uid));
        }
        if let Some(from) = params.from_date {
            sql_params.push(Box::new(from));
        }
        if let Some(to) = params.to_date {
            sql_params.push(Box::new(to));
        }

        sql_params.push(Box::new(params.limit));
        sql_params.push(Box::new(params.offset));

        let params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = sql_params
            .iter()
            .map(|p| p.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();

        let rows = db.query_raw(&query, &params_refs).await?;

        Ok(rows
            .into_iter()
            .map(|row: tokio_postgres::Row| {
                serde_json::json!({
                    "id": row.get::<_, Uuid>(0),
                    "event_type": row.get::<_, String>(1),
                    "event_category": row.get::<_, String>(2),
                    "resource_type": row.get::<_, Option<String>>(3),
                    "resource_id": row.get::<_, Option<String>>(4),
                    "resource_name": row.get::<_, Option<String>>(5),
                    "user_id": row.get::<_, Option<Uuid>>(6),
                    "username": row.get::<_, Option<String>>(7),
                    "success": row.get::<_, bool>(8),
                    "error_message": row.get::<_, Option<String>>(9),
                    "correlation_id": row.get::<_, Option<Uuid>>(10),
                    "created_at": row.get::<_, chrono::NaiveDateTime>(11).to_string(),
                })
            })
            .collect())
    }

    /// Record listener execution result
    pub async fn record_listener_execution(
        db: &Database,
        event_log_id: Uuid,
        listener_id: Uuid,
        success: bool,
        error_message: Option<&str>,
        duration_ms: i32,
        retry_count: i32,
        next_retry_at: Option<DateTime<Utc>>,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO event_listener_executions (
                event_log_id, listener_id, success, error_message,
                duration_ms, retry_count, next_retry_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id
        "#;

        let rows = db
            .query_raw(
                query,
                &[
                    &event_log_id,
                    &listener_id,
                    &success,
                    &error_message,
                    &duration_ms,
                    &retry_count,
                    &next_retry_at,
                ],
            )
            .await?;

        Ok(rows[0].get(0))
    }

    /// Register webhook listener
    pub async fn register_webhook(
        db: &Database,
        listener_id: Uuid,
        realm_id: Uuid,
        url: &str,
        http_method: &str,
        auth_type: Option<&str>,
        auth_credentials: Option<&JsonValue>,
        custom_headers: Option<&JsonValue>,
        payload_template: Option<&str>,
        secret_key: Option<&str>,
        verify_ssl: bool,
        timeout_seconds: i32,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO event_webhooks (
                listener_id, realm_id, url, http_method, auth_type,
                auth_credentials, custom_headers, payload_template,
                secret_key, verify_ssl, timeout_seconds
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
        "#;

        let rows = db
            .query_raw(
                query,
                &[
                    &listener_id,
                    &realm_id,
                    &url,
                    &http_method,
                    &auth_type,
                    &auth_credentials,
                    &custom_headers,
                    &payload_template,
                    &secret_key,
                    &verify_ssl,
                    &timeout_seconds,
                ],
            )
            .await?;

        Ok(rows[0].get(0))
    }

    /// Get event statistics
    pub async fn get_event_statistics(
        db: &Database,
        realm_id: Uuid,
        from_date: DateTime<Utc>,
        to_date: DateTime<Utc>,
    ) -> Result<JsonValue> {
        let query = r#"
            SELECT 
                COUNT(*) as total_events,
                COUNT(*) FILTER (WHERE success = TRUE) as successful_events,
                COUNT(*) FILTER (WHERE success = FALSE) as failed_events,
                COUNT(DISTINCT event_type) as unique_event_types,
                COUNT(DISTINCT user_id) as unique_users,
                COUNT(DISTINCT event_category) as unique_categories
            FROM event_log
            WHERE realm_id = $1 AND created_at >= $2 AND created_at <= $3
        "#;

        let from_naive = from_date.naive_utc();
        let to_naive = to_date.naive_utc();

        match db
            .query_opt(query, &[&realm_id, &from_naive, &to_naive])
            .await?
        {
            Some(row) => Ok(serde_json::json!({
                "total_events": row.get::<_, i64>(0),
                "successful_events": row.get::<_, i64>(1),
                "failed_events": row.get::<_, i64>(2),
                "unique_event_types": row.get::<_, i64>(3),
                "unique_users": row.get::<_, i64>(4),
                "unique_categories": row.get::<_, i64>(5),
            })),
            None => Ok(serde_json::json!({
                "total_events": 0,
                "successful_events": 0,
                "failed_events": 0,
                "unique_event_types": 0,
                "unique_users": 0,
                "unique_categories": 0,
            })),
        }
    }

    /// Get failed listener executions for retry
    pub async fn get_failed_executions_for_retry(
        db: &Database,
        max_retry_count: i32,
    ) -> Result<Vec<JsonValue>> {
        let query = r#"
            SELECT 
                ele.id, ele.event_log_id, ele.listener_id, ele.retry_count,
                el.realm_id, el.event_type, el.event_data
            FROM event_listener_executions ele
            JOIN event_log el ON ele.event_log_id = el.id
            JOIN event_listeners l ON ele.listener_id = l.id
            WHERE ele.success = FALSE 
                AND l.retry_on_failure = TRUE
                AND ele.retry_count < $1
                AND (ele.next_retry_at IS NULL OR ele.next_retry_at <= NOW())
            ORDER BY ele.next_retry_at NULLS FIRST
            LIMIT 100
        "#;

        let rows = db.query_raw(query, &[&max_retry_count]).await?;

        Ok(rows
            .into_iter()
            .map(|row: tokio_postgres::Row| {
                serde_json::json!({
                    "execution_id": row.get::<_, Uuid>(0),
                    "event_log_id": row.get::<_, Uuid>(1),
                    "listener_id": row.get::<_, Uuid>(2),
                    "retry_count": row.get::<_, i32>(3),
                    "realm_id": row.get::<_, Uuid>(4),
                    "event_type": row.get::<_, String>(5),
                    "event_data": row.get::<_, Option<JsonValue>>(6),
                })
            })
            .collect())
    }
}

/// Database operations for protocol mappers
pub mod protocol_mappers {
    use authenc_core::error::Result;

    use crate::database::Database;
    use chrono::Utc;
    use serde_json::Value as JsonValue;
    use uuid::Uuid;

    /// Create a protocol mapper
    pub async fn create_protocol_mapper(
        db: &Database,
        client_id: Option<Uuid>,
        realm_id: Uuid,
        name: String,
        protocol: String,
        mapper_type: String,
        config: JsonValue,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO protocol_mappers (id, client_id, realm_id, name, protocol, mapper_type, config, enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8, $9)
            RETURNING id
        "#;

        let mapper_id = Uuid::new_v4();
        let now = Utc::now().naive_utc();

        let rows = db
            .query_raw(
                query,
                &[
                    &mapper_id,
                    &client_id,
                    &realm_id,
                    &name,
                    &protocol,
                    &mapper_type,
                    &config,
                    &now,
                    &now,
                ],
            )
            .await?;

        Ok(rows[0].get::<_, Uuid>(0))
    }

    /// Get protocol mappers for a client
    pub async fn get_client_mappers(
        db: &Database,
        client_id: Uuid,
        protocol: Option<String>,
    ) -> Result<Vec<JsonValue>> {
        let mut query = String::from(
            r#"
            SELECT id, client_id, realm_id, name, protocol, mapper_type, config, enabled, created_at, updated_at
            FROM protocol_mappers
            WHERE client_id = $1 AND enabled = TRUE
        "#,
        );

        let param_idx = 2;
        let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = vec![&client_id];

        let protocol_owned;
        if let Some(ref p) = protocol {
            protocol_owned = p.clone();
            query.push_str(&format!(" AND protocol = ${}", param_idx));
            params.push(&protocol_owned);
            let _ = param_idx; // Consumed, future params would use next index
        }

        query.push_str(" ORDER BY name");

        let rows = db.query_raw(&query, &params).await?;

        Ok(rows
            .into_iter()
            .map(|row: tokio_postgres::Row| {
                serde_json::json!({
                    "id": row.get::<_, Uuid>(0),
                    "client_id": row.get::<_, Option<Uuid>>(1),
                    "realm_id": row.get::<_, Uuid>(2),
                    "name": row.get::<_, String>(3),
                    "protocol": row.get::<_, String>(4),
                    "mapper_type": row.get::<_, String>(5),
                    "config": row.get::<_, JsonValue>(6),
                    "enabled": row.get::<_, bool>(7),
                    "created_at": row.get::<_, chrono::DateTime<Utc>>(8).to_rfc3339(),
                    "updated_at": row.get::<_, chrono::DateTime<Utc>>(9).to_rfc3339(),
                })
            })
            .collect())
    }

    /// Get protocol mappers for a realm (not client-specific)
    pub async fn get_realm_mappers(
        db: &Database,
        realm_id: Uuid,
        protocol: Option<String>,
    ) -> Result<Vec<JsonValue>> {
        let mut query = String::from(
            r#"
            SELECT id, client_id, realm_id, name, protocol, mapper_type, config, enabled, created_at, updated_at
            FROM protocol_mappers
            WHERE realm_id = $1 AND client_id IS NULL AND enabled = TRUE
        "#,
        );

        let param_idx = 2;
        let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = vec![&realm_id];

        let protocol_owned;
        if let Some(ref p) = protocol {
            protocol_owned = p.clone();
            query.push_str(&format!(" AND protocol = ${}", param_idx));
            params.push(&protocol_owned);
            let _ = param_idx; // Consumed, future params would use next index
        }

        query.push_str(" ORDER BY name");

        let rows = db.query_raw(&query, &params).await?;

        Ok(rows
            .into_iter()
            .map(|row: tokio_postgres::Row| {
                serde_json::json!({
                    "id": row.get::<_, Uuid>(0),
                    "client_id": row.get::<_, Option<Uuid>>(1),
                    "realm_id": row.get::<_, Uuid>(2),
                    "name": row.get::<_, String>(3),
                    "protocol": row.get::<_, String>(4),
                    "mapper_type": row.get::<_, String>(5),
                    "config": row.get::<_, JsonValue>(6),
                    "enabled": row.get::<_, bool>(7),
                    "created_at": row.get::<_, chrono::DateTime<Utc>>(8).to_rfc3339(),
                    "updated_at": row.get::<_, chrono::DateTime<Utc>>(9).to_rfc3339(),
                })
            })
            .collect())
    }

    /// Update protocol mapper configuration
    pub async fn update_mapper_config(
        db: &Database,
        mapper_id: Uuid,
        config: JsonValue,
    ) -> Result<()> {
        let query = r#"
            UPDATE protocol_mappers
            SET config = $1, updated_at = $2
            WHERE id = $3
        "#;

        let now = Utc::now().naive_utc();
        db.execute(query, &[&config, &now, &mapper_id]).await?;

        Ok(())
    }

    /// Enable/disable protocol mapper
    pub async fn set_mapper_enabled(db: &Database, mapper_id: Uuid, enabled: bool) -> Result<()> {
        let query = r#"
            UPDATE protocol_mappers
            SET enabled = $1, updated_at = $2
            WHERE id = $3
        "#;

        let now = Utc::now().naive_utc();
        db.execute(query, &[&enabled, &now, &mapper_id]).await?;

        Ok(())
    }

    /// Delete protocol mapper
    pub async fn delete_mapper(db: &Database, mapper_id: Uuid) -> Result<()> {
        let query = r#"
            DELETE FROM protocol_mappers WHERE id = $1
        "#;

        db.execute(query, &[&mapper_id]).await?;

        Ok(())
    }

    /// Get mapper by ID
    pub async fn get_mapper_by_id(db: &Database, mapper_id: Uuid) -> Result<Option<JsonValue>> {
        let query = r#"
            SELECT id, client_id, realm_id, name, protocol, mapper_type, config, enabled, created_at, updated_at
            FROM protocol_mappers
            WHERE id = $1
        "#;

        let rows = db.query_raw(query, &[&mapper_id]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = &rows[0];
        Ok(Some(serde_json::json!({
            "id": row.get::<_, Uuid>(0),
            "client_id": row.get::<_, Option<Uuid>>(1),
            "realm_id": row.get::<_, Uuid>(2),
            "name": row.get::<_, String>(3),
            "protocol": row.get::<_, String>(4),
            "mapper_type": row.get::<_, String>(5),
            "config": row.get::<_, JsonValue>(6),
            "enabled": row.get::<_, bool>(7),
            "created_at": row.get::<_, chrono::DateTime<Utc>>(8).to_rfc3339(),
            "updated_at": row.get::<_, chrono::DateTime<Utc>>(9).to_rfc3339(),
        })))
    }

    /// Get mapper statistics for a realm
    pub async fn get_mapper_statistics(db: &Database, realm_id: Uuid) -> Result<JsonValue> {
        let query = r#"
            SELECT 
                COUNT(*) FILTER (WHERE enabled = TRUE) as total_enabled,
                COUNT(*) FILTER (WHERE enabled = FALSE) as total_disabled,
                COUNT(DISTINCT protocol) as unique_protocols,
                COUNT(DISTINCT mapper_type) as unique_types,
                COUNT(*) FILTER (WHERE client_id IS NULL) as realm_level_mappers,
                COUNT(*) FILTER (WHERE client_id IS NOT NULL) as client_level_mappers
            FROM protocol_mappers
            WHERE realm_id = $1
        "#;

        let rows = db.query_raw(query, &[&realm_id]).await?;

        if rows.is_empty() {
            return Ok(serde_json::json!({
                "total_mappers": 0,
                "total_enabled": 0,
                "total_disabled": 0,
                "unique_protocols": 0,
                "unique_types": 0,
                "realm_level_mappers": 0,
                "client_level_mappers": 0,
            }));
        }

        let row = &rows[0];
        Ok(serde_json::json!({
            "total_mappers": row.get::<_, i64>(0) + row.get::<_, i64>(1),
            "total_enabled": row.get::<_, i64>(0),
            "total_disabled": row.get::<_, i64>(1),
            "unique_protocols": row.get::<_, i64>(2),
            "unique_types": row.get::<_, i64>(3),
            "realm_level_mappers": row.get::<_, i64>(4),
            "client_level_mappers": row.get::<_, i64>(5),
        }))
    }
}

/// Database operations for custom authenticators
pub mod authenticators {
    use authenc_core::error::Result;

    use crate::database::Database;
    use chrono::Utc;
    use serde_json::Value as JsonValue;
    use uuid::Uuid;

    /// Register a new authenticator configuration
    pub async fn register_authenticator(
        db: &Database,
        realm_id: Uuid,
        name: String,
        alias: String,
        authenticator_type: String,
        config: JsonValue,
        priority: i32,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO authenticator_configs (id, realm_id, name, alias, authenticator_type, config, priority, enabled, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8, $9)
            RETURNING id
        "#;

        let authenticator_id = Uuid::new_v4();
        let now = Utc::now();

        let rows = db
            .query_raw(
                query,
                &[
                    &authenticator_id,
                    &realm_id,
                    &name,
                    &alias,
                    &authenticator_type,
                    &config,
                    &priority,
                    &now,
                    &now,
                ],
            )
            .await?;

        Ok(rows[0].get::<_, Uuid>(0))
    }

    /// Get authenticators for a realm
    pub async fn get_realm_authenticators(
        db: &Database,
        realm_id: Uuid,
        enabled_only: bool,
    ) -> Result<Vec<JsonValue>> {
        let mut query = String::from(
            r#"
            SELECT id, realm_id, name, alias, authenticator_type, config, priority, enabled, created_at, updated_at
            FROM authenticator_configs
            WHERE realm_id = $1
        "#,
        );

        if enabled_only {
            query.push_str(" AND enabled = TRUE");
        }

        query.push_str(" ORDER BY priority ASC");

        let rows = db.query_raw(&query, &[&realm_id]).await?;

        Ok(rows
            .into_iter()
            .map(|row: tokio_postgres::Row| {
                serde_json::json!({
                    "id": row.get::<_, Uuid>(0),
                    "realm_id": row.get::<_, Uuid>(1),
                    "name": row.get::<_, String>(2),
                    "alias": row.get::<_, String>(3),
                    "authenticator_type": row.get::<_, String>(4),
                    "config": row.get::<_, JsonValue>(5),
                    "priority": row.get::<_, i32>(6),
                    "enabled": row.get::<_, bool>(7),
                    "created_at": row.get::<_, chrono::DateTime<Utc>>(8).to_rfc3339(),
                    "updated_at": row.get::<_, chrono::DateTime<Utc>>(9).to_rfc3339(),
                })
            })
            .collect())
    }

    /// Create authenticator execution
    pub async fn create_execution(
        db: &Database,
        realm_id: Uuid,
        flow_id: Uuid,
        authenticator_id: Option<Uuid>,
        requirement: String,
        priority: i32,
        parent_flow_id: Option<Uuid>,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO authenticator_executions (id, realm_id, flow_id, authenticator_id, requirement, priority, parent_flow_id, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
        "#;

        let execution_id = Uuid::new_v4();
        let now = Utc::now();

        let rows = db
            .query_raw(
                query,
                &[
                    &execution_id,
                    &realm_id,
                    &flow_id,
                    &authenticator_id,
                    &requirement,
                    &priority,
                    &parent_flow_id,
                    &now,
                    &now,
                ],
            )
            .await?;

        Ok(rows[0].get::<_, Uuid>(0))
    }

    /// Get executions for a flow
    pub async fn get_flow_executions(db: &Database, flow_id: Uuid) -> Result<Vec<JsonValue>> {
        let query = r#"
            SELECT 
                e.id, e.realm_id, e.flow_id, e.authenticator_id, e.requirement, 
                e.priority, e.parent_flow_id, e.created_at, e.updated_at,
                a.name as authenticator_name, a.authenticator_type
            FROM authenticator_executions e
            LEFT JOIN authenticator_configs a ON e.authenticator_id = a.id
            WHERE e.flow_id = $1
            ORDER BY e.priority ASC
        "#;

        let rows = db.query_raw(query, &[&flow_id]).await?;

        Ok(rows
            .into_iter()
            .map(|row: tokio_postgres::Row| {
                serde_json::json!({
                    "id": row.get::<_, Uuid>(0),
                    "realm_id": row.get::<_, Uuid>(1),
                    "flow_id": row.get::<_, Uuid>(2),
                    "authenticator_id": row.get::<_, Option<Uuid>>(3),
                    "requirement": row.get::<_, String>(4),
                    "priority": row.get::<_, i32>(5),
                    "parent_flow_id": row.get::<_, Option<Uuid>>(6),
                    "created_at": row.get::<_, chrono::DateTime<Utc>>(7).to_rfc3339(),
                    "updated_at": row.get::<_, chrono::DateTime<Utc>>(8).to_rfc3339(),
                    "authenticator_name": row.get::<_, Option<String>>(9),
                    "authenticator_type": row.get::<_, Option<String>>(10),
                })
            })
            .collect())
    }

    /// Record execution result
    pub async fn record_execution_result(
        db: &Database,
        execution_id: Uuid,
        session_id: Option<Uuid>,
        user_id: Option<Uuid>,
        status: String,
        error_message: Option<String>,
        duration_ms: i32,
        attempt_count: i32,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO authenticator_execution_results (id, execution_id, session_id, user_id, status, error_message, duration_ms, attempt_count, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
        "#;

        let result_id = Uuid::new_v4();
        let now = Utc::now();

        let rows = db
            .query_raw(
                query,
                &[
                    &result_id,
                    &execution_id,
                    &session_id,
                    &user_id,
                    &status,
                    &error_message,
                    &duration_ms,
                    &attempt_count,
                    &now,
                ],
            )
            .await?;

        Ok(rows[0].get::<_, Uuid>(0))
    }

    /// Update authenticator configuration
    pub async fn update_authenticator_config(
        db: &Database,
        authenticator_id: Uuid,
        config: JsonValue,
    ) -> Result<()> {
        let query = r#"
            UPDATE authenticator_configs
            SET config = $1, updated_at = $2
            WHERE id = $3
        "#;

        let now = Utc::now();
        db.execute(query, &[&config, &now, &authenticator_id])
            .await?;

        Ok(())
    }

    /// Enable/disable authenticator
    pub async fn set_authenticator_enabled(
        db: &Database,
        authenticator_id: Uuid,
        enabled: bool,
    ) -> Result<()> {
        let query = r#"
            UPDATE authenticator_configs
            SET enabled = $1, updated_at = $2
            WHERE id = $3
        "#;

        let now = Utc::now();
        db.execute(query, &[&enabled, &now, &authenticator_id])
            .await?;

        Ok(())
    }

    /// Delete authenticator
    pub async fn delete_authenticator(db: &Database, authenticator_id: Uuid) -> Result<()> {
        let query = r#"
            DELETE FROM authenticator_configs WHERE id = $1
        "#;

        db.execute(query, &[&authenticator_id]).await?;

        Ok(())
    }

    /// Update execution requirement
    pub async fn update_execution_requirement(
        db: &Database,
        execution_id: Uuid,
        requirement: String,
    ) -> Result<()> {
        let query = r#"
            UPDATE authenticator_executions
            SET requirement = $1, updated_at = $2
            WHERE id = $3
        "#;

        let now = Utc::now();
        db.execute(query, &[&requirement, &now, &execution_id])
            .await?;

        Ok(())
    }

    /// Get execution statistics
    pub async fn get_execution_statistics(
        db: &Database,
        realm_id: Uuid,
        from_date: Option<chrono::DateTime<Utc>>,
        to_date: Option<chrono::DateTime<Utc>>,
    ) -> Result<JsonValue> {
        let mut query = String::from(
            r#"
            SELECT 
                COUNT(*) as total_attempts,
                COUNT(*) FILTER (WHERE status = 'SUCCESS') as successful_attempts,
                COUNT(*) FILTER (WHERE status = 'FAILED') as failed_attempts,
                COUNT(DISTINCT user_id) as unique_users,
                AVG(duration_ms) as avg_duration_ms
            FROM authenticator_execution_results r
            JOIN authenticator_executions e ON r.execution_id = e.id
            WHERE e.realm_id = $1
        "#,
        );

        let mut param_idx = 2;
        let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = vec![&realm_id];

        let from_owned;
        let to_owned;

        if let Some(ref from) = from_date {
            from_owned = *from;
            query.push_str(&format!(" AND r.created_at >= ${}", param_idx));
            params.push(&from_owned);
            param_idx += 1;
        }

        if let Some(ref to) = to_date {
            to_owned = *to;
            query.push_str(&format!(" AND r.created_at <= ${}", param_idx));
            params.push(&to_owned);
        }

        let rows = db.query_raw(&query, &params).await?;

        if rows.is_empty() {
            return Ok(serde_json::json!({
                "total_attempts": 0,
                "successful_attempts": 0,
                "failed_attempts": 0,
                "unique_users": 0,
                "avg_duration_ms": 0,
            }));
        }

        let row = &rows[0];
        Ok(serde_json::json!({
            "total_attempts": row.get::<_, i64>(0),
            "successful_attempts": row.get::<_, i64>(1),
            "failed_attempts": row.get::<_, i64>(2),
            "unique_users": row.get::<_, Option<i64>>(3).unwrap_or(0),
            "avg_duration_ms": row.get::<_, Option<f64>>(4).unwrap_or(0.0),
        }))
    }
}

/// Database operations for role management
pub mod roles {
    use authenc_core::error::Result;

    use authenc_models::models::Role;

    use crate::database::Database;
    use chrono::Utc;
    use uuid::Uuid;

    /// Create a new role
    pub async fn create_role(
        db: &Database,
        name: &str,
        description: Option<&str>,
        realm_id: &Uuid,
    ) -> Result<Role> {
        let client = db.get_connection().await?;
        let role_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO roles (id, name, description, realm_id, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING
                id, name, description, realm_id, composite, client_role,
                client_id, attributes, created_at, updated_at
        "#;

        let row = client
            .query_one(
                query,
                &[&role_id, &name, &description, &realm_id, &now, &now],
            )
            .await?;

        // Convert row to Role
        Ok(Role {
            id: row.get(0),
            name: row.get(1),
            description: row.get(2),
            realm_id: row.get(3),
            composite: row.get(4),
            client_role: row.get(5),
            client_id: row.get(6),
            attributes: row
                .get::<_, Option<String>>(7)
                .and_then(|s: String| serde_json::from_str(&s).ok()),
            created_at: row.get(8),
            updated_at: row.get(9),
            deleted_at: None, // Not selected in query
        })
    }

    /// Get role by ID
    pub async fn get_role_by_id(db: &Database, role_id: &Uuid) -> Result<Option<Role>> {
        let client = db.get_connection().await?;
        let query = r#"
            SELECT
                id, name, description, realm_id, composite, client_role,
                client_id, attributes, created_at, updated_at
            FROM roles
            WHERE id = $1 AND deleted_at IS NULL
        "#;

        let row = client.query_opt(query, &[&role_id]).await?;
        Ok(row.map(|r| Role {
            id: r.get(0),
            name: r.get(1),
            description: r.get(2),
            realm_id: r.get(3),
            composite: r.get(4),
            client_role: r.get(5),
            client_id: r.get(6),
            attributes: r
                .get::<_, Option<String>>(7)
                .and_then(|s: String| serde_json::from_str(&s).ok()),
            created_at: r.get(8),
            updated_at: r.get(9),
            deleted_at: None, // Not selected in query
        }))
    }

    /// List roles by realm
    pub async fn list_roles_by_realm(db: &Database, realm_id: &Uuid) -> Result<Vec<Role>> {
        let client = db.get_connection().await?;
        let query = r#"
            SELECT
                id, name, description, realm_id, composite, client_role,
                client_id, attributes, created_at, updated_at
            FROM roles
            WHERE realm_id = $1 AND deleted_at IS NULL
            ORDER BY created_at DESC
        "#;

        let rows = client.query(query, &[&realm_id]).await?;
        let mut roles = Vec::new();

        for row in rows {
            roles.push(Role {
                id: row.get(0),
                name: row.get(1),
                description: row.get(2),
                realm_id: row.get(3),
                composite: row.get(4),
                client_role: row.get(5),
                client_id: row.get(6),
                attributes: row
                    .get::<_, Option<String>>(7)
                    .and_then(|s: String| serde_json::from_str(&s).ok()),
                created_at: row.get(8),
                updated_at: row.get(9),
                deleted_at: None, // Not selected in query
            });
        }

        Ok(roles)
    }

    /// Assign role to user
    pub async fn assign_role_to_user(db: &Database, user_id: &Uuid, role_id: &Uuid) -> Result<()> {
        let client = db.get_connection().await?;
        let now = Utc::now();

        let query = r#"
            INSERT INTO user_roles (user_id, role_id, assigned_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (user_id, role_id) DO NOTHING
        "#;

        client.execute(query, &[&user_id, &role_id, &now]).await?;
        Ok(())
    }

    /// Remove role from user
    pub async fn remove_role_from_user(
        db: &Database,
        user_id: &Uuid,
        role_id: &Uuid,
    ) -> Result<()> {
        let client = db.get_connection().await?;
        let query = r#"
            DELETE FROM user_roles
            WHERE user_id = $1 AND role_id = $2
        "#;

        client.execute(query, &[&user_id, &role_id]).await?;
        Ok(())
    }
    pub async fn get_user_roles(db: &Database, user_id: &Uuid) -> Result<Vec<Role>> {
        let client = db.get_connection().await?;
        let query = r#"
            SELECT r.id, r.name, r.description, r.realm_id, r.composite, r.client_role,
                   r.client_id, r.attributes, r.created_at, r.updated_at
            FROM roles r
            JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = $1 AND r.deleted_at IS NULL
        "#;

        let rows = client.query(query, &[&user_id]).await?;
        let mut roles = Vec::new();

        for row in rows {
            roles.push(Role {
                id: row.get(0),
                name: row.get(1),
                description: row.get(2),
                realm_id: row.get(3),
                composite: row.get(4),
                client_role: row.get(5),
                client_id: row.get(6),
                attributes: row
                    .get::<_, Option<String>>(7)
                    .and_then(|s: String| serde_json::from_str(&s).ok()),
                created_at: row.get(8),
                updated_at: row.get(9),
                deleted_at: None, // Not selected in query
            });
        }

        Ok(roles)
    }

    /// Check if user has a specific permission
    pub async fn user_has_permission(
        db: &Database,
        user_id: &Uuid,
        permission: &str,
    ) -> Result<bool> {
        let client = db.get_connection().await?;
        let query = r#"
            SELECT COUNT(*) > 0
            FROM user_roles ur
            JOIN role_permissions rp ON ur.role_id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.id
            WHERE ur.user_id = $1 AND p.name = $2 AND p.deleted_at IS NULL
        "#;

        let row = client.query_one(query, &[&user_id, &permission]).await?;
        let has_permission: bool = row.get(0);

        Ok(has_permission)
    }

    /// Get all permissions for a user
    pub async fn get_user_permissions(db: &Database, user_id: &Uuid) -> Result<Vec<String>> {
        let client = db.get_connection().await?;
        let query = r#"
            SELECT DISTINCT p.name
            FROM user_roles ur
            JOIN role_permissions rp ON ur.role_id = rp.role_id
            JOIN permissions p ON rp.permission_id = p.id
            WHERE ur.user_id = $1 AND p.deleted_at IS NULL
            ORDER BY p.name
        "#;

        let rows = client.query(query, &[&user_id]).await?;
        let permissions = rows
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect();

        Ok(permissions)
    }

    /// Assign permission to role
    pub async fn assign_permission_to_role(
        db: &Database,
        role_id: &Uuid,
        permission_id: &Uuid,
    ) -> Result<()> {
        let client = db.get_connection().await?;
        let now = Utc::now();

        let query = r#"
            INSERT INTO role_permissions (role_id, permission_id, assigned_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (role_id, permission_id) DO NOTHING
        "#;

        client
            .execute(query, &[&role_id, &permission_id, &now])
            .await?;

        Ok(())
    }

    /// Remove permission from role
    pub async fn remove_permission_from_role(
        db: &Database,
        role_id: &Uuid,
        permission_id: &Uuid,
    ) -> Result<()> {
        let client = db.get_connection().await?;

        let query = r#"
            DELETE FROM role_permissions
            WHERE role_id = $1 AND permission_id = $2
        "#;

        client.execute(query, &[&role_id, &permission_id]).await?;

        Ok(())
    }
}

pub mod webauthn {
    use authenc_core::error::Result;

    use authenc_models::models::WebauthnCredential;

    use crate::database::Database;
    use chrono::Utc;
    use uuid::Uuid;

    /// Store WebAuthn credential
    pub async fn store_credential(
        db: &Database,
        user_id: Uuid,
        credential: &WebauthnCredential,
    ) -> Result<()> {
        let credential_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO webauthn_credentials (
                id, user_id, credential_id, public_key, public_key_algorithm,
                signature_counter, attestation_object, authenticator_data,
                user_handle, credential_type, transports, created_at, last_used_at,
                aaguid, attestation_format, device_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        "#;

        db.execute(
            query,
            &[
                &credential_id,
                &user_id,
                &credential.credential_id,
                &credential.public_key,
                &credential.public_key_algorithm,
                &(credential.signature_counter as i64),
                &credential.attestation_object,
                &credential.authenticator_data,
                &credential.user_handle,
                &credential.credential_type,
                &credential.transports,
                &now,
                &credential.last_used_at,
                &credential.aaguid,
                &credential.attestation_format,
                &credential.device_id,
            ],
        )
        .await?;

        Ok(())
    }

    /// Get WebAuthn credential by credential ID
    pub async fn get_credential_by_id(
        db: &Database,
        credential_id: &[u8],
    ) -> Result<Option<WebauthnCredential>> {
        let query = r#"
            SELECT
                id, user_id, credential_id, public_key, public_key_algorithm,
                signature_counter, attestation_object, authenticator_data, user_handle,
                credential_type, transports, aaguid, attestation_format,
                device_id, created_at, last_used_at, enabled
            FROM webauthn_credentials
            WHERE credential_id = $1
        "#;

        let row = db.query_opt(query, &[&credential_id]).await?;

        Ok(row.map(|r| WebauthnCredential {
            id: r.get("id"),
            user_id: r.get("user_id"),
            credential_id: r.get("credential_id"),
            public_key: r.get("public_key"),
            public_key_algorithm: r.get("public_key_algorithm"),
            signature_counter: r.get::<_, i64>("signature_counter") as u32,
            attestation_object: r.get("attestation_object"),
            authenticator_data: r.get("authenticator_data"),
            user_handle: r.get("user_handle"),
            credential_type: r.get("credential_type"),
            transports: r.get("transports"),
            aaguid: r.get("aaguid"),
            attestation_format: r.get("attestation_format"),
            device_id: r.get("device_id"),
            created_at: r.get("created_at"),
            last_used_at: r.get("last_used_at"),
            enabled: r.get("enabled"),
        }))
    }

    /// Get all WebAuthn credentials for a user
    pub async fn get_user_credentials(
        db: &Database,
        user_id: Uuid,
    ) -> Result<Vec<WebauthnCredential>> {
        let query = r#"
            SELECT
                id, user_id, credential_id, public_key, public_key_algorithm,
                signature_counter, attestation_object, authenticator_data, user_handle,
                credential_type, transports, aaguid, attestation_format,
                device_id, created_at, last_used_at, enabled
            FROM webauthn_credentials
            WHERE user_id = $1
            ORDER BY created_at DESC
        "#;

        let rows = db.query(query, &[&user_id]).await?;
        let credentials = rows
            .into_iter()
            .map(|row: tokio_postgres::Row| WebauthnCredential {
                id: row.get("id"),
                user_id: row.get("user_id"),
                credential_id: row.get("credential_id"),
                public_key: row.get("public_key"),
                public_key_algorithm: row.get("public_key_algorithm"),
                signature_counter: row.get::<_, i64>("signature_counter") as u32,
                attestation_object: row.get("attestation_object"),
                authenticator_data: row.get("authenticator_data"),
                user_handle: row.get("user_handle"),
                credential_type: row.get("credential_type"),
                transports: row.get("transports"),
                aaguid: row.get("aaguid"),
                attestation_format: row.get("attestation_format"),
                device_id: row.get("device_id"),
                created_at: row.get("created_at"),
                last_used_at: row.get("last_used_at"),
                enabled: row.get("enabled"),
            })
            .collect();
        Ok(credentials)
    }

    /// Delete all WebAuthn credentials for a user
    pub async fn delete_user_credentials(db: &Database, user_id: Uuid) -> Result<()> {
        let query = "DELETE FROM webauthn_credentials WHERE user_id = $1";
        db.execute(query, &[&user_id]).await?;
        Ok(())
    }

    /// Update signature count after authentication
    pub async fn update_signature_count(
        db: &Database,
        credential_id: &[u8],
        new_count: i64,
    ) -> Result<()> {
        let now = Utc::now();
        let query = r#"
            UPDATE webauthn_credentials
            SET signature_counter = $2, last_used_at = $3
            WHERE credential_id = $1
        "#;
        db.execute(query, &[&credential_id, &new_count, &now])
            .await?;
        Ok(())
    }

}

/// Database operations for identity provider management
pub mod identity_providers {
    use authenc_core::error::Result;

    use crate::database::Database;
    use chrono::{DateTime, Utc};
    use serde_json::Value;
    use uuid::Uuid;

    /// Identity provider data structure for database operations
    #[derive(Debug, Clone)]
    pub struct IdentityProviderData {
        /// Unique identifier for the identity provider
        pub id: Uuid,
        /// Internal name of the identity provider
        pub name: String,
        /// Display name shown to users
        pub display_name: String,
        /// Type of identity provider (SAML, OIDC, etc.)
        pub provider_type: String,
        /// Whether the provider is enabled
        pub enabled: bool,
        /// ID of the realm this provider belongs to
        pub realm_id: Uuid,
        /// Configuration data as JSON
        pub config: Value,
        /// Path to truststore for SSL certificates
        pub truststore_path: Option<String>,
        /// Path to keystore for client certificates
        pub keystore_path: Option<String>,
        /// When the provider was created
        pub created_at: DateTime<Utc>,
        /// When the provider was last updated
        pub updated_at: DateTime<Utc>,
    }

    /// Get identity provider by entity ID (from config)
    pub async fn get_identity_provider_by_entity_id(
        db: &Database,
        entity_id: &str,
    ) -> Result<Option<IdentityProviderData>> {
        let query = r#"
            SELECT id, name, display_name, provider_type, enabled, realm_id,
                   config, truststore_path, keystore_path, created_at, updated_at
            FROM identity_providers
            WHERE config->>'entity_id' = $1
        "#;

        let row_opt = db.query_opt(query, &[&entity_id]).await.map_err(|e| {
            authenc_core::error::AuthencError::database(format!("Failed to get identity provider: {}", e))
        })?;

        if let Some(row) = row_opt {
            Ok(Some(IdentityProviderData {
                id: row.get(0),
                name: row.get(1),
                display_name: row.get(2),
                provider_type: row.get(3),
                enabled: row.get(4),
                realm_id: row.get(5),
                config: {
                    let json_str: String = row.get(6);
                    serde_json::from_str(&json_str)?
                },
                truststore_path: row.get(7),
                keystore_path: row.get(8),
                created_at: row.get(9),
                updated_at: row.get(10),
            }))
        } else {
            Ok(None)
        }
    }

    /// Create a new identity provider
    pub async fn create_identity_provider(
        db: &Database,
        name: &str,
        display_name: &str,
        provider_type: &str,
        enabled: bool,
        realm_id: Uuid,
        config: Value,
        truststore_path: Option<&str>,
        keystore_path: Option<&str>,
    ) -> Result<IdentityProviderData> {
        let config_json = serde_json::to_string(&config)?;

        let query = r#"
            INSERT INTO identity_providers (
                name, display_name, provider_type, enabled, realm_id,
                config, truststore_path, keystore_path
            )
            VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
            RETURNING id, name, display_name, provider_type, enabled, realm_id,
                      config, truststore_path, keystore_path, created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &name,
                    &display_name,
                    &provider_type,
                    &enabled,
                    &realm_id,
                    &config_json,
                    &truststore_path,
                    &keystore_path,
                ],
            )
            .await?;

        Ok(IdentityProviderData {
            id: row.get(0),
            name: row.get(1),
            display_name: row.get(2),
            provider_type: row.get(3),
            enabled: row.get(4),
            realm_id: row.get(5),
            config: {
                let json_str: String = row.get(6);
                serde_json::from_str(&json_str)?
            },
            truststore_path: row.get(7),
            keystore_path: row.get(8),
            created_at: row.get(9),
            updated_at: row.get(10),
        })
    }

    /// Get identity provider by ID
    pub async fn get_identity_provider_by_id(
        db: &Database,
        provider_id: Uuid,
    ) -> Result<Option<IdentityProviderData>> {
        let query = r#"
            SELECT id, name, display_name, provider_type, enabled, realm_id,
                   config, truststore_path, keystore_path, created_at, updated_at
            FROM identity_providers
            WHERE id = $1 AND deleted_at IS NULL
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&provider_id]).await?;
        if rows.is_empty() {
            return Ok(None);
        }

        let row: &tokio_postgres::Row = &rows[0];
        Ok(Some(IdentityProviderData {
            id: row.get(0),
            name: row.get(1),
            display_name: row.get(2),
            provider_type: row.get(3),
            enabled: row.get(4),
            realm_id: row.get(5),
            config: {
                let json_str: String = row.get(6);
                serde_json::from_str(&json_str)?
            },
            truststore_path: row.get(7),
            keystore_path: row.get(8),
            created_at: row.get(9),
            updated_at: row.get(10),
        }))
    }

    /// Get all identity providers for a realm
    pub async fn get_identity_providers_by_realm(
        db: &Database,
        realm_id: Uuid,
    ) -> Result<Vec<IdentityProviderData>> {
        let query = r#"
            SELECT id, name, display_name, provider_type, enabled, realm_id,
                   config, truststore_path, keystore_path, created_at, updated_at
            FROM identity_providers
            WHERE realm_id = $1 AND deleted_at IS NULL
            ORDER BY display_name
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&realm_id]).await?;
        let mut providers = Vec::new();

        for row in rows {
            providers.push(IdentityProviderData {
                id: row.get(0),
                name: row.get(1),
                display_name: row.get(2),
                provider_type: row.get(3),
                enabled: row.get(4),
                realm_id: row.get(5),
                config: {
                    let json_str: String = row.get(6);
                    serde_json::from_str(&json_str)?
                },
                truststore_path: row.get(7),
                keystore_path: row.get(8),
                created_at: row.get(9),
                updated_at: row.get(10),
            });
        }

        Ok(providers)
    }

    /// Update identity provider
    pub async fn update_identity_provider(
        db: &Database,
        provider_id: Uuid,
        name: Option<&str>,
        display_name: Option<&str>,
        provider_type: Option<&str>,
        enabled: Option<bool>,
        config: Option<Value>,
        truststore_path: Option<&str>,
        keystore_path: Option<&str>,
    ) -> Result<IdentityProviderData> {
        let config_json = config.as_ref().map(serde_json::to_string).transpose()?;

        let query = r#"
            UPDATE identity_providers
            SET name = COALESCE($2, name),
                display_name = COALESCE($3, display_name),
                provider_type = COALESCE($4, provider_type),
                enabled = COALESCE($5, enabled),
                config = COALESCE($6::jsonb, config),
                truststore_path = COALESCE($7, truststore_path),
                keystore_path = COALESCE($8, keystore_path),
                updated_at = NOW()
            WHERE id = $1 AND deleted_at IS NULL
            RETURNING id, name, display_name, provider_type, enabled, realm_id,
                      config, truststore_path, keystore_path, created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &provider_id,
                    &name,
                    &display_name,
                    &provider_type,
                    &enabled,
                    &config_json,
                    &truststore_path,
                    &keystore_path,
                ],
            )
            .await?;

        Ok(IdentityProviderData {
            id: row.get(0),
            name: row.get(1),
            display_name: row.get(2),
            provider_type: row.get(3),
            enabled: row.get(4),
            realm_id: row.get(5),
            config: {
                let json_str: String = row.get(6);
                serde_json::from_str(&json_str)?
            },
            truststore_path: row.get(7),
            keystore_path: row.get(8),
            created_at: row.get(9),
            updated_at: row.get(10),
        })
    }

    /// Delete identity provider (soft delete)
    pub async fn delete_identity_provider(db: &Database, provider_id: Uuid) -> Result<()> {
        let query = r#"
            UPDATE identity_providers
            SET deleted_at = NOW()
            WHERE id = $1 AND deleted_at IS NULL
        "#;

        db.execute(query, &[&provider_id]).await?;
        Ok(())
    }

    /// Check if identity provider exists and is enabled
    pub async fn identity_provider_exists_and_enabled(
        db: &Database,
        provider_id: Uuid,
    ) -> Result<bool> {
        let query = r#"
            SELECT EXISTS(
                SELECT 1 FROM identity_providers
                WHERE id = $1 AND enabled = true AND deleted_at IS NULL
            )
        "#;

        let row: tokio_postgres::Row = db.query_one(query, &[&provider_id]).await?;
        Ok(row.get(0))
    }
}

/// Database operations for federated identity management
pub mod federated_identities {
    use authenc_core::error::Result;

    use authenc_models::models::user::{CreateFederatedIdentityRequest, FederatedIdentity};

    use crate::database::Database;
    use uuid::Uuid;

    /// Create a new federated identity link
    pub async fn create_federated_identity(
        db: &Database,
        request: &CreateFederatedIdentityRequest,
    ) -> Result<FederatedIdentity> {
        let external_attributes_json = request
            .external_attributes
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        let query = r#"
            INSERT INTO federated_identities (
                user_id, identity_provider_id, external_id, external_username,
                external_email, external_attributes
            )
            VALUES ($1, $2, $3, $4, $5, $6::jsonb)
            RETURNING id, user_id, identity_provider_id, external_id, external_username,
                      external_email, external_attributes, last_login_at, created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &request.user_id,
                    &request.identity_provider_id,
                    &request.external_id,
                    &request.external_username,
                    &request.external_email,
                    &external_attributes_json,
                ],
            )
            .await?;

        Ok(FederatedIdentity {
            id: row.get(0),
            user_id: row.get(1),
            identity_provider_id: row.get(2),
            external_id: row.get(3),
            external_username: row.get(4),
            external_email: row.get(5),
            external_attributes: row
                .get::<_, Option<String>>(6)
                .and_then(|s: String| serde_json::from_str(&s).ok()),
            last_login_at: row.get(7),
            created_at: row.get(8),
            updated_at: row.get(9),
        })
    }

    /// Get federated identity by external ID and provider
    pub async fn get_federated_identity_by_external_id(
        db: &Database,
        identity_provider_id: Uuid,
        external_id: &str,
    ) -> Result<Option<FederatedIdentity>> {
        let query = r#"
            SELECT id, user_id, identity_provider_id, external_id, external_username,
                   external_email, external_attributes, last_login_at, created_at, updated_at
            FROM federated_identities
            WHERE identity_provider_id = $1 AND external_id = $2
        "#;

        let rows = db
            .query(query, &[&identity_provider_id, &external_id])
            .await?;
        Ok(rows
            .into_iter()
            .next()
            .map(|r: tokio_postgres::Row| FederatedIdentity {
                id: r.get(0),
                user_id: r.get(1),
                identity_provider_id: r.get(2),
                external_id: r.get(3),
                external_username: r.get(4),
                external_email: r.get(5),
                external_attributes: r
                    .get::<_, Option<String>>(6)
                    .and_then(|s: String| serde_json::from_str(&s).ok()),
                last_login_at: r.get(7),
                created_at: r.get(8),
                updated_at: r.get(9),
            }))
    }

    /// Get all federated identities for a user
    pub async fn get_federated_identities_by_user(
        db: &Database,
        user_id: Uuid,
    ) -> Result<Vec<FederatedIdentity>> {
        let query = r#"
            SELECT id, user_id, identity_provider_id, external_id, external_username,
                   external_email, external_attributes, last_login_at, created_at, updated_at
            FROM federated_identities
            WHERE user_id = $1
            ORDER BY created_at
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&user_id]).await?;
        let mut identities = Vec::new();

        for row in rows {
            identities.push(FederatedIdentity {
                id: row.get(0),
                user_id: row.get(1),
                identity_provider_id: row.get(2),
                external_id: row.get(3),
                external_username: row.get(4),
                external_email: row.get(5),
                external_attributes: row
                    .get::<_, Option<String>>(6)
                    .and_then(|s: String| serde_json::from_str(&s).ok()),
                last_login_at: row.get(7),
                created_at: row.get(8),
                updated_at: row.get(9),
            });
        }

        Ok(identities)
    }

    /// Update last login time for federated identity
    pub async fn update_last_login(db: &Database, federated_identity_id: Uuid) -> Result<()> {
        let query = r#"
            UPDATE federated_identities
            SET last_login_at = NOW(), updated_at = NOW()
            WHERE id = $1
        "#;

        db.execute(query, &[&federated_identity_id]).await?;
        Ok(())
    }

    /// Delete federated identity link
    pub async fn delete_federated_identity(
        db: &Database,
        federated_identity_id: Uuid,
    ) -> Result<()> {
        let query = r#"
            DELETE FROM federated_identities
            WHERE id = $1
        "#;

        db.execute(query, &[&federated_identity_id]).await?;
        Ok(())
    }
}

/// Database operations for authentication flows
pub mod auth_flows {
    use crate::database::Database;
    use authenc_core::error::{AuthencError, Result};
    use chrono::Utc;
    use log::error;
    use uuid::Uuid;

    /// Create authentication flow
    pub async fn create_flow(db: &Database, flow: &serde_json::Value) -> Result<serde_json::Value> {
        let flow_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO authentication_flows (
                id, realm_id, alias, description, provider_id,
                top_level, built_in, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, realm_id, alias, description, provider_id,
                      top_level, built_in, created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &flow_id,
                    &flow
                        .get("realm_id")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok()),
                    &flow.get("alias").and_then(|v| v.as_str()).unwrap_or(""),
                    &flow.get("description").and_then(|v| v.as_str()),
                    &flow
                        .get("provider_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    &flow
                        .get("top_level")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    &flow
                        .get("built_in")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    &now,
                    &now,
                ],
            )
            .await
            .map_err(|e| {
                error!("Failed to create authentication flow: {}", e);
                AuthencError::database("Failed to create authentication flow")
            })?;

        Ok(serde_json::json!({
            "id": row.get::<_, Uuid>(0).to_string(),
            "realm_id": row.get::<_, Option<Uuid>>(1).map(|u| u.to_string()),
            "alias": row.get::<_, String>(2),
            "description": row.get::<_, Option<String>>(3),
            "provider_id": row.get::<_, String>(4),
            "top_level": row.get::<_, bool>(5),
            "built_in": row.get::<_, bool>(6),
            "created_at": row.get::<_, chrono::DateTime<Utc>>(7).to_rfc3339(),
            "updated_at": row.get::<_, chrono::DateTime<Utc>>(8).to_rfc3339(),
        }))
    }

    /// Get authentication flow by ID
    pub async fn get_flow(db: &Database, flow_id: Uuid) -> Result<Option<serde_json::Value>> {
        let query = r#"
            SELECT id, realm_id, alias, description, provider_id,
                   top_level, built_in, created_at, updated_at
            FROM authentication_flows
            WHERE id = $1
        "#;

        let row_opt = db.query_opt(query, &[&flow_id]).await.map_err(|e| {
            error!("Failed to get authentication flow: {}", e);
            AuthencError::database("Failed to get authentication flow")
        })?;

        Ok(row_opt.map(|row| {
            serde_json::json!({
                "id": row.get::<_, Uuid>(0).to_string(),
                "realm_id": row.get::<_, Option<Uuid>>(1).map(|u| u.to_string()),
                "alias": row.get::<_, String>(2),
                "description": row.get::<_, Option<String>>(3),
                "provider_id": row.get::<_, String>(4),
                "top_level": row.get::<_, bool>(5),
                "built_in": row.get::<_, bool>(6),
                "created_at": row.get::<_, chrono::DateTime<Utc>>(7).to_rfc3339(),
                "updated_at": row.get::<_, chrono::DateTime<Utc>>(8).to_rfc3339(),
            })
        }))
    }

    /// List authentication flows
    pub async fn list_flows(
        db: &Database,
        realm_id: Option<Uuid>,
    ) -> Result<Vec<serde_json::Value>> {
        let query = if realm_id.is_some() {
            r#"
                SELECT id, realm_id, alias, description, provider_id,
                       top_level, built_in, created_at, updated_at
                FROM authentication_flows
                WHERE realm_id = $1
                ORDER BY alias
            "#
        } else {
            r#"
                SELECT id, realm_id, alias, description, provider_id,
                       top_level, built_in, created_at, updated_at
                FROM authentication_flows
                ORDER BY alias
            "#
        };

        let rows: Vec<tokio_postgres::Row> = if let Some(realm_id) = realm_id {
            db.query(query, &[&realm_id]).await
        } else {
            db.query(query, &[]).await
        }
        .map_err(|e| {
            error!("Failed to list authentication flows: {}", e);
            AuthencError::database("Failed to list authentication flows")
        })?;

        Ok(rows
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "id": row.get::<_, Uuid>(0).to_string(),
                    "realm_id": row.get::<_, Option<Uuid>>(1).map(|u| u.to_string()),
                    "alias": row.get::<_, String>(2),
                    "description": row.get::<_, Option<String>>(3),
                    "provider_id": row.get::<_, String>(4),
                    "top_level": row.get::<_, bool>(5),
                    "built_in": row.get::<_, bool>(6),
                    "created_at": row.get::<_, chrono::DateTime<Utc>>(7).to_rfc3339(),
                    "updated_at": row.get::<_, chrono::DateTime<Utc>>(8).to_rfc3339(),
                })
            })
            .collect())
    }

    /// Update authentication flow
    pub async fn update_flow(
        db: &Database,
        flow_id: Uuid,
        flow: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let now = Utc::now();

        let query = r#"
            UPDATE authentication_flows
            SET alias = $2, description = $3, provider_id = $4,
                top_level = $5, updated_at = $6
            WHERE id = $1
            RETURNING id, realm_id, alias, description, provider_id,
                      top_level, built_in, created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &flow_id,
                    &flow.get("alias").and_then(|v| v.as_str()).unwrap_or(""),
                    &flow.get("description").and_then(|v| v.as_str()),
                    &flow
                        .get("provider_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    &flow
                        .get("top_level")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    &now,
                ],
            )
            .await
            .map_err(|e| {
                error!("Failed to update authentication flow: {}", e);
                AuthencError::database("Failed to update authentication flow")
            })?;

        Ok(serde_json::json!({
            "id": row.get::<_, Uuid>(0).to_string(),
            "realm_id": row.get::<_, Option<Uuid>>(1).map(|u| u.to_string()),
            "alias": row.get::<_, String>(2),
            "description": row.get::<_, Option<String>>(3),
            "provider_id": row.get::<_, String>(4),
            "top_level": row.get::<_, bool>(5),
            "built_in": row.get::<_, bool>(6),
            "created_at": row.get::<_, chrono::DateTime<Utc>>(7).to_rfc3339(),
            "updated_at": row.get::<_, chrono::DateTime<Utc>>(8).to_rfc3339(),
        }))
    }

    /// Delete authentication flow
    pub async fn delete_flow(db: &Database, flow_id: Uuid) -> Result<()> {
        let query = "DELETE FROM authentication_flows WHERE id = $1";

        db.execute(query, &[&flow_id]).await.map_err(|e| {
            error!("Failed to delete authentication flow: {}", e);
            AuthencError::database("Failed to delete authentication flow")
        })?;

        Ok(())
    }

    /// Create authentication execution
    pub async fn create_execution(
        db: &Database,
        execution: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let execution_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO authentication_executions (
                id, flow_id, authenticator, authenticator_config,
                authenticator_flow, requirement, priority, parent_flow,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING id, flow_id, authenticator, authenticator_config,
                      authenticator_flow, requirement, priority, parent_flow,
                      created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &execution_id,
                    &execution
                        .get("flow_id")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok()),
                    &execution.get("authenticator").and_then(|v| v.as_str()),
                    &execution
                        .get("authenticator_config")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok()),
                    &execution
                        .get("authenticator_flow")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    &execution
                        .get("requirement")
                        .and_then(|v| v.as_str())
                        .unwrap_or("DISABLED"),
                    &(execution
                        .get("priority")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0) as i32),
                    &execution
                        .get("parent_flow")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok()),
                    &now,
                    &now,
                ],
            )
            .await
            .map_err(|e| {
                error!("Failed to create authentication execution: {}", e);
                AuthencError::database("Failed to create authentication execution")
            })?;

        Ok(serde_json::json!({
            "id": row.get::<_, Uuid>(0).to_string(),
            "flow_id": row.get::<_, Option<Uuid>>(1).map(|u| u.to_string()),
            "authenticator": row.get::<_, Option<String>>(2),
            "authenticator_config": row.get::<_, Option<Uuid>>(3).map(|u| u.to_string()),
            "authenticator_flow": row.get::<_, bool>(4),
            "requirement": row.get::<_, String>(5),
            "priority": row.get::<_, i32>(6),
            "parent_flow": row.get::<_, Option<Uuid>>(7).map(|u| u.to_string()),
            "created_at": row.get::<_, chrono::DateTime<Utc>>(8).to_rfc3339(),
            "updated_at": row.get::<_, chrono::DateTime<Utc>>(9).to_rfc3339(),
        }))
    }

    /// Create authentication session
    pub async fn create_session(
        db: &Database,
        session: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let session_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::hours(1); // Default 1 hour expiry

        let query = r#"
            INSERT INTO authentication_sessions (
                id, realm_id, user_id, client_id, flow_id, auth_state,
                protocol, redirect_uri, execution_status, authentication_notes,
                client_notes, required_actions, started_at, expires_at,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
            RETURNING id, realm_id, user_id, client_id, flow_id, auth_state,
                      protocol, redirect_uri, started_at, expires_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &session_id,
                    &session
                        .get("realm_id")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok()),
                    &session
                        .get("user_id")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok()),
                    &session.get("client_id").and_then(|v| v.as_str()),
                    &session
                        .get("flow_id")
                        .and_then(|v| v.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok()),
                    &session
                        .get("auth_state")
                        .and_then(|v| v.as_str())
                        .unwrap_or("STARTED"),
                    &session
                        .get("protocol")
                        .and_then(|v| v.as_str())
                        .unwrap_or("openid-connect"),
                    &session.get("redirect_uri").and_then(|v| v.as_str()),
                    &session
                        .get("execution_status")
                        .unwrap_or(&serde_json::json!({})),
                    &session
                        .get("authentication_notes")
                        .unwrap_or(&serde_json::json!({})),
                    &session
                        .get("client_notes")
                        .unwrap_or(&serde_json::json!({})),
                    &session
                        .get("required_actions")
                        .unwrap_or(&serde_json::json!([])),
                    &now,
                    &expires_at,
                    &now,
                    &now,
                ],
            )
            .await
            .map_err(|e| {
                error!("Failed to create authentication session: {}", e);
                AuthencError::database("Failed to create authentication session")
            })?;

        Ok(serde_json::json!({
            "id": row.get::<_, Uuid>(0).to_string(),
            "realm_id": row.get::<_, Option<Uuid>>(1).map(|u| u.to_string()),
            "user_id": row.get::<_, Option<Uuid>>(2).map(|u| u.to_string()),
            "client_id": row.get::<_, Option<String>>(3),
            "flow_id": row.get::<_, Option<Uuid>>(4).map(|u| u.to_string()),
            "auth_state": row.get::<_, String>(5),
            "protocol": row.get::<_, String>(6),
            "redirect_uri": row.get::<_, Option<String>>(7),
            "started_at": row.get::<_, chrono::DateTime<Utc>>(8).to_rfc3339(),
            "expires_at": row.get::<_, chrono::DateTime<Utc>>(9).to_rfc3339(),
        }))
    }

    /// Get authentication session by ID
    pub async fn get_session(db: &Database, session_id: Uuid) -> Result<Option<serde_json::Value>> {
        let query = r#"
            SELECT id, realm_id, user_id, client_id, flow_id, auth_state,
                   protocol, redirect_uri, execution_status, authentication_notes,
                   client_notes, required_actions, started_at, completed_at,
                   expires_at, success, error_message
            FROM authentication_sessions
            WHERE id = $1
        "#;

        let row_opt = db.query_opt(query, &[&session_id]).await.map_err(|e| {
            error!("Failed to get authentication session: {}", e);
            AuthencError::database("Failed to get authentication session")
        })?;

        Ok(row_opt.map(|row| {
            serde_json::json!({
                "id": row.get::<_, Uuid>(0).to_string(),
                "realm_id": row.get::<_, Option<Uuid>>(1).map(|u| u.to_string()),
                "user_id": row.get::<_, Option<Uuid>>(2).map(|u| u.to_string()),
                "client_id": row.get::<_, Option<String>>(3),
                "flow_id": row.get::<_, Option<Uuid>>(4).map(|u| u.to_string()),
                "auth_state": row.get::<_, String>(5),
                "protocol": row.get::<_, String>(6),
                "redirect_uri": row.get::<_, Option<String>>(7),
                "execution_status": row.get::<_, serde_json::Value>(8),
                "authentication_notes": row.get::<_, serde_json::Value>(9),
                "client_notes": row.get::<_, serde_json::Value>(10),
                "required_actions": row.get::<_, serde_json::Value>(11),
                "started_at": row.get::<_, chrono::DateTime<Utc>>(12).to_rfc3339(),
                "completed_at": row.get::<_, Option<chrono::DateTime<Utc>>>(13).map(|dt| dt.to_rfc3339()),
                "expires_at": row.get::<_, chrono::DateTime<Utc>>(14).to_rfc3339(),
                "success": row.get::<_, Option<bool>>(15),
                "error_message": row.get::<_, Option<String>>(16),
            })
        }))
    }

    /// Update authentication session
    pub async fn update_session(
        db: &Database,
        session_id: Uuid,
        session: &serde_json::Value,
    ) -> Result<()> {
        let now = Utc::now();

        let query = r#"
            UPDATE authentication_sessions
            SET auth_state = $2, execution_status = $3, authentication_notes = $4,
                client_notes = $5, required_actions = $6, updated_at = $7
            WHERE id = $1
        "#;

        db.execute(
            query,
            &[
                &session_id,
                &session
                    .get("auth_state")
                    .and_then(|v| v.as_str())
                    .unwrap_or("IN_PROGRESS"),
                &session
                    .get("execution_status")
                    .unwrap_or(&serde_json::json!({})),
                &session
                    .get("authentication_notes")
                    .unwrap_or(&serde_json::json!({})),
                &session
                    .get("client_notes")
                    .unwrap_or(&serde_json::json!({})),
                &session
                    .get("required_actions")
                    .unwrap_or(&serde_json::json!([])),
                &now,
            ],
        )
        .await
        .map_err(|e| {
            error!("Failed to update authentication session: {}", e);
            AuthencError::database("Failed to update authentication session")
        })?;

        Ok(())
    }

    /// Complete authentication session
    pub async fn complete_session(
        db: &Database,
        session_id: Uuid,
        success: bool,
        error_message: Option<String>,
    ) -> Result<()> {
        let now = Utc::now();
        let auth_state = if success { "COMPLETED" } else { "FAILED" };

        let query = r#"
            UPDATE authentication_sessions
            SET auth_state = $2, completed_at = $3, success = $4,
                error_message = $5, updated_at = $6
            WHERE id = $1
        "#;

        db.execute(
            query,
            &[
                &session_id,
                &auth_state,
                &now,
                &success,
                &error_message,
                &now,
            ],
        )
        .await
        .map_err(|e| {
            error!("Failed to complete authentication session: {}", e);
            AuthencError::database("Failed to complete authentication session")
        })?;

        Ok(())
    }

    /// Clean up expired authentication sessions
    pub async fn cleanup_expired_sessions(db: &Database) -> Result<i64> {
        let query = "DELETE FROM authentication_sessions WHERE expires_at < NOW()";

        let rows_affected = db.execute(query, &[]).await.map_err(|e| {
            error!("Failed to cleanup expired sessions: {}", e);
            AuthencError::database("Failed to cleanup expired sessions")
        })?;

        Ok(rows_affected as i64)
    }
}

/// Database operations for resources
pub mod resources {
    use crate::database::Database;
    use authenc_core::error::{AuthencError, Result};
    use authenc_models::models::resource::{CreateResourceRequest, Resource, UpdateResourceRequest};
    use chrono::Utc;
    use log::error;
    use uuid::Uuid;

    /// Create a new resource
    pub async fn create_resource(
        db: &Database,
        request: CreateResourceRequest,
        owner: String,
        realm_id: Uuid,
        resource_server_id: Uuid,
    ) -> Result<Resource> {
        let resource_id = Uuid::new_v4();
        let now = Utc::now();

        let uris = request.uris.unwrap_or_default();
        let scopes = request.scopes.unwrap_or_default();
        let attributes_json = serde_json::to_value(request.attributes.unwrap_or_default())
            .map_err(|e| AuthencError::validation(format!("Invalid attributes: {}", e)))?;

        let query = r#"
            INSERT INTO resources (
                id, name, display_name, uris, icon_uri, resource_type, owner,
                enabled, realm_id, resource_server_id, scopes, attributes,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING
                id, name, display_name, uris, icon_uri, resource_type, owner,
                enabled, realm_id, resource_server_id, scopes, attributes,
                created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &resource_id,
                    &request.name,
                    &request.display_name,
                    &uris,
                    &request.icon_uri,
                    &request.resource_type,
                    &owner,
                    &true, // enabled
                    &realm_id,
                    &resource_server_id,
                    &scopes,
                    &attributes_json,
                    &now,
                    &now,
                ],
            )
            .await
            .map_err(|e| {
                error!("Failed to create resource: {}", e);
                AuthencError::database(format!("Failed to create resource: {}", e))
            })?;

        row.try_into()
    }

    /// Get resource by ID
    pub async fn get_resource_by_id(db: &Database, resource_id: Uuid) -> Result<Option<Resource>> {
        let query = r#"
            SELECT
                id, name, display_name, uris, icon_uri, resource_type, owner,
                enabled, realm_id, resource_server_id, scopes, attributes,
                created_at, updated_at
            FROM resources
            WHERE id = $1
        "#;

        match db.query_opt(query, &[&resource_id]).await {
            Ok(Some(row)) => Ok(Some(row.try_into()?)),
            Ok(None) => Ok(None),
            Err(e) => {
                error!("Failed to get resource: {}", e);
                Err(AuthencError::database(format!(
                    "Failed to get resource: {}",
                    e
                )))
            }
        }
    }

    /// Get resource by name
    pub async fn get_resource_by_name(
        db: &Database,
        name: &str,
        resource_server_id: Uuid,
    ) -> Result<Option<Resource>> {
        let query = r#"
            SELECT
                id, name, display_name, uris, icon_uri, resource_type, owner,
                enabled, realm_id, resource_server_id, scopes, attributes,
                created_at, updated_at
            FROM resources
            WHERE name = $1 AND resource_server_id = $2
        "#;

        match db.query_opt(query, &[&name, &resource_server_id]).await {
            Ok(Some(row)) => Ok(Some(row.try_into()?)),
            Ok(None) => Ok(None),
            Err(e) => {
                error!("Failed to get resource by name: {}", e);
                Err(AuthencError::database(format!(
                    "Failed to get resource by name: {}",
                    e
                )))
            }
        }
    }

    /// List resources by owner
    pub async fn get_resources_by_owner(
        db: &Database,
        owner: &str,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Resource>> {
        let offset = first.unwrap_or(0);
        let limit = max.unwrap_or(100);

        let query = r#"
            SELECT
                id, name, display_name, uris, icon_uri, resource_type, owner,
                enabled, realm_id, resource_server_id, scopes, attributes,
                created_at, updated_at
            FROM resources
            WHERE owner = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
        "#;

        let rows = db
            .query(query, &[&owner, &(limit as i64), &(offset as i64)])
            .await?;
        rows.into_iter()
            .map(|row: tokio_postgres::Row| row.try_into())
            .collect::<Result<Vec<Resource>>>()
    }

    /// List resources by resource server
    pub async fn get_resources_by_server(
        db: &Database,
        resource_server_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Resource>> {
        let offset = first.unwrap_or(0);
        let limit = max.unwrap_or(100);

        let query = r#"
            SELECT
                id, name, display_name, uris, icon_uri, resource_type, owner,
                enabled, realm_id, resource_server_id, scopes, attributes,
                created_at, updated_at
            FROM resources
            WHERE resource_server_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
        "#;

        let rows = db
            .query(
                query,
                &[&resource_server_id, &(limit as i64), &(offset as i64)],
            )
            .await?;
        rows.into_iter()
            .map(|row: tokio_postgres::Row| row.try_into())
            .collect::<Result<Vec<Resource>>>()
    }

    /// List resources by realm
    pub async fn get_resources_by_realm(
        db: &Database,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Resource>> {
        let offset = first.unwrap_or(0);
        let limit = max.unwrap_or(100);

        let query = r#"
            SELECT
                id, name, display_name, uris, icon_uri, resource_type, owner,
                enabled, realm_id, resource_server_id, scopes, attributes,
                created_at, updated_at
            FROM resources
            WHERE realm_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
        "#;

        let rows = db
            .query(query, &[&realm_id, &(limit as i64), &(offset as i64)])
            .await?;
        rows.into_iter()
            .map(|row: tokio_postgres::Row| row.try_into())
            .collect::<Result<Vec<Resource>>>()
    }

    /// Update resource
    pub async fn update_resource(
        db: &Database,
        resource_id: Uuid,
        request: UpdateResourceRequest,
    ) -> Result<Resource> {
        let now = Utc::now();

        let attributes_json = request
            .attributes
            .map(|a| serde_json::to_value(&a))
            .transpose()
            .map_err(|e| AuthencError::validation(format!("Invalid attributes: {}", e)))?;

        let query = r#"
            UPDATE resources
            SET
                display_name = COALESCE($2, display_name),
                uris = COALESCE($3, uris),
                icon_uri = COALESCE($4, icon_uri),
                resource_type = COALESCE($5, resource_type),
                owner = COALESCE($6, owner),
                scopes = COALESCE($7, scopes),
                attributes = COALESCE($8, attributes),
                updated_at = $9
            WHERE id = $1
            RETURNING
                id, name, display_name, uris, icon_uri, resource_type, owner,
                enabled, realm_id, resource_server_id, scopes, attributes,
                created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &resource_id,
                    &request.display_name,
                    &request.uris,
                    &request.icon_uri,
                    &request.resource_type,
                    &request.owner,
                    &request.scopes,
                    &attributes_json,
                    &now,
                ],
            )
            .await
            .map_err(|e| {
                error!("Failed to update resource: {}", e);
                AuthencError::database(format!("Failed to update resource: {}", e))
            })?;

        row.try_into()
    }

    /// Delete resource
    pub async fn delete_resource(db: &Database, resource_id: Uuid) -> Result<()> {
        let query = "DELETE FROM resources WHERE id = $1";

        let rows_affected = db.execute(query, &[&resource_id]).await?;

        if rows_affected == 0 {
            return Err(AuthencError::resource_not_found(format!(
                "Resource {} not found",
                resource_id
            )));
        }

        Ok(())
    }

    /// Search resources by name pattern
    pub async fn search_resources(
        db: &Database,
        name_pattern: &str,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Resource>> {
        let offset = first.unwrap_or(0);
        let limit = max.unwrap_or(100);
        let pattern = format!("%{}%", name_pattern);

        let query = r#"
            SELECT
                id, name, display_name, uris, icon_uri, resource_type, owner,
                enabled, realm_id, resource_server_id, scopes, attributes,
                created_at, updated_at
            FROM resources
            WHERE realm_id = $1 AND (name ILIKE $2 OR display_name ILIKE $2)
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
        "#;

        let rows = db
            .query(
                query,
                &[&realm_id, &pattern, &(limit as i64), &(offset as i64)],
            )
            .await?;
        rows.into_iter()
            .map(|row: tokio_postgres::Row| row.try_into())
            .collect::<Result<Vec<Resource>>>()
    }

    /// Count resources
    pub async fn count_resources(db: &Database, resource_server_id: Uuid) -> Result<i64> {
        let query = "SELECT COUNT(*) FROM resources WHERE resource_server_id = $1";

        let row: tokio_postgres::Row = db.query_one(query, &[&resource_server_id]).await?;
        Ok(row.get(0))
    }

    /// Count resources by owner
    pub async fn count_resources_by_owner(db: &Database, owner: &str) -> Result<i64> {
        let query = "SELECT COUNT(*) FROM resources WHERE owner = $1";

        let row: tokio_postgres::Row = db.query_one(query, &[&owner]).await?;
        Ok(row.get(0))
    }
}
use authenc_core::error::{AuthencError, Result};

use authenc_models::models::events::{AdminEvent, AuthDetails, Event, EventType, OperationType, ResourceType};

use authenc_spi::spi::events::{AdminEventOperationType, AdminEventQuery, EventQuery};

use crate::database::Database;

use log::error;
use serde_json;
use std::collections::HashMap;
use uuid::Uuid;
use tokio_postgres::types::{FromSql, Type};
use serde::Deserialize;

/// Wrapper for direct JSON deserialization from database
struct Json<T>(pub T);

impl<'a, T> FromSql<'a> for Json<T>
where
    T: Deserialize<'a>,
{
    fn from_sql(ty: &Type, raw: &'a [u8]) -> std::result::Result<Self, Box<dyn std::error::Error + Sync + Send>> {
        if *ty == Type::JSONB {
             // Postgres JSONB version 1
             if raw.is_empty() {
                 return Err("empty JSONB value".into());
             }
             let version = raw[0];
             if version != 1 {
                 return Err("unsupported JSONB version".into());
             }
             let val = serde_json::from_slice(&raw[1..])?;
             Ok(Json(val))
        } else if *ty == Type::JSON {
             let val = serde_json::from_slice(raw)?;
             Ok(Json(val))
        } else {
             Err("invalid type".into())
        }
    }

    fn accepts(ty: &Type) -> bool {
        *ty == Type::JSONB || *ty == Type::JSON
    }
}

/// Store a user event in the database
pub async fn store_event(db: &Database, event: &Event) -> Result<()> {
    let details_json = serde_json::to_string(&event.details).map_err(|e| {
        error!("Failed to serialize event details: {}", e);
        AuthencError::validation("Failed to serialize event details")
    })?;

    let query = r#"
            INSERT INTO events (
                id, time, event_type, realm_id, realm_name, client_id,
                user_id, session_id, ip_address, error, details
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#;

    db.execute(
        query,
        &[
            &Uuid::parse_str(&event.id)
                .map_err(|_| AuthencError::validation("Invalid event ID"))?,
            &event.time,
            &event.event_type.as_str(),
            &event.realm_id,
            &event.realm_name,
            &event.client_id,
            &event.user_id,
            &event.session_id,
            &event.ip_address,
            &event.error,
            &details_json,
        ],
    )
    .await
    .map_err(|e| {
        error!("Failed to store event: {}", e);
        AuthencError::database("Failed to store event")
    })?;

    Ok(())
}

/// Store an admin event in the database
pub async fn store_admin_event(db: &Database, event: &AdminEvent) -> Result<()> {
    let query = r#"
            INSERT INTO admin_events (
                id, time, realm_id, realm_name, auth_user_id, auth_username,
                auth_ip_address, auth_user_agent, resource_type, operation_type,
                resource_path, representation, error
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        "#;

    // Use default text if realm_name is None, as table might expect string or NULL is allowed
    // Based on previous code, realm_name is Option<String>.
    db.execute(
        query,
        &[
            &Uuid::parse_str(&event.id)
                .map_err(|_| AuthencError::validation("Invalid admin event ID"))?,
            &event.time,
            &event.realm_id,
            &event.realm_name,
            &Uuid::parse_str(&event.auth_details.user_id)
                .map_err(|_| AuthencError::validation("Invalid auth user ID"))?,
            &event.auth_details.username,
            &event.auth_details.ip_address,
            &event.auth_details.user_agent,
            &event.resource_type.as_str(),
            &event.operation_type.as_str(),
            &event.resource_path,
            &event.representation,
            &event.error,
        ],
    )
    .await
    .map_err(|e| {
        error!("Failed to store admin event: {}", e);
        AuthencError::database("Failed to store admin event")
    })?;

    Ok(())
}

/// Query events based on the provided query parameters
pub async fn query_events(db: &Database, query: &EventQuery) -> Result<Vec<Event>> {
    let mut conditions = Vec::new();
    let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
    let mut param_index = 1;

    // Build WHERE conditions
    if let Some(realm_id) = &query.realm_id {
        conditions.push(format!("realm_id = ${}", param_index));
        params.push(Box::new(realm_id.clone()));
        param_index += 1;
    }

    if let Some(user_id) = &query.user_id {
        conditions.push(format!("user_id = ${}", param_index));
        params.push(Box::new(user_id.clone()));
        param_index += 1;
    }

    if let Some(client_id) = &query.client_id {
        conditions.push(format!("client_id = ${}", param_index));
        params.push(Box::new(client_id.clone()));
        param_index += 1;
    }

    if let Some(event_types) = &query.event_types
        && let Some(event_type) = event_types.first() {
            conditions.push(format!("event_type = ${}", param_index));
            params.push(Box::new(event_type.as_str()));
            param_index += 1;
        }

    if let Some(from_date) = &query.date_from {
        conditions.push(format!("time >= ${}", param_index));
        params.push(Box::new(*from_date));
        param_index += 1;
    }

    if let Some(to_date) = &query.date_to {
        conditions.push(format!("time <= ${}", param_index));
        params.push(Box::new(*to_date));
        param_index += 1;
    }

    if let Some(ip_address) = &query.ip_address {
        conditions.push(format!("ip_address = ${}", param_index));
        params.push(Box::new(ip_address.clone()));
        param_index += 1;
    }

    // SECURITY: This is SAFE from SQL injection because:
    // 1. The where_clause only contains parameterized query placeholders ($1, $2, etc.)
    // 2. Actual user data is passed via params vector and properly escaped by tokio_postgres
    // 3. The format! is only building query structure, NOT interpolating user data
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let limit = query.max_results.unwrap_or(100).min(1000);
    let offset = query.first_result.unwrap_or(0);

    // SECURITY NOTE: Using format! here is safe because:
    // - where_clause contains only SQL structure with $N placeholders
    // - param_index values are integers generated internally
    // - All user data goes through parameterized queries (params vector)
    let query_sql = format!(
        r#"
            SELECT
                id, time, event_type, realm_id, realm_name, client_id,
                user_id, session_id, ip_address, error, details
            FROM events
            {}
            ORDER BY time DESC
            LIMIT ${} OFFSET ${}
            "#,
        where_clause,
        param_index,
        param_index + 1
    );

    params.push(Box::new(limit as i64));
    params.push(Box::new(offset as i64));

    let param_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params
        .iter()
        .map(|p| &**p as &(dyn tokio_postgres::types::ToSql + Sync))
        .collect();

    let rows: Vec<tokio_postgres::Row> = db
        .query(&query_sql, param_refs.as_slice())
        .await
        .map_err(|e| {
            error!("Failed to query events: {}", e);
            AuthencError::database("Failed to query events")
        })?;

    let mut events = Vec::new();
    for row in rows {
        // OPTIMIZATION: Parse directly from JSONB binary to HashMap using custom wrapper
        // This avoids intermediate String allocation AND intermediate Value structure
        let details: HashMap<String, String> = row
            .try_get::<_, Json<HashMap<String, String>>>(10)
            .map(|json| json.0)
            .unwrap_or_default();

        events.push(Event {
            id: row.get::<_, Uuid>(0).to_string(),
            time: row.get(1),
            event_type: EventType::from_str(&row.get::<_, String>(2)).unwrap_or(EventType::Login),
            realm_id: row.get(3),
            realm_name: row.get(4),
            client_id: row.get(5),
            user_id: row.get(6),
            session_id: row.get(7),
            ip_address: row.get(8),
            error: row.get(9),
            details,
        });
    }

    Ok(events)
}

/// Query admin events based on the provided query parameters
pub async fn query_admin_events(db: &Database, query: &AdminEventQuery) -> Result<Vec<AdminEvent>> {
    let mut conditions = Vec::new();
    let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
    let mut param_index = 1;

    // Build WHERE conditions
    if let Some(realm_id) = &query.realm_id {
        conditions.push(format!("realm_id = ${}", param_index));
        params.push(Box::new(realm_id.clone()));
        param_index += 1;
    }

    if let Some(auth_user_id) = &query.auth_user_id {
        conditions.push(format!("auth_user_id = ${}", param_index));
        params
            .push(Box::new(Uuid::parse_str(auth_user_id).map_err(|_| {
                AuthencError::validation("Invalid auth user ID")
            })?));
        param_index += 1;
    }

    if let Some(resource_type) = &query.resource_type {
        conditions.push(format!("resource_type = ${}", param_index));
        params.push(Box::new(resource_type.as_str()));
        param_index += 1;
    }

    if let Some(operation_type) = &query.operation_type {
        conditions.push(format!("operation_type = ${}", param_index));
        params.push(Box::new(match operation_type {
            AdminEventOperationType::Create => "CREATE",
            AdminEventOperationType::Update => "UPDATE",
            AdminEventOperationType::Delete => "DELETE",
            AdminEventOperationType::Action => "ACTION",
        }));
        param_index += 1;
    }

    if let Some(from_date) = &query.date_from {
        conditions.push(format!("time >= ${}", param_index));
        params.push(Box::new(*from_date));
        param_index += 1;
    }

    if let Some(to_date) = &query.date_to {
        conditions.push(format!("time <= ${}", param_index));
        params.push(Box::new(*to_date));
        param_index += 1;
    }

    if let Some(resource_path) = &query.resource_type {
        conditions.push(format!("resource_path LIKE ${}", param_index));
        params.push(Box::new(format!("%{}%", resource_path)));
        param_index += 1;
    }

    // SECURITY: This is SAFE from SQL injection because:
    // 1. The where_clause only contains parameterized query placeholders ($1, $2, etc.)
    // 2. Actual user data is passed via params vector and properly escaped by tokio_postgres
    // 3. The format! is only building query structure, NOT interpolating user data
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let limit = query.max_results.unwrap_or(100).min(1000);
    let offset = query.first_result.unwrap_or(0);

    // SECURITY NOTE: Using format! here is safe because:
    // - where_clause contains only SQL structure with $N placeholders
    // - param_index values are integers generated internally
    // - All user data goes through parameterized queries (params vector)
    let query_sql = format!(
        r#"
            SELECT
                id, time, realm_id, realm_name, auth_user_id, auth_username,
                auth_ip_address, auth_user_agent, resource_type, operation_type,
                resource_path, representation, error
            FROM admin_events
            {}
            ORDER BY time DESC
            LIMIT ${} OFFSET ${}
            "#,
        where_clause,
        param_index,
        param_index + 1
    );

    params.push(Box::new(limit as i64));
    params.push(Box::new(offset as i64));

    let param_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params
        .iter()
        .map(|p| &**p as &(dyn tokio_postgres::types::ToSql + Sync))
        .collect();

    let rows: Vec<tokio_postgres::Row> = db
        .query(&query_sql, param_refs.as_slice())
        .await
        .map_err(|e| {
            error!("Failed to query admin events: {}", e);
            AuthencError::database("Failed to query admin events")
        })?;

    let mut events = Vec::new();
    for row in rows {
        events.push(AdminEvent {
            id: row.get::<_, Uuid>(0).to_string(),
            time: row.get(1),
            realm_id: row.get(2),
            realm_name: row.get(3),
            auth_details: AuthDetails {
                user_id: row
                    .get::<_, Option<Uuid>>(4)
                    .map(|id| id.to_string())
                    .unwrap_or_default(),
                username: row.get(5),
                ip_address: row.get(6),
                user_agent: row.get(7),
            },
            resource_type: ResourceType::from_str(&row.get::<_, String>(8))
                .unwrap_or(ResourceType::User),
            operation_type: OperationType::from_str(&row.get::<_, String>(9))
                .unwrap_or(OperationType::Create),
            resource_path: row.get(10),
            representation: row.get(11),
            error: row.get(12),
        });
    }

    Ok(events)
}

/// Clear old events based on retention policy
pub async fn clear_old_events(db: &Database, retention_days: i32) -> Result<i64> {
    let query = "DELETE FROM events WHERE time < NOW() - INTERVAL '1 day' * $1";

    let deleted = db.execute(query, &[&retention_days]).await.map_err(|e| {
        error!("Failed to clear old events: {}", e);
        AuthencError::database("Failed to clear old events")
    })?;

    Ok(deleted as i64)
}

/// Clear old admin events based on retention policy
pub async fn clear_old_admin_events(db: &Database, retention_days: i32) -> Result<i64> {
    let query = "DELETE FROM admin_events WHERE time < NOW() - INTERVAL '1 day' * $1";

    let deleted = db.execute(query, &[&retention_days]).await.map_err(|e| {
        error!("Failed to clear old admin events: {}", e);
        AuthencError::database("Failed to clear old admin events")
    })?;

    Ok(deleted as i64)
}

// ============================================================================
// TOKEN MANAGEMENT OPERATIONS
// ============================================================================

/// Database operations for OAuth2 token management
pub mod tokens {
    use crate::database::Database;
    use authenc_core::error::Result;
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    /// Stored access token data
    #[derive(Debug, Clone)]
    pub struct AccessTokenData {
        /// Unique identifier for the access token
        pub id: Uuid,
        /// Hash of the access token
        pub token_hash: String,
        /// Hash of the associated refresh token
        pub refresh_token_hash: Option<String>,
        /// ID of the OAuth client
        pub client_id: Uuid,
        /// ID of the user (None for client credentials flow)
        pub user_id: Option<Uuid>,
        /// OAuth scopes granted to the token
        pub scopes: Vec<String>,
        /// Expiration timestamp of the token
        pub expires_at: DateTime<Utc>,
        /// Expiration timestamp of the refresh token
        pub refresh_expires_at: Option<DateTime<Utc>>,
        /// Whether the token has been revoked
        pub revoked: bool,
        /// Timestamp when the token was revoked
        pub revoked_at: Option<DateTime<Utc>>,
        /// Timestamp when the token was created
        pub created_at: DateTime<Utc>,
        /// Timestamp when the token was last used
        pub last_used_at: Option<DateTime<Utc>>,
        /// Session identifier (if bound to a session)
        pub session_id: Option<String>,
    }

    /// Create new access token in database
    #[allow(clippy::too_many_arguments)]
    pub async fn create_access_token(
        db: &Database,
        token_hash: &str,
        refresh_token_hash: Option<&str>,
        client_id: Uuid,
        user_id: Option<Uuid>,
        scopes: Vec<String>,
        expires_at: DateTime<Utc>,
        refresh_expires_at: Option<DateTime<Utc>>,
        session_id: Option<String>,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();

        let query = "
            INSERT INTO oauth2_access_tokens (
                id, token_hash, refresh_token_hash, client_id, user_id, scopes,
                expires_at, refresh_expires_at, created_at, session_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), $9)
        ";

        db.execute(
            query,
            &[
                &id,
                &token_hash,
                &refresh_token_hash,
                &client_id,
                &user_id,
                &scopes,
                &expires_at,
                &refresh_expires_at,
                &session_id,
            ],
        )
        .await?;

        Ok(id)
    }

    /// Get access token by hash
    pub async fn get_access_token(
        db: &Database,
        token_hash: &str,
    ) -> Result<Option<AccessTokenData>> {
        let query = "
            SELECT id, token_hash, refresh_token_hash, client_id, user_id, scopes,
                   expires_at, refresh_expires_at, revoked, revoked_at, created_at, last_used_at, session_id
            FROM oauth2_access_tokens
            WHERE token_hash = $1
        ";

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&token_hash]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = &rows[0];
        Ok(Some(AccessTokenData {
            id: row.get(0),
            token_hash: row.get(1),
            refresh_token_hash: row.get(2),
            client_id: row.get(3),
            user_id: row.get(4),
            scopes: row.get(5),
            expires_at: row.get(6),
            refresh_expires_at: row.get(7),
            revoked: row.get(8),
            revoked_at: row.get(9),
            created_at: row.get(10),
            last_used_at: row.get(11),
            session_id: row.get(12),
        }))
    }

    /// Get access token by refresh token hash
    pub async fn get_token_by_refresh(
        db: &Database,
        refresh_token_hash: &str,
    ) -> Result<Option<AccessTokenData>> {
        let query = "
            SELECT id, token_hash, refresh_token_hash, client_id, user_id, scopes,
                   expires_at, refresh_expires_at, revoked, revoked_at, created_at, last_used_at, session_id
            FROM oauth2_access_tokens
            WHERE refresh_token_hash = $1
        ";

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&refresh_token_hash]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = &rows[0];
        Ok(Some(AccessTokenData {
            id: row.get(0),
            token_hash: row.get(1),
            refresh_token_hash: row.get(2),
            client_id: row.get(3),
            user_id: row.get(4),
            scopes: row.get(5),
            expires_at: row.get(6),
            refresh_expires_at: row.get(7),
            revoked: row.get(8),
            revoked_at: row.get(9),
            created_at: row.get(10),
            last_used_at: row.get(11),
            session_id: row.get(12),
        }))
    }

    /// Update last_used_at timestamp for token
    pub async fn update_token_last_used(db: &Database, token_hash: &str) -> Result<()> {
        let query = "
            UPDATE oauth2_access_tokens
            SET last_used_at = NOW()
            WHERE token_hash = $1
        ";

        db.execute(query, &[&token_hash]).await?;
        Ok(())
    }

    /// Revoke access token
    pub async fn revoke_access_token(db: &Database, token_hash: &str) -> Result<()> {
        let query = "
            UPDATE oauth2_access_tokens
            SET revoked = true, revoked_at = NOW()
            WHERE token_hash = $1 AND revoked = false
        ";

        db.execute(query, &[&token_hash]).await?;
        Ok(())
    }

    /// Revoke all tokens for a user
    pub async fn revoke_user_tokens(db: &Database, user_id: Uuid) -> Result<u64> {
        let query = "
            UPDATE oauth2_access_tokens
            SET revoked = true, revoked_at = NOW()
            WHERE user_id = $1 AND revoked = false
        ";

        let rows_affected = db.execute(query, &[&user_id]).await?;
        Ok(rows_affected)
    }

    /// Revoke all tokens for a client
    pub async fn revoke_client_tokens(db: &Database, client_id: Uuid) -> Result<u64> {
        let query = "
            UPDATE oauth2_access_tokens
            SET revoked = true, revoked_at = NOW()
            WHERE client_id = $1 AND revoked = false
        ";

        let rows_affected = db.execute(query, &[&client_id]).await?;
        Ok(rows_affected)
    }

    /// Get active tokens for a user
    pub async fn get_user_active_tokens(
        db: &Database,
        user_id: Uuid,
    ) -> Result<Vec<AccessTokenData>> {
        let query = "
            SELECT id, token_hash, refresh_token_hash, client_id, user_id, scopes,
                   expires_at, refresh_expires_at, revoked, revoked_at, created_at, last_used_at, session_id
            FROM oauth2_access_tokens
            WHERE user_id = $1
              AND revoked = false
              AND expires_at > NOW()
            ORDER BY created_at DESC
        ";

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&user_id]).await?;

        let mut tokens = Vec::new();
        for row in rows {
            tokens.push(AccessTokenData {
                id: row.get(0),
                token_hash: row.get(1),
                refresh_token_hash: row.get(2),
                client_id: row.get(3),
                user_id: row.get(4),
                scopes: row.get(5),
                expires_at: row.get(6),
                refresh_expires_at: row.get(7),
                revoked: row.get(8),
                revoked_at: row.get(9),
                created_at: row.get(10),
                last_used_at: row.get(11),
                session_id: row.get(12),
            });
        }

        Ok(tokens)
    }

    /// Delete expired tokens (cleanup operation)
    pub async fn delete_expired_tokens(db: &Database) -> Result<u64> {
        let query = "
            DELETE FROM oauth2_access_tokens
            WHERE expires_at < NOW()
              AND (refresh_expires_at IS NULL OR refresh_expires_at < NOW())
        ";

        let rows_affected = db.execute(query, &[]).await?;
        Ok(rows_affected)
    }

    /// Get token count statistics
    pub async fn get_token_statistics(db: &Database) -> Result<TokenStatistics> {
        let query = "
            SELECT
                COUNT(*) FILTER (WHERE revoked = false AND expires_at > NOW()) as active_tokens,
                COUNT(*) FILTER (WHERE revoked = true) as revoked_tokens,
                COUNT(*) FILTER (WHERE expires_at < NOW()) as expired_tokens,
                COUNT(*) as total_tokens
            FROM oauth2_access_tokens
        ";

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[]).await?;
        if rows.is_empty() {
            return Ok(TokenStatistics {
                active_tokens: 0,
                revoked_tokens: 0,
                expired_tokens: 0,
                total_tokens: 0,
            });
        }

        let row = &rows[0];
        Ok(TokenStatistics {
            active_tokens: row.get::<_, i64>(0) as u64,
            revoked_tokens: row.get::<_, i64>(1) as u64,
            expired_tokens: row.get::<_, i64>(2) as u64,
            total_tokens: row.get::<_, i64>(3) as u64,
        })
    }

    /// Token statistics
    #[derive(Debug, Clone)]
    pub struct TokenStatistics {
        /// Number of currently active tokens
        pub active_tokens: u64,
        /// Number of revoked tokens
        pub revoked_tokens: u64,
        /// Number of expired tokens
        pub expired_tokens: u64,
        /// Total number of tokens
        pub total_tokens: u64,
    }
}

/// Database operations for permission tickets
pub mod permission_tickets {
    use crate::database::Database;
    use authenc_core::error::{AuthencError, Result};
    use authenc_models::models::permission_ticket::{
        CreatePermissionTicketRequest, PermissionTicket, PermissionTicketFilter,
    };
    use chrono::Utc;
    use log::error;
    use uuid::Uuid;

    /// Create a new permission ticket
    pub async fn create_permission_ticket(
        db: &Database,
        request: CreatePermissionTicketRequest,
        owner: String,
        realm_id: Uuid,
        resource_server_id: Uuid,
    ) -> Result<PermissionTicket> {
        let ticket_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO permission_tickets (
                id, resource_id, scope_id, owner, requester, granted,
                granted_timestamp, realm_id, resource_server_id,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING
                id, resource_id, scope_id, owner, requester, granted,
                granted_timestamp, realm_id, resource_server_id,
                created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &ticket_id,
                    &request.resource_id,
                    &request.scope_id,
                    &owner,
                    &request.requester,
                    &false,                         // granted
                    &None::<chrono::DateTime<Utc>>, // granted_timestamp
                    &realm_id,
                    &resource_server_id,
                    &now,
                    &now,
                ],
            )
            .await
            .map_err(|e| {
                error!("Failed to create permission ticket: {}", e);
                AuthencError::database(format!("Failed to create permission ticket: {}", e))
            })?;

        row.try_into()
    }

    /// Get permission ticket by ID
    pub async fn get_permission_ticket(
        db: &Database,
        id: Uuid,
    ) -> Result<Option<PermissionTicket>> {
        let query = r#"
            SELECT
                id, resource_id, scope_id, owner, requester, granted,
                granted_timestamp, realm_id, resource_server_id,
                created_at, updated_at
            FROM permission_tickets
            WHERE id = $1
        "#;

        match db.query_opt(query, &[&id]).await {
            Ok(Some(row)) => Ok(Some(row.try_into()?)),
            Ok(None) => Ok(None),
            Err(e) => {
                error!("Failed to get permission ticket: {}", e);
                Err(AuthencError::database(format!(
                    "Failed to get permission ticket: {}",
                    e
                )))
            }
        }
    }

    /// Get permission tickets with filters
    pub async fn get_permission_tickets(
        db: &Database,
        filters: Vec<PermissionTicketFilter>,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<PermissionTicket>> {
        let offset = first.unwrap_or(0);
        let limit = max.unwrap_or(100);

        let mut conditions = Vec::new();
        let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = Vec::new();
        let mut param_index = 1;

        for filter in &filters {
            match filter {
                PermissionTicketFilter::Owner(owner) => {
                    conditions.push(format!("owner = ${}", param_index));
                    params.push(owner);
                    param_index += 1;
                }
                PermissionTicketFilter::Requester(requester) => {
                    conditions.push(format!("requester = ${}", param_index));
                    params.push(requester);
                    param_index += 1;
                }
                PermissionTicketFilter::ResourceId(resource_id) => {
                    conditions.push(format!("resource_id = ${}", param_index));
                    params.push(resource_id);
                    param_index += 1;
                }
                PermissionTicketFilter::Granted(granted) => {
                    conditions.push(format!("granted = ${}", param_index));
                    params.push(granted);
                    param_index += 1;
                }
                PermissionTicketFilter::ResourceServerId(resource_server_id) => {
                    conditions.push(format!("resource_server_id = ${}", param_index));
                    params.push(resource_server_id);
                    param_index += 1;
                }
            }
        }

        let where_clause = if conditions.is_empty() {
            String::from("TRUE")
        } else {
            conditions.join(" AND ")
        };

        let limit_i64 = limit as i64;
        let offset_i64 = offset as i64;

        let query = format!(
            r#"
            SELECT
                id, resource_id, scope_id, owner, requester, granted,
                granted_timestamp, realm_id, resource_server_id,
                created_at, updated_at
            FROM permission_tickets
            WHERE {}
            ORDER BY created_at DESC
            LIMIT ${} OFFSET ${}
            "#,
            where_clause,
            param_index,
            param_index + 1
        );

        params.push(&limit_i64);
        params.push(&offset_i64);

        let rows = db.query(&query, &params).await?;
        rows.into_iter()
            .map(|row: tokio_postgres::Row| row.try_into())
            .collect::<Result<Vec<PermissionTicket>>>()
    }

    /// Get granted resources for a user
    pub async fn get_granted_resources(
        db: &Database,
        user_id: &str,
        name_filter: Option<&str>,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Uuid>> {
        let offset = first.unwrap_or(0);
        let limit = max.unwrap_or(100);

        let query = if let Some(name_pattern) = name_filter {
            let _pattern = format!("%{}%", name_pattern);
            r#"
                SELECT DISTINCT pt.resource_id
                FROM permission_tickets pt
                JOIN resources r ON pt.resource_id = r.id
                WHERE pt.requester = $1 AND pt.granted = true
                  AND r.name ILIKE $2
                ORDER BY pt.resource_id
                LIMIT $3 OFFSET $4
            "#
        } else {
            r#"
                SELECT DISTINCT resource_id
                FROM permission_tickets
                WHERE requester = $1 AND granted = true
                ORDER BY resource_id
                LIMIT $2 OFFSET $3
            "#
        };

        let rows = if name_filter.is_some() {
            let pattern = format!("%{}%", name_filter.unwrap());
            db.query(
                query,
                &[&user_id, &pattern, &(limit as i64), &(offset as i64)],
            )
            .await?
        } else {
            db.query(query, &[&user_id, &(limit as i64), &(offset as i64)])
                .await?
        };

        Ok(rows
            .into_iter()
            .map(|row: tokio_postgres::Row| row.get(0))
            .collect())
    }

    /// Get granted owner resources
    pub async fn get_granted_owner_resources(
        db: &Database,
        owner: &str,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Uuid>> {
        let offset = first.unwrap_or(0);
        let limit = max.unwrap_or(100);

        let query = r#"
            SELECT DISTINCT resource_id
            FROM permission_tickets
            WHERE owner = $1 AND granted = true
            ORDER BY resource_id
            LIMIT $2 OFFSET $3
        "#;

        let rows = db
            .query(query, &[&owner, &(limit as i64), &(offset as i64)])
            .await?;
        Ok(rows
            .into_iter()
            .map(|row: tokio_postgres::Row| row.get::<_, Uuid>(0))
            .collect())
    }

    /// Get permission tickets for resource
    pub async fn get_tickets_for_resource(
        db: &Database,
        resource_id: Uuid,
        granted: Option<bool>,
    ) -> Result<Vec<PermissionTicket>> {
        let query = if let Some(_granted_filter) = granted {
            r#"
                SELECT
                    id, resource_id, scope_id, owner, requester, granted,
                    granted_timestamp, realm_id, resource_server_id,
                    created_at, updated_at
                FROM permission_tickets
                WHERE resource_id = $1 AND granted = $2
                ORDER BY created_at DESC
            "#
        } else {
            r#"
                SELECT
                    id, resource_id, scope_id, owner, requester, granted,
                    granted_timestamp, realm_id, resource_server_id,
                    created_at, updated_at
                FROM permission_tickets
                WHERE resource_id = $1
                ORDER BY created_at DESC
            "#
        };

        let rows = if let Some(granted_filter) = granted {
            db.query(query, &[&resource_id, &granted_filter]).await?
        } else {
            db.query(query, &[&resource_id]).await?
        };

        rows.into_iter()
            .map(|row: tokio_postgres::Row| row.try_into())
            .collect::<Result<Vec<PermissionTicket>>>()
    }

    /// Get permission tickets for requester
    pub async fn get_tickets_for_requester(
        db: &Database,
        requester: &str,
        granted: Option<bool>,
    ) -> Result<Vec<PermissionTicket>> {
        let query = if let Some(_granted_filter) = granted {
            r#"
                SELECT
                    id, resource_id, scope_id, owner, requester, granted,
                    granted_timestamp, realm_id, resource_server_id,
                    created_at, updated_at
                FROM permission_tickets
                WHERE requester = $1 AND granted = $2
                ORDER BY created_at DESC
            "#
        } else {
            r#"
                SELECT
                    id, resource_id, scope_id, owner, requester, granted,
                    granted_timestamp, realm_id, resource_server_id,
                    created_at, updated_at
                FROM permission_tickets
                WHERE requester = $1
                ORDER BY created_at DESC
            "#
        };

        let rows = if let Some(granted_filter) = granted {
            db.query(query, &[&requester, &granted_filter]).await?
        } else {
            db.query(query, &[&requester]).await?
        };

        rows.into_iter()
            .map(|row: tokio_postgres::Row| row.try_into())
            .collect::<Result<Vec<PermissionTicket>>>()
    }

    /// Grant permission ticket
    pub async fn grant_permission_ticket(db: &Database, id: Uuid) -> Result<PermissionTicket> {
        let now = Utc::now();

        let query = r#"
            UPDATE permission_tickets
            SET granted = true, granted_timestamp = $2, updated_at = $3
            WHERE id = $1
            RETURNING
                id, resource_id, scope_id, owner, requester, granted,
                granted_timestamp, realm_id, resource_server_id,
                created_at, updated_at
        "#;

        let row = db
            .query_opt(query, &[&id, &now, &now])
            .await
            .map_err(|e| {
                error!("Failed to grant permission ticket: {}", e);
                AuthencError::database(format!("Failed to grant permission ticket: {}", e))
            })?
            .ok_or_else(|| {
                AuthencError::resource_not_found(format!("Permission ticket {} not found", id))
            })?;

        row.try_into()
    }

    /// Revoke permission ticket
    pub async fn revoke_permission_ticket(db: &Database, id: Uuid) -> Result<PermissionTicket> {
        let now = Utc::now();

        let query = r#"
            UPDATE permission_tickets
            SET granted = false, granted_timestamp = NULL, updated_at = $2
            WHERE id = $1
            RETURNING
                id, resource_id, scope_id, owner, requester, granted,
                granted_timestamp, realm_id, resource_server_id,
                created_at, updated_at
        "#;

        let row = db
            .query_opt(query, &[&id, &now])
            .await
            .map_err(|e| {
                error!("Failed to revoke permission ticket: {}", e);
                AuthencError::database(format!("Failed to revoke permission ticket: {}", e))
            })?
            .ok_or_else(|| {
                AuthencError::resource_not_found(format!("Permission ticket {} not found", id))
            })?;

        row.try_into()
    }

    /// Delete permission ticket
    pub async fn delete_permission_ticket(db: &Database, id: Uuid) -> Result<()> {
        let query = "DELETE FROM permission_tickets WHERE id = $1";

        let rows_affected = db.execute(query, &[&id]).await?;

        if rows_affected == 0 {
            return Err(AuthencError::resource_not_found(format!(
                "Permission ticket {} not found",
                id
            )));
        }

        Ok(())
    }

    /// Count permission tickets with filters
    pub async fn count_permission_tickets(
        db: &Database,
        filters: Vec<PermissionTicketFilter>,
    ) -> Result<i64> {
        let mut conditions = Vec::new();
        let mut params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = Vec::new();
        let mut param_index = 1;

        for filter in &filters {
            match filter {
                PermissionTicketFilter::Owner(owner) => {
                    conditions.push(format!("owner = ${}", param_index));
                    params.push(owner);
                    param_index += 1;
                }
                PermissionTicketFilter::Requester(requester) => {
                    conditions.push(format!("requester = ${}", param_index));
                    params.push(requester);
                    param_index += 1;
                }
                PermissionTicketFilter::ResourceId(resource_id) => {
                    conditions.push(format!("resource_id = ${}", param_index));
                    params.push(resource_id);
                    param_index += 1;
                }
                PermissionTicketFilter::Granted(granted) => {
                    conditions.push(format!("granted = ${}", param_index));
                    params.push(granted);
                    param_index += 1;
                }
                PermissionTicketFilter::ResourceServerId(resource_server_id) => {
                    conditions.push(format!("resource_server_id = ${}", param_index));
                    params.push(resource_server_id);
                    param_index += 1;
                }
            }
        }

        let where_clause = if conditions.is_empty() {
            String::from("TRUE")
        } else {
            conditions.join(" AND ")
        };

        let query = format!(
            "SELECT COUNT(*) FROM permission_tickets WHERE {}",
            where_clause
        );

        let row: tokio_postgres::Row = db.query_one(&query, &params).await?;
        Ok(row.get(0))
    }
}

/// Database operations for scopes
pub mod scopes {
    use crate::database::Database;
    use authenc_core::error::{AuthencError, Result};
    use authenc_models::models::scope::{CreateScopeRequest, Scope, UpdateScopeRequest};
    use chrono::Utc;
    use log::error;
    use uuid::Uuid;

    /// Create a new scope
    pub async fn create_scope(
        db: &Database,
        request: CreateScopeRequest,
        realm_id: Uuid,
        resource_server_id: Uuid,
    ) -> Result<Scope> {
        let scope_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO scopes (
                id, name, display_name, icon_uri, realm_id, resource_server_id,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING
                id, name, display_name, icon_uri, realm_id, resource_server_id,
                created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &scope_id,
                    &request.name,
                    &request.display_name,
                    &request.icon_uri,
                    &realm_id,
                    &resource_server_id,
                    &now,
                    &now,
                ],
            )
            .await
            .map_err(|e| {
                error!("Failed to create scope: {}", e);
                AuthencError::database(format!("Failed to create scope: {}", e))
            })?;

        row.try_into()
    }

    /// Get scope by ID
    pub async fn get_scope_by_id(db: &Database, id: Uuid) -> Result<Option<Scope>> {
        let query = r#"
            SELECT
                id, name, display_name, icon_uri, realm_id, resource_server_id,
                created_at, updated_at
            FROM scopes
            WHERE id = $1
        "#;

        match db.query_opt(query, &[&id]).await {
            Ok(Some(row)) => Ok(Some(row.try_into()?)),
            Ok(None) => Ok(None),
            Err(e) => {
                error!("Failed to get scope: {}", e);
                Err(AuthencError::database(format!(
                    "Failed to get scope: {}",
                    e
                )))
            }
        }
    }

    /// Get scope by name and resource server
    pub async fn get_scope_by_name(
        db: &Database,
        name: &str,
        resource_server_id: Uuid,
    ) -> Result<Option<Scope>> {
        let query = r#"
            SELECT
                id, name, display_name, icon_uri, realm_id, resource_server_id,
                created_at, updated_at
            FROM scopes
            WHERE name = $1 AND resource_server_id = $2
        "#;

        match db.query_opt(query, &[&name, &resource_server_id]).await {
            Ok(Some(row)) => Ok(Some(row.try_into()?)),
            Ok(None) => Ok(None),
            Err(e) => {
                error!("Failed to get scope by name: {}", e);
                Err(AuthencError::database(format!(
                    "Failed to get scope by name: {}",
                    e
                )))
            }
        }
    }

    /// Get scopes by resource server
    pub async fn get_scopes_by_server(
        db: &Database,
        resource_server_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Scope>> {
        let offset = first.unwrap_or(0);
        let limit = max.unwrap_or(100);

        let query = r#"
            SELECT
                id, name, display_name, icon_uri, realm_id, resource_server_id,
                created_at, updated_at
            FROM scopes
            WHERE resource_server_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
        "#;

        let rows = db
            .query(
                query,
                &[&resource_server_id, &(limit as i64), &(offset as i64)],
            )
            .await?;
        rows.into_iter()
            .map(|row: tokio_postgres::Row| row.try_into())
            .collect::<Result<Vec<Scope>>>()
    }

    /// Get scopes by realm
    pub async fn get_scopes_by_realm(
        db: &Database,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Scope>> {
        let offset = first.unwrap_or(0);
        let limit = max.unwrap_or(100);

        let query = r#"
            SELECT
                id, name, display_name, icon_uri, realm_id, resource_server_id,
                created_at, updated_at
            FROM scopes
            WHERE realm_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
        "#;

        let rows = db
            .query(query, &[&realm_id, &(limit as i64), &(offset as i64)])
            .await?;
        rows.into_iter()
            .map(|row: tokio_postgres::Row| row.try_into())
            .collect::<Result<Vec<Scope>>>()
    }

    /// Update scope
    pub async fn update_scope(
        db: &Database,
        id: Uuid,
        request: UpdateScopeRequest,
    ) -> Result<Scope> {
        let now = Utc::now();

        let query = r#"
            UPDATE scopes
            SET
                name = COALESCE($2, name),
                display_name = COALESCE($3, display_name),
                icon_uri = COALESCE($4, icon_uri),
                updated_at = $5
            WHERE id = $1
            RETURNING
                id, name, display_name, icon_uri, realm_id, resource_server_id,
                created_at, updated_at
        "#;

        let row = db
            .query_opt(
                query,
                &[
                    &id,
                    &request.name,
                    &request.display_name,
                    &request.icon_uri,
                    &now,
                ],
            )
            .await
            .map_err(|e| {
                error!("Failed to update scope: {}", e);
                AuthencError::database(format!("Failed to update scope: {}", e))
            })?
            .ok_or_else(|| AuthencError::resource_not_found(format!("Scope {} not found", id)))?;

        row.try_into()
    }

    /// Delete scope
    pub async fn delete_scope(db: &Database, id: Uuid) -> Result<()> {
        let query = "DELETE FROM scopes WHERE id = $1";

        let rows_affected = db.execute(query, &[&id]).await?;

        if rows_affected == 0 {
            return Err(AuthencError::resource_not_found(format!(
                "Scope {} not found",
                id
            )));
        }

        Ok(())
    }

    /// Search scopes by name
    pub async fn search_scopes(
        db: &Database,
        name_pattern: &str,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<Scope>> {
        let offset = first.unwrap_or(0);
        let limit = max.unwrap_or(100);
        let pattern = format!("%{}%", name_pattern);

        let query = r#"
            SELECT
                id, name, display_name, icon_uri, realm_id, resource_server_id,
                created_at, updated_at
            FROM scopes
            WHERE realm_id = $1 AND (name ILIKE $2 OR display_name ILIKE $2)
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
        "#;

        let rows = db
            .query(
                query,
                &[&realm_id, &pattern, &(limit as i64), &(offset as i64)],
            )
            .await?;
        rows.into_iter()
            .map(|row: tokio_postgres::Row| row.try_into())
            .collect::<Result<Vec<Scope>>>()
    }

    /// Count scopes by resource server
    pub async fn count_scopes_by_server(db: &Database, resource_server_id: Uuid) -> Result<i64> {
        let query = "SELECT COUNT(*) FROM scopes WHERE resource_server_id = $1";

        let row: tokio_postgres::Row = db.query_one(query, &[&resource_server_id]).await?;
        Ok(row.get(0))
    }
}

/// Resource server operations
pub mod resource_servers {
    use authenc_core::error::Result;

    use authenc_models::models::resource_server::{CreateResourceServerRequest, ResourceServer, UpdateResourceServerRequest};
    use crate::database::Database;
    use uuid::Uuid;

    /// Create a new resource server
    pub async fn create_resource_server(
        db: &Database,
        request: CreateResourceServerRequest,
        realm_id: Uuid,
    ) -> Result<ResourceServer> {
        let id = Uuid::new_v4();
        let now = chrono::Utc::now();

        let query = r#"
            INSERT INTO resource_servers (
                id, client_id, name, description, enabled, realm_id,
                policy_enforcement_mode, decision_strategy, allow_remote_resource_management,
                created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING
                id, client_id, name, description, enabled, realm_id,
                policy_enforcement_mode, decision_strategy, allow_remote_resource_management,
                created_at, updated_at
        "#;

        let policy_mode = "enforcing"; // Default
        let decision_strat = "unanimous"; // Default

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &id,
                    &request.client_id,
                    &request.name,
                    &request.description,
                    &true, // enabled by default
                    &realm_id,
                    &policy_mode,
                    &decision_strat,
                    &false, // allow_remote_resource_management default
                    &now,
                    &now,
                ],
            )
            .await?;

        row.try_into()
    }

    /// Get resource server by ID
    pub async fn get_resource_server_by_id(
        db: &Database,
        id: Uuid,
    ) -> Result<Option<ResourceServer>> {
        let query = r#"
            SELECT
                id, client_id, name, description, enabled, realm_id,
                policy_enforcement_mode, decision_strategy, allow_remote_resource_management,
                created_at, updated_at
            FROM resource_servers
            WHERE id = $1
        "#;

        match db.query_opt(query, &[&id]).await? {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    /// Get resource server by client ID and realm
    pub async fn get_resource_server_by_client(
        db: &Database,
        client_id: &str,
        realm_id: Uuid,
    ) -> Result<Option<ResourceServer>> {
        let query = r#"
            SELECT
                id, client_id, name, description, enabled, realm_id,
                policy_enforcement_mode, decision_strategy, allow_remote_resource_management,
                created_at, updated_at
            FROM resource_servers
            WHERE client_id = $1 AND realm_id = $2
        "#;

        match db.query_opt(query, &[&client_id, &realm_id]).await? {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    /// List resource servers by realm
    pub async fn get_resource_servers_by_realm(
        db: &Database,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<ResourceServer>> {
        let offset = first.unwrap_or(0);
        let limit = max.unwrap_or(100);

        let query = r#"
            SELECT
                id, client_id, name, description, enabled, realm_id,
                policy_enforcement_mode, decision_strategy, allow_remote_resource_management,
                created_at, updated_at
            FROM resource_servers
            WHERE realm_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
        "#;

        let rows = db
            .query(query, &[&realm_id, &(limit as i64), &(offset as i64)])
            .await?;
        rows.into_iter()
            .map(|row: tokio_postgres::Row| row.try_into())
            .collect::<Result<Vec<ResourceServer>>>()
    }

    /// Update resource server
    pub async fn update_resource_server(
        db: &Database,
        id: Uuid,
        request: UpdateResourceServerRequest,
    ) -> Result<ResourceServer> {
        let now = chrono::Utc::now();

        let query = r#"
            UPDATE resource_servers
            SET
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                policy_enforcement_mode = COALESCE($4, policy_enforcement_mode),
                decision_strategy = COALESCE($5, decision_strategy),
                allow_remote_resource_management = COALESCE($6, allow_remote_resource_management),
                updated_at = $7
            WHERE id = $1
            RETURNING
                id, client_id, name, description, enabled, realm_id,
                policy_enforcement_mode, decision_strategy, allow_remote_resource_management,
                created_at, updated_at
        "#;

        let policy_mode = request.policy_enforcement_mode.as_ref().map(|m| m.as_str());
        let decision_strat = request.decision_strategy.as_ref().map(|s| s.as_str());

        match db
            .query_opt(
                query,
                &[
                    &id,
                    &request.name,
                    &request.description,
                    &policy_mode,
                    &decision_strat,
                    &request.allow_remote_resource_management,
                    &now,
                ],
            )
            .await?
        {
            Some(row) => row.try_into(),
            None => Err(authenc_core::error::AuthencError::resource_not_found(format!(
                "Resource server with id {} not found",
                id
            ))),
        }
    }

    /// Delete resource server
    pub async fn delete_resource_server(db: &Database, id: Uuid) -> Result<()> {
        let query = "DELETE FROM resource_servers WHERE id = $1";

        let rows_affected = db.execute(query, &[&id]).await?;

        if rows_affected == 0 {
            return Err(authenc_core::error::AuthencError::resource_not_found(format!(
                "Resource server with id {} not found",
                id
            )));
        }

        Ok(())
    }

    /// Search resource servers by name pattern
    pub async fn search_resource_servers(
        db: &Database,
        name_pattern: &str,
        realm_id: Uuid,
        first: Option<i32>,
        max: Option<i32>,
    ) -> Result<Vec<ResourceServer>> {
        let offset = first.unwrap_or(0);
        let limit = max.unwrap_or(100);
        let pattern = format!("%{}%", name_pattern);

        let query = r#"
            SELECT
                id, client_id, name, description, enabled, realm_id,
                policy_enforcement_mode, decision_strategy, allow_remote_resource_management,
                created_at, updated_at
            FROM resource_servers
            WHERE realm_id = $1 AND (name ILIKE $2 OR client_id ILIKE $2)
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
        "#;

        let rows = db
            .query(
                query,
                &[&realm_id, &pattern, &(limit as i64), &(offset as i64)],
            )
            .await?;
        rows.into_iter()
            .map(|row: tokio_postgres::Row| row.try_into())
            .collect::<Result<Vec<ResourceServer>>>()
    }

    /// Count resource servers by realm
    pub async fn count_resource_servers_by_realm(db: &Database, realm_id: Uuid) -> Result<i64> {
        let query = "SELECT COUNT(*) FROM resource_servers WHERE realm_id = $1";

        let row: tokio_postgres::Row = db.query_one(query, &[&realm_id]).await?;
        Ok(row.get(0))
    }
}

/// Database operations for user consent management
pub mod user_consents {
    use authenc_core::error::{AuthencError, Result};

    use authenc_models::models::{ConsentGrantRequest, UserConsent};

    use crate::database::Database;
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    /// Grant user consent for a client
    pub async fn grant_consent(
        db: &Database,
        user_id: Uuid,
        request: &ConsentGrantRequest,
    ) -> Result<UserConsent> {
        let consent_id = Uuid::new_v4();
        let granted_at = Utc::now();
        let expires_at = request
            .expires_in
            .map(|secs| granted_at + Duration::seconds(secs));
        let metadata = request
            .metadata
            .clone()
            .unwrap_or(serde_json::Value::Null);

        let query = r#"
            INSERT INTO user_consents (id, user_id, client_id, scopes, granted_at, expires_at, metadata)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (user_id, client_id) 
            DO UPDATE SET 
                scopes = EXCLUDED.scopes,
                granted_at = EXCLUDED.granted_at,
                expires_at = EXCLUDED.expires_at,
                metadata = EXCLUDED.metadata
            RETURNING id, user_id, client_id, scopes, granted_at, expires_at, metadata
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &consent_id,
                    &user_id,
                    &request.client_id,
                    &request.scopes,
                    &granted_at,
                    &expires_at,
                    &metadata,
                ],
            )
            .await?;

        Ok(UserConsent {
            id: row.get("id"),
            user_id: row.get("user_id"),
            client_id: row.get("client_id"),
            scopes: row.get("scopes"),
            granted_at: row.get("granted_at"),
            expires_at: row.get("expires_at"),
            metadata: row.get("metadata"),
        })
    }

    /// Revoke user consent for a client
    pub async fn revoke_consent(db: &Database, user_id: Uuid, client_id: &str) -> Result<()> {
        let query = "DELETE FROM user_consents WHERE user_id = $1 AND client_id = $2";

        let rows_affected = db.execute(query, &[&user_id, &client_id]).await?;

        if rows_affected == 0 {
            return Err(AuthencError::resource_not_found(format!(
                "Consent for user {} and client {} not found",
                user_id, client_id
            )));
        }

        Ok(())
    }

    /// Revoke specific consent by ID
    pub async fn revoke_consent_by_id(
        db: &Database,
        user_id: Uuid,
        consent_id: Uuid,
    ) -> Result<()> {
        let query = "DELETE FROM user_consents WHERE id = $1 AND user_id = $2";

        let rows_affected = db.execute(query, &[&consent_id, &user_id]).await?;

        if rows_affected == 0 {
            return Err(AuthencError::resource_not_found(format!(
                "Consent with id {} for user {} not found",
                consent_id, user_id
            )));
        }

        Ok(())
    }

    /// Get all user consents
    pub async fn get_user_consents(db: &Database, user_id: Uuid) -> Result<Vec<UserConsent>> {
        let query = r#"
            SELECT id, user_id, client_id, scopes, granted_at, expires_at, metadata
            FROM user_consents
            WHERE user_id = $1
            AND (expires_at IS NULL OR expires_at > NOW())
            ORDER BY granted_at DESC
        "#;

        let rows = db.query(query, &[&user_id]).await?;

        rows.into_iter()
            .map(|row: tokio_postgres::Row| {
                Ok(UserConsent {
                    id: row.get("id"),
                    user_id: row.get("user_id"),
                    client_id: row.get("client_id"),
                    scopes: row.get("scopes"),
                    granted_at: row.get("granted_at"),
                    expires_at: row.get("expires_at"),
                    metadata: row.get("metadata"),
                })
            })
            .collect()
    }

    /// Get specific user consent for a client
    pub async fn get_user_consent(
        db: &Database,
        user_id: Uuid,
        client_id: &str,
    ) -> Result<Option<UserConsent>> {
        let query = r#"
            SELECT id, user_id, client_id, scopes, granted_at, expires_at, metadata
            FROM user_consents
            WHERE user_id = $1 AND client_id = $2
            AND (expires_at IS NULL OR expires_at > NOW())
        "#;

        let row = db.query_opt(query, &[&user_id, &client_id]).await?;

        Ok(row.map(|row: tokio_postgres::Row| UserConsent {
            id: row.get("id"),
            user_id: row.get("user_id"),
            client_id: row.get("client_id"),
            scopes: row.get("scopes"),
            granted_at: row.get("granted_at"),
            expires_at: row.get("expires_at"),
            metadata: row.get("metadata"),
        }))
    }

    /// Check if user has valid consent for client and scopes
    pub async fn has_consent(
        db: &Database,
        user_id: Uuid,
        client_id: &str,
        required_scopes: &[String],
    ) -> Result<bool> {
        let query = r#"
            SELECT scopes
            FROM user_consents
            WHERE user_id = $1 AND client_id = $2
            AND (expires_at IS NULL OR expires_at > NOW())
        "#;

        let row = db.query_opt(query, &[&user_id, &client_id]).await?;

        match row {
            Some(row) => {
                let granted_scopes: Vec<String> = row.get("scopes");
                Ok(required_scopes
                    .iter()
                    .all(|scope| granted_scopes.contains(scope)))
            }
            None => Ok(false),
        }
    }

    /// Clean up expired consents
    pub async fn cleanup_expired_consents(db: &Database) -> Result<i64> {
        let query = "DELETE FROM user_consents WHERE expires_at IS NOT NULL AND expires_at < NOW()";

        let rows_affected = db.execute(query, &[]).await?;
        Ok(rows_affected as i64)
    }

    /// Get consent statistics for a user
    pub async fn get_consent_stats(db: &Database, user_id: Uuid) -> Result<serde_json::Value> {
        let query = r#"
            SELECT 
                COUNT(*) as total_consents,
                COUNT(*) FILTER (WHERE expires_at IS NULL) as permanent_consents,
                COUNT(*) FILTER (WHERE expires_at IS NOT NULL AND expires_at > NOW()) as temporary_consents,
                COUNT(DISTINCT client_id) as unique_clients
            FROM user_consents
            WHERE user_id = $1
        "#;

        let row: tokio_postgres::Row = db.query_one(query, &[&user_id]).await?;

        Ok(serde_json::json!({
            "total_consents": row.get::<_, i64>("total_consents"),
            "permanent_consents": row.get::<_, i64>("permanent_consents"),
            "temporary_consents": row.get::<_, i64>("temporary_consents"),
            "unique_clients": row.get::<_, i64>("unique_clients")
        }))
    }
}

/// Session management database operations
pub mod sessions {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Store a session in the database
    pub async fn store_session(db: &Database, session: &authenc_models::models::session::Session) -> Result<()> {
        let query = r#"
            INSERT INTO user_sessions (
                id, session_id, user_id,
                expires_at, ip_address, user_agent, started_at,
                last_activity_at, terminated, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (id) DO UPDATE SET
                last_activity_at = EXCLUDED.last_activity_at,
                terminated = EXCLUDED.terminated,
                ip_address = EXCLUDED.ip_address,
                user_agent = EXCLUDED.user_agent
        "#;

        let ip_addr: Option<std::net::IpAddr> = session
            .ip_address
            .as_ref()
            .and_then(|ip| ip.parse().ok());

        // Use ID string as session_id since we don't have a separate ID
        let session_id_str = session.id.to_string();

        db.execute(
            query,
            &[
                &session.id,
                &session_id_str,
                &session.user_id,
                &session.expires_at,
                &ip_addr,
                &session.user_agent,
                &session.created_at,
                &session.last_accessed,
                &session.revoked,
                &session.created_at,
            ],
        )
        .await?;

        Ok(())
    }

    /// Create a new user session
    pub async fn create_user_session(
        db: &Database,
        user_id: Uuid,
        realm_id: Uuid,
        client_id: Option<Uuid>,
        token: &str,
        refresh_token: Option<&str>,
        expires_in: i64,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        authentication_method: Option<&str>,
        protocol: Option<&str>,
    ) -> Result<serde_json::Value> {
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(expires_in);
        let now = chrono::Utc::now();
        let session_uuid = Uuid::new_v4();
        let session_id_str = session_uuid.to_string();

        let query = r#"
            INSERT INTO user_sessions (
                id, session_id, user_id,
                expires_at,
                ip_address, user_agent,
                started_at, created_at, last_activity_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, session_id, user_id, started_at, expires_at,
                      last_activity_at, terminated, created_at
        "#;

        let ip_addr: Option<std::net::IpAddr> = ip_address.and_then(|ip| ip.parse().ok());

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &session_uuid,
                    &session_id_str,
                    &user_id,
                    &expires_at,
                    &ip_addr,
                    &user_agent,
                    &now,
                    &now,
                    &now,
                ],
            )
            .await?;

        // Store tokens if client_id is present (OAuth2 flow)
        if let Some(cid) = client_id {
            let token_id = Uuid::new_v4();
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            let token_hash = format!("{:x}", hasher.finalize());

            let refresh_token_hash = refresh_token.map(|rt| {
                let mut hasher = Sha256::new();
                hasher.update(rt.as_bytes());
                format!("{:x}", hasher.finalize())
            });

            let scopes: Vec<String> = Vec::new();
            let refresh_expires_at = if refresh_token.is_some() {
                Some(expires_at)
            } else {
                None
            };

            let token_query = r#"
                INSERT INTO oauth2_access_tokens (
                    id, token_hash, refresh_token_hash, client_id, user_id, scopes,
                    expires_at, refresh_expires_at, created_at, session_id
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#;

            db.execute(
                token_query,
                &[
                    &token_id,
                    &token_hash,
                    &refresh_token_hash,
                    &cid,
                    &user_id,
                    &scopes,
                    &expires_at,
                    &refresh_expires_at,
                    &now,
                    &session_id_str,
                ],
            )
            .await?;
        }

        // Note: realm_id, client_id, token_hash etc are not stored in user_sessions schema
        Ok(serde_json::json!({
            "id": row.get::<_, Uuid>("id"),
            "session_id": row.get::<_, String>("session_id"),
            "user_id": row.get::<_, Uuid>("user_id"),
            "realm_id": realm_id, // Passed through
            "client_id": client_id, // Passed through
            "started_at": row.get::<_, chrono::DateTime<chrono::Utc>>("started_at"),
            "expires_at": row.get::<_, chrono::DateTime<chrono::Utc>>("expires_at"),
            "last_accessed": row.get::<_, chrono::DateTime<chrono::Utc>>("last_activity_at"),
            "revoked": row.get::<_, bool>("terminated"),
            "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at")
        }))
    }

    /// Get a user session by ID
    pub async fn get_user_session(
        db: &Database,
        session_id: Uuid,
    ) -> Result<Option<serde_json::Value>> {
        let query = r#"
            SELECT id, session_id, user_id, device_id,
                   started_at, expires_at, last_activity_at,
                   terminated, terminated_at, terminated_reason,
                   ip_address, user_agent, created_at
            FROM user_sessions
            WHERE id = $1
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&session_id]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row: &tokio_postgres::Row = &rows[0];
        Ok(Some(serde_json::json!({
            "id": row.get::<_, Uuid>("id"),
            "session_id": row.get::<_, String>("session_id"),
            "user_id": row.get::<_, Uuid>("user_id"),
            "device_id": row.try_get::<_, Option<Uuid>>("device_id").ok().flatten(),
            "started_at": row.get::<_, chrono::DateTime<chrono::Utc>>("started_at"),
            "expires_at": row.get::<_, chrono::DateTime<chrono::Utc>>("expires_at"),
            "last_accessed": row.get::<_, chrono::DateTime<chrono::Utc>>("last_activity_at"),
            "revoked": row.get::<_, bool>("terminated"),
            "revoked_at": row.try_get::<_, Option<chrono::DateTime<chrono::Utc>>>("terminated_at").ok().flatten(),
            "revoked_reason": row.try_get::<_, Option<String>>("terminated_reason").ok().flatten(),
            "ip_address": row.get::<_, Option<std::net::IpAddr>>("ip_address").map(|ip| ip.to_string()),
            "user_agent": row.get::<_, Option<String>>("user_agent"),
            "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at")
        })))
    }

    /// Get a user session by token
    pub async fn get_session_by_token(
        db: &Database,
        token: &str,
    ) -> Result<Option<serde_json::Value>> {
        let token_hash = hash_token(token);

        // 1. Find session_id from oauth2_access_tokens
        let token_query = "SELECT session_id FROM oauth2_access_tokens WHERE token_hash = $1 AND revoked = false AND expires_at > NOW()";
        let token_rows: Vec<tokio_postgres::Row> = db.query(token_query, &[&token_hash]).await?;

        if token_rows.is_empty() {
            return Ok(None);
        }

        // 2. Retrieve session using ID
        let session_id_opt: Option<Uuid> = token_rows[0]
            .try_get::<_, Option<String>>("session_id")
            .ok()
            .flatten()
            .and_then(|s| Uuid::parse_str(&s).ok());

        if let Some(session_id) = session_id_opt {
             return get_user_session(db, session_id).await;
        }

        Ok(None)
    }

    /// Get all active sessions for a user
    pub async fn get_user_sessions(db: &Database, user_id: Uuid) -> Result<Vec<serde_json::Value>> {
        let query = r#"
            SELECT id, session_id, user_id,
                   started_at, expires_at, last_activity_at,
                   ip_address, user_agent, created_at
            FROM user_sessions
            WHERE user_id = $1 AND NOT terminated AND expires_at > NOW()
            ORDER BY last_activity_at DESC
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&user_id]).await?;

        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(serde_json::json!({
                "id": row.get::<_, Uuid>("id"),
                "session_id": row.get::<_, String>("session_id"),
                "user_id": row.get::<_, Uuid>("user_id"),
                "started_at": row.get::<_, chrono::DateTime<chrono::Utc>>("started_at"),
                "expires_at": row.get::<_, chrono::DateTime<chrono::Utc>>("expires_at"),
                "last_accessed": row.get::<_, chrono::DateTime<chrono::Utc>>("last_activity_at"),
                "ip_address": row.get::<_, Option<std::net::IpAddr>>("ip_address").map(|ip| ip.to_string()),
                "user_agent": row.get::<_, Option<String>>("user_agent"),
                "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at")
            }));
        }

        Ok(sessions)
    }

    /// Get sessions for a specific device
    pub async fn get_device_sessions(
        db: &Database,
        device_id: Uuid,
    ) -> Result<Vec<serde_json::Value>> {
        let query = r#"
            SELECT id, device_id, user_id, user_session_id,
                   session_identifier, started_at, last_activity,
                   ip_address, location, risk_score, risk_factors,
                   is_active, created_at, updated_at
            FROM device_sessions
            WHERE device_id = $1
            ORDER BY last_activity DESC
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&device_id]).await?;

        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(serde_json::json!({
                "id": row.get::<_, Uuid>("id"),
                "device_id": row.get::<_, Uuid>("device_id"),
                "user_id": row.get::<_, Uuid>("user_id"),
                "user_session_id": row.get::<_, Option<Uuid>>("user_session_id"),
                "session_identifier": row.get::<_, String>("session_identifier"),
                "started_at": row.get::<_, chrono::DateTime<chrono::Utc>>("started_at"),
                "last_activity": row.get::<_, chrono::DateTime<chrono::Utc>>("last_activity"),
                "ip_address": row.get::<_, Option<std::net::IpAddr>>("ip_address").map(|ip| ip.to_string()),
                "location": row.get::<_, Option<serde_json::Value>>("location"),
                "risk_score": row.get::<_, f64>("risk_score"),
                "risk_factors": row.get::<_, Option<serde_json::Value>>("risk_factors"),
                "is_active": row.get::<_, bool>("is_active"),
                "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at"),
                "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>("updated_at")
            }));
        }

        Ok(sessions)
    }

    /// Update session last accessed time
    pub async fn touch_session(db: &Database, session_id: Uuid) -> Result<()> {
        let query = r#"
            UPDATE user_sessions
            SET last_activity_at = NOW()
            WHERE id = $1 AND NOT terminated
        "#;

        db.execute(query, &[&session_id]).await?;
        Ok(())
    }

    /// Rotate refresh token
    pub async fn rotate_refresh_token(
        db: &Database,
        session_id: Uuid,
        old_refresh_token: &str,
        new_refresh_token: &str,
        _client_ip: Option<&str>,
        _user_agent: Option<&str>,
    ) -> Result<bool> {
        let old_hash = hash_token(old_refresh_token);
        let new_hash = hash_token(new_refresh_token);
        let now = chrono::Utc::now();
        // Default 30 days extension, should ideally match client policy
        let refresh_expires = now + chrono::Duration::days(30);

        let query = r#"
            UPDATE oauth2_access_tokens
            SET refresh_token_hash = $1,
                refresh_expires_at = $2,
                last_used_at = $3
            WHERE refresh_token_hash = $4
              AND session_id = $5
              AND revoked = false
        "#;

        let session_id_str = session_id.to_string();
        let affected = db.execute(
            query,
            &[&new_hash, &refresh_expires, &now, &old_hash, &session_id_str]
        ).await?;

        Ok(affected > 0)
    }

    /// Revoke a session
    pub async fn revoke_session(
        db: &Database,
        session_id: Uuid,
        reason: Option<&str>,
    ) -> Result<()> {
        let query = r#"
            UPDATE user_sessions
            SET terminated = TRUE,
                terminated_at = NOW(),
                terminated_reason = $2
            WHERE id = $1
        "#;

        db.execute(query, &[&session_id, &reason]).await?;
        Ok(())
    }

    /// Revoke all sessions for a user
    pub async fn revoke_user_sessions(
        db: &Database,
        user_id: Uuid,
        reason: Option<&str>,
    ) -> Result<i64> {
        let query = r#"
            UPDATE user_sessions
            SET terminated = TRUE,
                terminated_at = NOW(),
                terminated_reason = $2
            WHERE user_id = $1 AND NOT terminated
        "#;

        let count = db.execute(query, &[&user_id, &reason]).await?;
        Ok(count as i64)
    }

    /// Cleanup expired sessions
    pub async fn cleanup_expired_sessions(db: &Database) -> Result<i64> {
        let query = r#"
            DELETE FROM user_sessions
            WHERE expires_at < NOW()
        "#;

        let count = db.execute(query, &[]).await?;
        Ok(count as i64)
    }

    /// Create offline token
    pub async fn create_offline_token(
        db: &Database,
        user_id: Uuid,
        realm_id: Uuid,
        client_id: Uuid,
        token: &str,
        scope: Option<&str>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        data: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let token_hash = hash_token(token);

        let query = r#"
            INSERT INTO offline_tokens (
                user_id, realm_id, client_id,
                token_hash, scope, expires_at, data
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, user_id, realm_id, client_id,
                      created_at, expires_at, last_used_at,
                      scope, revoked, created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &user_id,
                    &realm_id,
                    &client_id,
                    &token_hash,
                    &scope,
                    &expires_at,
                    &data,
                ],
            )
            .await?;

        Ok(serde_json::json!({
            "id": row.get::<_, Uuid>("id"),
            "user_id": row.get::<_, Uuid>("user_id"),
            "realm_id": row.get::<_, Uuid>("realm_id"),
            "client_id": row.get::<_, Uuid>("client_id"),
            "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at"),
            "expires_at": row.get::<_, Option<chrono::DateTime<chrono::Utc>>>("expires_at"),
            "last_used_at": row.get::<_, Option<chrono::DateTime<chrono::Utc>>>("last_used_at"),
            "scope": row.get::<_, Option<String>>("scope"),
            "revoked": row.get::<_, bool>("revoked"),
            "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>("updated_at")
        }))
    }

    /// Get offline token by token string
    pub async fn get_offline_token(
        db: &Database,
        token: &str,
    ) -> Result<Option<serde_json::Value>> {
        let token_hash = hash_token(token);

        let query = r#"
            SELECT id, user_id, realm_id, client_id,
                   created_at, expires_at, last_used_at,
                   scope, data, revoked, revoked_at,
                   created_at, updated_at
            FROM offline_tokens
            WHERE token_hash = $1
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&token_hash]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = &rows[0];
        Ok(Some(serde_json::json!({
            "id": row.get::<_, Uuid>("id"),
            "user_id": row.get::<_, Uuid>("user_id"),
            "realm_id": row.get::<_, Uuid>("realm_id"),
            "client_id": row.get::<_, Uuid>("client_id"),
            "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at"),
            "expires_at": row.get::<_, Option<chrono::DateTime<chrono::Utc>>>("expires_at"),
            "last_used_at": row.get::<_, Option<chrono::DateTime<chrono::Utc>>>("last_used_at"),
            "scope": row.get::<_, Option<String>>("scope"),
            "data": row.get::<_, Option<serde_json::Value>>("data"),
            "revoked": row.get::<_, bool>("revoked"),
            "revoked_at": row.get::<_, Option<chrono::DateTime<chrono::Utc>>>("revoked_at"),
            "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>("updated_at")
        })))
    }

    /// Update offline token last used time
    pub async fn touch_offline_token(db: &Database, token_id: Uuid) -> Result<()> {
        let query = r#"
            UPDATE offline_tokens
            SET last_used_at = NOW(), updated_at = NOW()
            WHERE id = $1 AND NOT revoked
        "#;

        db.execute(query, &[&token_id]).await?;
        Ok(())
    }

    /// Revoke offline token
    pub async fn revoke_offline_token(db: &Database, token_id: Uuid) -> Result<()> {
        let query = r#"
            UPDATE offline_tokens
            SET revoked = TRUE, revoked_at = NOW(), updated_at = NOW()
            WHERE id = $1
        "#;

        db.execute(query, &[&token_id]).await?;
        Ok(())
    }

    /// Create device session
    pub async fn create_device_session(
        db: &Database,
        device_id: Uuid,
        user_id: Uuid,
        user_session_id: Option<Uuid>,
        session_identifier: &str,
        ip_address: Option<&str>,
        location: Option<serde_json::Value>,
        risk_score: f64,
    ) -> Result<serde_json::Value> {
        let ip_addr: Option<std::net::IpAddr> = ip_address.and_then(|ip| ip.parse().ok());

        let query = r#"
            INSERT INTO device_sessions (
                device_id, user_id, user_session_id,
                session_identifier, ip_address, location, risk_score
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, device_id, user_id, user_session_id,
                      session_identifier, started_at, last_activity,
                      ip_address, location, risk_score, risk_factors,
                      is_active, created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &device_id,
                    &user_id,
                    &user_session_id,
                    &session_identifier,
                    &ip_addr,
                    &location,
                    &risk_score,
                ],
            )
            .await?;

        Ok(serde_json::json!({
            "id": row.get::<_, Uuid>("id"),
            "device_id": row.get::<_, Uuid>("device_id"),
            "user_id": row.get::<_, Uuid>("user_id"),
            "user_session_id": row.get::<_, Option<Uuid>>("user_session_id"),
            "session_identifier": row.get::<_, String>("session_identifier"),
            "started_at": row.get::<_, chrono::DateTime<chrono::Utc>>("started_at"),
            "last_activity": row.get::<_, chrono::DateTime<chrono::Utc>>("last_activity"),
            "ip_address": row.get::<_, Option<std::net::IpAddr>>("ip_address").map(|ip| ip.to_string()),
            "location": row.get::<_, Option<serde_json::Value>>("location"),
            "risk_score": row.get::<_, f64>("risk_score"),
            "risk_factors": row.get::<_, Option<serde_json::Value>>("risk_factors"),
            "is_active": row.get::<_, bool>("is_active"),
            "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at"),
            "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>("updated_at")
        }))
    }

    /// Update device session activity
    pub async fn update_device_session_activity(
        db: &Database,
        session_id: Uuid,
        risk_score: Option<f64>,
        risk_factors: Option<serde_json::Value>,
    ) -> Result<()> {
        let query = if risk_score.is_some() && risk_factors.is_some() {
            r#"
                UPDATE device_sessions
                SET last_activity = NOW(),
                    risk_score = $2,
                    risk_factors = $3,
                    updated_at = NOW()
                WHERE id = $1 AND is_active
            "#
        } else {
            r#"
                UPDATE device_sessions
                SET last_activity = NOW(), updated_at = NOW()
                WHERE id = $1 AND is_active
            "#
        };

        if let (Some(score), Some(factors)) = (risk_score, risk_factors) {
            db.execute(query, &[&session_id, &score, &factors]).await?;
        } else {
            db.execute(query, &[&session_id]).await?;
        }

        Ok(())
    }

    /// End device session
    pub async fn end_device_session(db: &Database, session_id: Uuid) -> Result<()> {
        let query = r#"
            UPDATE device_sessions
            SET is_active = FALSE,
                ended_at = NOW(),
                updated_at = NOW()
            WHERE id = $1
        "#;

        db.execute(query, &[&session_id]).await?;
        Ok(())
    }

    /// Get active device sessions for a user
    pub async fn get_user_device_sessions(
        db: &Database,
        user_id: Uuid,
    ) -> Result<Vec<serde_json::Value>> {
        let query = r#"
            SELECT id, device_id, user_id, user_session_id,
                   session_identifier, started_at, last_activity,
                   ip_address, location, risk_score, risk_factors,
                   is_active, created_at, updated_at
            FROM device_sessions
            WHERE user_id = $1 AND is_active
            ORDER BY last_activity DESC
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&user_id]).await?;

        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(serde_json::json!({
                "id": row.get::<_, Uuid>("id"),
                "device_id": row.get::<_, Uuid>("device_id"),
                "user_id": row.get::<_, Uuid>("user_id"),
                "user_session_id": row.get::<_, Option<Uuid>>("user_session_id"),
                "session_identifier": row.get::<_, String>("session_identifier"),
                "started_at": row.get::<_, chrono::DateTime<chrono::Utc>>("started_at"),
                "last_activity": row.get::<_, chrono::DateTime<chrono::Utc>>("last_activity"),
                "ip_address": row.get::<_, Option<std::net::IpAddr>>("ip_address").map(|ip| ip.to_string()),
                "location": row.get::<_, Option<serde_json::Value>>("location"),
                "risk_score": row.get::<_, f64>("risk_score"),
                "risk_factors": row.get::<_, Option<serde_json::Value>>("risk_factors"),
                "is_active": row.get::<_, bool>("is_active"),
                "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at"),
                "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>("updated_at")
            }));
        }

        Ok(sessions)
    }

    /// Helper function to hash tokens using SHA256
    fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// Theme customization database operations
pub mod themes {
    use super::*;

    /// Create a custom theme
    pub async fn create_theme(
        db: &Database,
        realm_id: Uuid,
        name: &str,
        theme_type: &str,
        parent_theme: Option<&str>,
        css_content: Option<&str>,
        css_variables: Option<serde_json::Value>,
        description: Option<&str>,
    ) -> Result<serde_json::Value> {
        let query = r#"
            INSERT INTO custom_themes (
                realm_id, name, theme_type, parent_theme,
                css_content, css_variables, description
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, realm_id, name, theme_type, parent_theme,
                      is_active, is_default, created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &realm_id,
                    &name,
                    &theme_type,
                    &parent_theme,
                    &css_content,
                    &css_variables,
                    &description,
                ],
            )
            .await?;

        Ok(serde_json::json!({
            "id": row.get::<_, Uuid>("id"),
            "realm_id": row.get::<_, Uuid>("realm_id"),
            "name": row.get::<_, String>("name"),
            "theme_type": row.get::<_, String>("theme_type"),
            "parent_theme": row.get::<_, Option<String>>("parent_theme"),
            "is_active": row.get::<_, bool>("is_active"),
            "is_default": row.get::<_, bool>("is_default"),
            "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at"),
            "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>("updated_at")
        }))
    }

    /// Get theme by ID
    pub async fn get_theme(db: &Database, theme_id: Uuid) -> Result<Option<serde_json::Value>> {
        let query = r#"
            SELECT id, realm_id, name, theme_type, parent_theme,
                   css_content, css_variables, templates, resources, messages,
                   description, version, author, is_active, is_default,
                   created_at, updated_at
            FROM custom_themes
            WHERE id = $1
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&theme_id]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = &rows[0];
        Ok(Some(serde_json::json!({
            "id": row.get::<_, Uuid>("id"),
            "realm_id": row.get::<_, Uuid>("realm_id"),
            "name": row.get::<_, String>("name"),
            "theme_type": row.get::<_, String>("theme_type"),
            "parent_theme": row.get::<_, Option<String>>("parent_theme"),
            "css_content": row.get::<_, Option<String>>("css_content"),
            "css_variables": row.get::<_, Option<serde_json::Value>>("css_variables"),
            "templates": row.get::<_, Option<serde_json::Value>>("templates"),
            "resources": row.get::<_, Option<serde_json::Value>>("resources"),
            "messages": row.get::<_, Option<serde_json::Value>>("messages"),
            "description": row.get::<_, Option<String>>("description"),
            "version": row.get::<_, Option<String>>("version"),
            "author": row.get::<_, Option<String>>("author"),
            "is_active": row.get::<_, bool>("is_active"),
            "is_default": row.get::<_, bool>("is_default"),
            "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at"),
            "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>("updated_at")
        })))
    }

    /// Get themes for a realm
    pub async fn get_realm_themes(
        db: &Database,
        realm_id: Uuid,
        theme_type: Option<&str>,
    ) -> Result<Vec<serde_json::Value>> {
        let query = if theme_type.is_some() {
            r#"
                SELECT id, realm_id, name, theme_type, parent_theme,
                       description, is_active, is_default,
                       created_at, updated_at
                FROM custom_themes
                WHERE realm_id = $1 AND theme_type = $2
                ORDER BY name ASC
            "#
        } else {
            r#"
                SELECT id, realm_id, name, theme_type, parent_theme,
                       description, is_active, is_default,
                       created_at, updated_at
                FROM custom_themes
                WHERE realm_id = $1
                ORDER BY theme_type ASC, name ASC
            "#
        };

        let rows: Vec<tokio_postgres::Row> = if let Some(ttype) = theme_type {
            db.query(query, &[&realm_id, &ttype]).await?
        } else {
            db.query(query, &[&realm_id]).await?
        };

        let mut themes = Vec::new();
        for row in rows {
            themes.push(serde_json::json!({
                "id": row.get::<_, Uuid>("id"),
                "realm_id": row.get::<_, Uuid>("realm_id"),
                "name": row.get::<_, String>("name"),
                "theme_type": row.get::<_, String>("theme_type"),
                "parent_theme": row.get::<_, Option<String>>("parent_theme"),
                "description": row.get::<_, Option<String>>("description"),
                "is_active": row.get::<_, bool>("is_active"),
                "is_default": row.get::<_, bool>("is_default"),
                "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at"),
                "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>("updated_at")
            }));
        }

        Ok(themes)
    }

    /// Update theme
    pub async fn update_theme(
        db: &Database,
        theme_id: Uuid,
        updates: serde_json::Value,
    ) -> Result<()> {
        let now = chrono::Utc::now();
        let mut set_clauses = Vec::new();
        let mut param_index = 2;
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
            vec![Box::new(theme_id)];

        if let Some(name) = updates.get("name").and_then(|v| v.as_str()) {
            set_clauses.push(format!("name = ${}", param_index));
            params.push(Box::new(name.to_string()));
            param_index += 1;
        }

        if let Some(css_content) = updates.get("css_content").and_then(|v| v.as_str()) {
            set_clauses.push(format!("css_content = ${}", param_index));
            params.push(Box::new(css_content.to_string()));
            param_index += 1;
        }

        if let Some(css_variables) = updates.get("css_variables") {
            set_clauses.push(format!("css_variables = ${}", param_index));
            params.push(Box::new(css_variables.clone()));
            param_index += 1;
        }

        if let Some(templates) = updates.get("templates") {
            set_clauses.push(format!("templates = ${}", param_index));
            params.push(Box::new(templates.clone()));
            param_index += 1;
        }

        if let Some(messages) = updates.get("messages") {
            set_clauses.push(format!("messages = ${}", param_index));
            params.push(Box::new(messages.clone()));
            param_index += 1;
        }

        if set_clauses.is_empty() {
            return Ok(());
        }

        set_clauses.push(format!("updated_at = ${}", param_index));
        params.push(Box::new(now));

        let query = format!(
            "UPDATE custom_themes SET {} WHERE id = $1",
            set_clauses.join(", ")
        );

        let params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync)).collect();

        db.execute(&query, &params_refs).await?;
        Ok(())
    }

    /// Activate theme
    pub async fn activate_theme(db: &Database, theme_id: Uuid) -> Result<()> {
        let now = chrono::Utc::now();

        // Deactivate other themes of same type in same realm
        let deactivate_query = r#"
            UPDATE custom_themes
            SET is_active = FALSE, updated_at = $1
            WHERE realm_id = (SELECT realm_id FROM custom_themes WHERE id = $2)
                AND theme_type = (SELECT theme_type FROM custom_themes WHERE id = $2)
                AND id != $2
        "#;

        db.execute(deactivate_query, &[&now, &theme_id]).await?;

        // Activate the selected theme
        let activate_query = r#"
            UPDATE custom_themes
            SET is_active = TRUE, updated_at = $1
            WHERE id = $2
        "#;

        db.execute(activate_query, &[&now, &theme_id]).await?;
        Ok(())
    }

    /// Delete theme
    pub async fn delete_theme(db: &Database, theme_id: Uuid) -> Result<()> {
        let query = "DELETE FROM custom_themes WHERE id = $1";
        db.execute(query, &[&theme_id]).await?;
        Ok(())
    }

    /// Add theme resource
    pub async fn add_theme_resource(
        db: &Database,
        theme_id: Uuid,
        resource_name: &str,
        resource_type: &str,
        mime_type: Option<&str>,
        content_url: Option<&str>,
        content_data: Option<&[u8]>,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO theme_resources (
                theme_id, resource_name, resource_type,
                mime_type, content_url, content_data, content_size
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (theme_id, resource_name) 
            DO UPDATE SET
                resource_type = EXCLUDED.resource_type,
                mime_type = EXCLUDED.mime_type,
                content_url = EXCLUDED.content_url,
                content_data = EXCLUDED.content_data,
                content_size = EXCLUDED.content_size,
                updated_at = NOW()
            RETURNING id
        "#;

        let content_size = content_data.map(|d| d.len() as i64);

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &theme_id,
                    &resource_name,
                    &resource_type,
                    &mime_type,
                    &content_url,
                    &content_data,
                    &content_size,
                ],
            )
            .await?;

        Ok(row.get(0))
    }

    /// Get theme resource
    pub async fn get_theme_resource(
        db: &Database,
        theme_id: Uuid,
        resource_name: &str,
    ) -> Result<Option<serde_json::Value>> {
        let query = r#"
            SELECT id, theme_id, resource_name, resource_type,
                   mime_type, content_url, content_size,
                   created_at, updated_at
            FROM theme_resources
            WHERE theme_id = $1 AND resource_name = $2
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&theme_id, &resource_name]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = &rows[0];
        Ok(Some(serde_json::json!({
            "id": row.get::<_, Uuid>("id"),
            "theme_id": row.get::<_, Uuid>("theme_id"),
            "resource_name": row.get::<_, String>("resource_name"),
            "resource_type": row.get::<_, String>("resource_type"),
            "mime_type": row.get::<_, Option<String>>("mime_type"),
            "content_url": row.get::<_, Option<String>>("content_url"),
            "content_size": row.get::<_, Option<i64>>("content_size"),
            "created_at": row.get::<_, chrono::DateTime<chrono::Utc>>("created_at"),
            "updated_at": row.get::<_, chrono::DateTime<chrono::Utc>>("updated_at")
        })))
    }

    /// Add or update theme template
    pub async fn save_theme_template(
        db: &Database,
        theme_id: Uuid,
        template_name: &str,
        template_type: &str,
        content: &str,
    ) -> Result<Uuid> {
        let query = r#"
            INSERT INTO theme_templates (
                theme_id, template_name, template_type, content
            )
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (theme_id, template_name)
            DO UPDATE SET
                content = EXCLUDED.content,
                version = theme_templates.version + 1,
                updated_at = NOW()
            RETURNING id
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[&theme_id, &template_name, &template_type, &content],
            )
            .await?;

        Ok(row.get(0))
    }

    /// Get theme template
    pub async fn get_theme_template(
        db: &Database,
        theme_id: Uuid,
        template_name: &str,
    ) -> Result<Option<String>> {
        let query = r#"
            SELECT content
            FROM theme_templates
            WHERE theme_id = $1 AND template_name = $2
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&theme_id, &template_name]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        Ok(Some(rows[0].get(0)))
    }

    /// Set realm theme for specific type
    pub async fn set_realm_theme(
        db: &Database,
        realm_id: Uuid,
        theme_type: &str,
        theme_id: Uuid,
    ) -> Result<()> {
        let column_name = match theme_type {
            "login" => "login_theme_id",
            "account" => "account_theme_id",
            "admin" => "admin_theme_id",
            "email" => "email_theme_id",
            _ => return Err(authenc_core::error::AuthencError::validation("Invalid theme type")),
        };

        let query = format!(
            r#"
                INSERT INTO realm_theme_settings (realm_id, {})
                VALUES ($1, $2)
                ON CONFLICT (realm_id)
                DO UPDATE SET {} = EXCLUDED.{}, updated_at = NOW()
            "#,
            column_name, column_name, column_name
        );

        db.execute(&query, &[&realm_id, &theme_id]).await?;
        Ok(())
    }

    /// Get active realm themes
    pub async fn get_realm_active_themes(
        db: &Database,
        realm_id: Uuid,
    ) -> Result<serde_json::Value> {
        let query = r#"
            SELECT login_theme_id, account_theme_id, admin_theme_id, email_theme_id
            FROM realm_theme_settings
            WHERE realm_id = $1
        "#;

        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&realm_id]).await?;

        if rows.is_empty() {
            return Ok(serde_json::json!({}));
        }

        let row = &rows[0];
        Ok(serde_json::json!({
            "login_theme_id": row.get::<_, Option<Uuid>>("login_theme_id"),
            "account_theme_id": row.get::<_, Option<Uuid>>("account_theme_id"),
            "admin_theme_id": row.get::<_, Option<Uuid>>("admin_theme_id"),
            "email_theme_id": row.get::<_, Option<Uuid>>("email_theme_id")
        }))
    }
}

/// Database operations for policies
pub mod policies {
    use crate::database::Database;
    use authenc_core::error::{AuthencError, Result};
    use authenc_models::models::Policy;
    use chrono::Utc;
    use uuid::Uuid;

    /// Get policies by realm with pagination
    pub async fn get_policies_by_realm(
        db: &Database,
        realm_id: Uuid,
        page: u32,
        limit: u32,
    ) -> Result<Vec<Policy>> {
        let offset = (page.saturating_sub(1)) * limit;
        let query = r#"
            SELECT
                id, name, description, policy_type, logic, config,
                enabled, realm_id, created_at, updated_at
            FROM policies
            WHERE realm_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
        "#;

        let rows: Vec<tokio_postgres::Row> = db
            .query(query, &[&realm_id, &(limit as i64), &(offset as i64)])
            .await?;

        let mut policies = Vec::new();
        for row in rows {
            policies.push(Policy {
                id: row.get("id"),
                name: row.get("name"),
                description: row.get("description"),
                policy_type: row.get("policy_type"),
                logic: row.get("logic"),
                config: row.get("config"),
                enabled: row.get("enabled"),
                realm_id: row.get("realm_id"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            });
        }

        Ok(policies)
    }

    /// Create a new policy
    pub async fn create_policy(
        db: &Database,
        name: &str,
        description: Option<&str>,
        policy_type: &str,
        logic: &str,
        config: &serde_json::Value,
        enabled: bool,
        realm_id: Uuid,
    ) -> Result<Policy> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO policies (
                id, name, description, policy_type, logic, config,
                enabled, realm_id, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING
                id, name, description, policy_type, logic, config,
                enabled, realm_id, created_at, updated_at
        "#;

        let row: tokio_postgres::Row = db
            .query_one(
                query,
                &[
                    &id,
                    &name,
                    &description,
                    &policy_type,
                    &logic,
                    &config,
                    &enabled,
                    &realm_id,
                    &now,
                    &now,
                ],
            )
            .await
            .map_err(|e| AuthencError::database(format!("Failed to create policy: {}", e)))?;

        Ok(Policy {
            id: row.get("id"),
            name: row.get("name"),
            description: row.get("description"),
            policy_type: row.get("policy_type"),
            logic: row.get("logic"),
            config: row.get("config"),
            enabled: row.get("enabled"),
            realm_id: row.get("realm_id"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
}

/// Database operations for SPI configuration
pub mod spi {
    use authenc_core::error::{AuthencError, Result};

    use crate::database::Database;
    use chrono::Utc;
    use log::error;
    use serde_json::Value;

    /// Upsert SPI provider configuration (Atomic)
    pub async fn upsert_provider_config(
        db: &Database,
        spi_name: &str,
        provider_id: &str,
        config: Value,
        enabled: bool,
    ) -> Result<()> {
        let now = Utc::now();
        let query = r#"
            INSERT INTO spi_provider_configs (
                spi_name, provider_id, config, enabled, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $5)
            ON CONFLICT (spi_name, provider_id)
            DO UPDATE SET
                config = EXCLUDED.config,
                enabled = EXCLUDED.enabled,
                updated_at = EXCLUDED.updated_at
        "#;

        db.execute(query, &[&spi_name, &provider_id, &config, &enabled, &now])
            .await
            .map_err(|e| {
                error!("Failed to upsert SPI provider config: {}", e);
                AuthencError::database(format!("Failed to upsert SPI provider config: {}", e))
            })?;

        Ok(())
    }

    /// Get all SPI provider configurations for a given SPI
    pub async fn get_all_provider_configs(
        db: &Database,
        spi_name: &str,
    ) -> Result<std::collections::HashMap<String, (Value, bool)>> {
        let query =
            "SELECT provider_id, config, enabled FROM spi_provider_configs WHERE spi_name = $1";
        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&spi_name]).await?;

        let mut map = std::collections::HashMap::new();
        for row in rows {
            let pid: String = row.get(0);
            let config: Value = row.get(1);
            let enabled: bool = row.get(2);
            map.insert(pid, (config, enabled));
        }
        Ok(map)
    }

    /// Get SPI provider configuration
    pub async fn get_provider_config(
        db: &Database,
        spi_name: &str,
        provider_id: &str,
    ) -> Result<Option<(Value, bool)>> {
        let query = "SELECT config, enabled FROM spi_provider_configs WHERE spi_name = $1 AND provider_id = $2";
        let rows: Vec<tokio_postgres::Row> = db.query(query, &[&spi_name, &provider_id]).await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = &rows[0];
        Ok(Some((row.get(0), row.get(1))))
    }
}

