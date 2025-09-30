/// Database operations for device management
pub mod devices {
    use crate::{
        database::Database,
        error::{AuthencError, Result},
        models::{Device, DeviceInfo},
    };
    use chrono::Utc;
    use log::error;
    use uuid::Uuid;

    /// Register a new device in the database
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
                user_agent, first_seen_at, last_seen_at, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING
                id, user_id, device_name, device_fingerprint, trust_score,
                risk_level, os, os_version, browser, browser_version,
                ip_address, user_agent, last_seen_at,
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
                    &0.5f64, // Initial trust score
                    &device_info.os,
                    &device_info.os_version,
                    &device_info.browser,
                    &device_info.browser_version,
                    &device_info.ip_address,
                    &device_info.user_agent,
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
                ip_address, user_agent, last_seen_at,
                first_seen_at, created_at, updated_at
            FROM devices
            WHERE id = $1
        "#;

        let row: tokio_postgres::Row = db.query_one(query, &[&device_id]).await?;
        // Convert row to Device
        Ok(Some(row.try_into()?))
    }

    /// Update device trust score
    pub async fn update_trust_score(
        db: &Database,
        device_id: Uuid,
        new_score: f64,
        factors: serde_json::Value,
    ) -> Result<()> {
        let now = Utc::now();

        // First, get the current score for history
        let current_query = "SELECT trust_score FROM devices WHERE id = $1";
        let current_row: tokio_postgres::Row = db.query_one(current_query, &[&device_id]).await?;
        let current_score: f64 = current_row.get(0);

        // Update the device trust score
        let update_query = r#"
            UPDATE devices
            SET trust_score = $2, updated_at = $3
            WHERE id = $1
        "#;
        db.execute(update_query, &[&device_id, &new_score, &now])
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
                ip_address, user_agent, location_data, last_seen_at,
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

/// Database operations for WebAuthn credentials
pub mod webauthn {
    use crate::{database::Database, error::Result, models::WebauthnCredential};
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
                user_handle, credential_type, transports, created_at, last_used_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        "#;

        db.execute(
            query,
            &[
                &credential_id,
                &user_id,
                &credential.credential_id,
                &credential.public_key,
                &credential.public_key_algorithm,
                &credential.signature_counter,
                &credential.attestation_object,
                &credential.authenticator_data,
                &credential.user_handle,
                &credential.credential_type,
                &credential.transports,
                &now,
                &credential.last_used_at,
            ],
        )
        .await?;

        Ok(())
    }

    /// Get WebAuthn credential by credential ID
    pub async fn get_credential_by_id(
        db: &Database,
        credential_id: &str,
    ) -> Result<Option<WebauthnCredential>> {
        let query = r#"
            SELECT
                id, user_id, credential_id, public_key, public_key_algorithm,
                attestation_object, authenticator_data, user_handle,
                signature_counter, credential_type, transports,
                aaguid, attestation_format, created_at, last_used_at, enabled
            FROM webauthn_credentials
            WHERE credential_id = $1
        "#;

        let row = db.query(query, &[&credential_id]).await?;
        let rows = row;
        Ok(if rows.is_empty() {
            None
        } else {
            let r: &tokio_postgres::Row = &rows[0];
            Some(WebauthnCredential {
                id: r.get(0),
                user_id: r.get(1),
                credential_id: r.get(2),
                public_key: r.get(3),
                public_key_algorithm: r.get(4),
                signature_counter: r.get(5),
                attestation_object: r.get(6),
                authenticator_data: r.get(7),
                user_handle: r.get(8),
                credential_type: r.get(9),
                transports: r.get(10),
                aaguid: r.get(11),
                attestation_format: r.get(12),
                created_at: r.get(13),
                last_used_at: r.get(14),
                enabled: r.get(15),
            })
        })
    }

    /// Get all WebAuthn credentials for a user
    pub async fn get_user_credentials(
        db: &Database,
        user_id: Uuid,
    ) -> Result<Vec<WebauthnCredential>> {
        let query = r#"
            SELECT
                id, user_id, credential_id, public_key, public_key_algorithm,
                attestation_object, authenticator_data, user_handle,
                signature_counter, credential_type, transports,
                aaguid, attestation_format, created_at, last_used_at, enabled
            FROM webauthn_credentials
            WHERE user_id = $1
            ORDER BY created_at DESC
        "#;

        let rows = db.query(query, &[&user_id]).await?;
        let credentials: Vec<WebauthnCredential> = rows
            .into_iter()
            .map(|row: tokio_postgres::Row| WebauthnCredential {
                id: row.get(0),
                user_id: row.get(1),
                credential_id: row.get(2),
                public_key: row.get(3),
                public_key_algorithm: row.get(4),
                signature_counter: row.get(5),
                attestation_object: row.get(6),
                authenticator_data: row.get(7),
                user_handle: row.get(8),
                credential_type: row.get(9),
                transports: row.get(10),
                aaguid: row.get(11),
                attestation_format: row.get(12),
                created_at: row.get(13),
                last_used_at: row.get(14),
                enabled: row.get(15),
            })
            .collect();
        Ok(credentials)
    }

    /// Update signature count after authentication
    pub async fn update_signature_count(
        db: &Database,
        credential_id: &str,
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

    /// Delete WebAuthn credential
    pub async fn delete_credential(db: &Database, credential_id: &str) -> Result<()> {
        let query = "DELETE FROM webauthn_credentials WHERE credential_id = $1";
        db.execute(query, &[&credential_id]).await?;
        Ok(())
    }

    /// Delete all WebAuthn credentials for a user
    pub async fn delete_user_credentials(db: &Database, user_id: Uuid) -> Result<()> {
        let query = "DELETE FROM webauthn_credentials WHERE user_id = $1";
        db.execute(query, &[&user_id]).await?;
        Ok(())
    }
}

/// Database operations for OAuth2
pub mod oauth2 {
    use crate::{
        database::Database,
        error::Result,
        models::{OAuth2AccessToken, OAuth2AuthorizationCode, OAuth2Client},
    };
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

        let row: tokio_postgres::Row = db.query_one(query, &[&client_id]).await?;
        // Convert row to OAuth2Client
        Ok(Some(row.try_into()?))
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
        let token_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO oauth2_access_tokens (
                id, token_hash, refresh_token_hash, client_id, user_id,
                scopes, expires_at, refresh_expires_at, revoked,
                created_at, last_used_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#;

        db.execute(
            query,
            &[
                &token_id,
                &token.token_hash,
                &token.refresh_token_hash,
                &token.client_id,
                &token.user_id,
                &token.scopes,
                &token.expires_at,
                &token.refresh_expires_at,
                &false,
                &now,
                &now,
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
                revoked_at, created_at, last_used_at
            FROM oauth2_access_tokens
            WHERE token_hash = $1 AND revoked = false AND expires_at > NOW()
        "#;

        let row: tokio_postgres::Row = db.query_one(query, &[&token_hash]).await?;
        // Convert row to OAuth2AccessToken
        Ok(Some(row.try_into()?))
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
    use crate::{
        database::Database,
        error::{AuthencError, Result},
        models::{Organization, OrganizationInvitation, OrganizationMember},
        services::organization::OrganizationRole,
    };
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
            let attributes: HashMap<String, String> =
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
                role: OrganizationRole::from_str(&row.get::<_, String>(3))
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
}

/// Database operations for SAML
pub mod saml {
    use crate::{
        database::Database,
        error::Result,
        models::{SamlServiceProvider, SamlSession},
    };
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
    use crate::{database::Database, error::Result, models::AuditEvent};

    use uuid::Uuid;

    /// Create audit log entry
    pub async fn create_audit_log(db: &Database, event: &AuditEvent) -> Result<()> {
        let event_id = Uuid::new_v4();

        let query = r#"
            INSERT INTO audit_logs (
                id, timestamp, event_type, user_id, session_id,
                client_id, resource_type, resource_id, action,
                status, details, ip_address, user_agent,
                location_data, error_message, request_id, correlation_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
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
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditEvent>> {
        let query = r#"
            SELECT
                id, timestamp, event_type, user_id, session_id,
                client_id, resource_type, resource_id, action,
                status, details, ip_address, user_agent,
                location_data, error_message, request_id, correlation_id
            FROM audit_logs
            WHERE ($1::uuid IS NULL OR user_id = $1)
            AND ($2::text IS NULL OR event_type = $2)
            ORDER BY timestamp DESC
            LIMIT $3 OFFSET $4
        "#;

        let rows = db
            .query(query, &[&user_id, &event_type, &limit, &offset])
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
    ) -> Result<i64> {
        let query = r#"
            SELECT COUNT(*) FROM audit_logs
            WHERE ($1::uuid IS NULL OR user_id = $1)
            AND ($2::text IS NULL OR event_type = $2)
        "#;

        let client = db.get_connection().await?;
        let count: i64 = client
            .query_one(query, &[&user_id, &event_type])
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
    use crate::{
        database::Database,
        error::Result,
        models::{user::CreateUserRequest, user::UpdateUserRequest, User},
    };
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
        let password_hash = request
            .password
            .as_ref()
            .map(|p| bcrypt::hash(p, bcrypt::DEFAULT_COST).unwrap_or_default());
        let realm_id = request.realm_id;
        let organization_id = request.organization_id;
        let attributes_json = request
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
        }))
    }

    /// Get user by username
    pub async fn get_user_by_username(db: &Database, username: &str) -> Result<Option<User>> {
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
            WHERE username = $1 AND deleted_at IS NULL
        "#;

        let row = client.query_opt(query, &[&username]).await?;
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
        }))
    }

    /// Get user by email
    pub async fn get_user_by_email(db: &Database, email: &str) -> Result<Option<User>> {
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
            WHERE email = $1 AND deleted_at IS NULL
        "#;

        let row = db.query_one(query, &[&email]).await?;
        Ok(Some(row_to_user(&row)))
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
    pub async fn record_failed_login(db: &Database, user_id: Uuid) -> Result<()> {
        let now = Utc::now();
        let query = r#"
            UPDATE users SET
                failed_login_attempts = failed_login_attempts + 1,
                last_failed_login_at = $2,
                updated_at = $2
            WHERE id = $1
        "#;
        db.execute(query, &[&user_id, &now]).await?;
        Ok(())
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

    /// Helper function to convert database row to User
    fn row_to_user(row: &tokio_postgres::Row) -> User {
        User {
            id: row.get(0),
            username: row.get(1),
            email: row.get(2),
            email_verified: row.get(3),
            first_name: row.get(4),
            last_name: row.get(5),
            phone_number: row.get(6),
            phone_verified: row.get(7),
            password_hash: row.get(8),
            totp_secret: row.get(9),
            totp_backup_codes: row.get(10),
            webauthn_enabled: row.get(11),
            account_locked: row.get(12),
            account_locked_until: row.get(13),
            failed_login_attempts: row.get(14),
            last_failed_login_at: row.get(15),
            password_changed_at: row.get(16),
            password_expires_at: row.get(17),
            require_password_change: row.get(18),
            realm_id: row.get(19),
            organization_id: row.get(20),
            attributes: row.get(21),
            enabled: row.get(22),
            federated: row.get(23),
            created_at: row.get(24),
            updated_at: row.get(25),
            deleted_at: row.get(26),
            last_login_at: row.get(27),
            login_count: row.get(28),
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
            });
        }

        Ok(users)
    }
}

/// Database operations for social accounts
pub mod social_accounts {
    use crate::{
        database::Database,
        error::Result,
        models::social_account::{CreateSocialAccountRequest, SocialAccount},
        services::social::SocialProvider,
    };
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

/// Database operations for realms
pub mod realms {
    use crate::{
        database::Database,
        error::Result,
        models::{realm::CreateRealmRequest, realm::UpdateRealmRequest, Realm},
    };
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

/// Database operations for role management
pub mod roles {
    use crate::{database::Database, error::Result, models::Role};
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

    /// Get user roles
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

/// Database operations for identity provider management
pub mod identity_providers {
    use crate::{database::Database, error::Result};
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
    use crate::{
        database::Database,
        error::Result,
        models::user::{CreateFederatedIdentityRequest, FederatedIdentity},
    };
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
    use crate::error::Result;
    use uuid::Uuid;

    /// Create authentication flow
    pub async fn create_flow(
        _db: &Database,
        _flow: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        // TODO: Implement
        Ok(serde_json::json!({}))
    }

    /// Get authentication flow by ID
    pub async fn get_flow(_db: &Database, _flow_id: Uuid) -> Result<Option<serde_json::Value>> {
        // TODO: Implement
        Ok(None)
    }

    /// List authentication flows
    pub async fn list_flows(
        _db: &Database,
        _realm_id: Option<Uuid>,
    ) -> Result<Vec<serde_json::Value>> {
        // TODO: Implement
        Ok(vec![])
    }

    /// Update authentication flow
    pub async fn update_flow(
        _db: &Database,
        _flow_id: Uuid,
        _flow: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        // TODO: Implement
        Ok(serde_json::json!({}))
    }

    /// Delete authentication flow
    pub async fn delete_flow(_db: &Database, _flow_id: Uuid) -> Result<()> {
        // TODO: Implement
        Ok(())
    }

    /// Create authentication execution
    pub async fn create_execution(
        _db: &Database,
        _execution: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        // TODO: Implement
        Ok(serde_json::json!({}))
    }

    /// Create authentication session
    pub async fn create_session(
        _db: &Database,
        _session: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        // TODO: Implement
        Ok(serde_json::json!({}))
    }
}

/// Database operations for resources
pub mod resources {
    use crate::database::Database;
    use crate::error::Result;
    use uuid::Uuid;

    /// Create resource
    pub async fn create_resource(
        _db: &Database,
        _resource: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        // TODO: Implement
        Ok(serde_json::json!({}))
    }

    /// Get resource by ID
    pub async fn get_resource(
        _db: &Database,
        _resource_id: Uuid,
    ) -> Result<Option<serde_json::Value>> {
        // TODO: Implement
        Ok(None)
    }

    /// List resources
    pub async fn list_resources(
        _db: &Database,
        _owner_id: Option<Uuid>,
    ) -> Result<Vec<serde_json::Value>> {
        // TODO: Implement
        Ok(vec![])
    }

    /// Update resource
    pub async fn update_resource(
        _db: &Database,
        _resource_id: Uuid,
        _resource: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        // TODO: Implement
        Ok(serde_json::json!({}))
    }

    /// Delete resource
    pub async fn delete_resource(_db: &Database, _resource_id: Uuid) -> Result<()> {
        // TODO: Implement
        Ok(())
    }
}
use crate::{
    database::Database,
    error::{AuthencError, Result},
    models::events::{AdminEvent, AuthDetails, Event, EventType, OperationType, ResourceType},
    spi::events::{AdminEventOperationType, AdminEventQuery, EventQuery},
};

use log::error;
use serde_json;
use std::collections::HashMap;
use uuid::Uuid;

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
    let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync>> = Vec::new();
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

    if let Some(event_types) = &query.event_types {
        if let Some(event_type) = event_types.first() {
            conditions.push(format!("event_type = ${}", param_index));
            params.push(Box::new(event_type.as_str()));
            param_index += 1;
        }
    }

    if let Some(from_date) = &query.date_from {
        conditions.push(format!("time >= ${}", param_index));
        params.push(Box::new(from_date.clone()));
        param_index += 1;
    }

    if let Some(to_date) = &query.date_to {
        conditions.push(format!("time <= ${}", param_index));
        params.push(Box::new(to_date.clone()));
        param_index += 1;
    }

    if let Some(ip_address) = &query.ip_address {
        conditions.push(format!("ip_address = ${}", param_index));
        params.push(Box::new(ip_address.clone()));
        param_index += 1;
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let limit = query.max_results.unwrap_or(100).min(1000);
    let offset = query.first_result.unwrap_or(0);

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

    let param_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
        params.iter().map(|p| p.as_ref()).collect();

    let rows: Vec<tokio_postgres::Row> = db.query(&query_sql, &param_refs).await.map_err(|e| {
        error!("Failed to query events: {}", e);
        AuthencError::database("Failed to query events")
    })?;

    let mut events = Vec::new();
    for row in rows {
        let details_json: String = row.get(10);
        let details: HashMap<String, String> =
            serde_json::from_str(&details_json).unwrap_or_default();

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
    let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync>> = Vec::new();
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
        params.push(Box::new(from_date.clone()));
        param_index += 1;
    }

    if let Some(to_date) = &query.date_to {
        conditions.push(format!("time <= ${}", param_index));
        params.push(Box::new(to_date.clone()));
        param_index += 1;
    }

    if let Some(resource_path) = &query.resource_type {
        conditions.push(format!("resource_path LIKE ${}", param_index));
        params.push(Box::new(format!("%{}%", resource_path)));
        param_index += 1;
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let limit = query.max_results.unwrap_or(100).min(1000);
    let offset = query.first_result.unwrap_or(0);

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

    let param_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
        params.iter().map(|p| p.as_ref()).collect();

    let rows: Vec<tokio_postgres::Row> = db.query(&query_sql, &param_refs).await.map_err(|e| {
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
