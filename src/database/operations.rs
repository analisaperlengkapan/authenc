/// Database operations for device management
pub mod devices {
    use crate::{
        database::Database,
        error::Result,
        models::{Device, DeviceInfo},
    };
    use chrono::Utc;
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
                ip_address, user_agent, location_data, last_seen_at,
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
                    &device_info.ip_address.map(|ip| ip.to_string()),
                    &device_info.user_agent,
                    &now,
                    &now,
                    &now,
                    &now,
                ],
            )
            .await?;

        // Convert row to Device
        Ok(row.try_into()?)
    }

    /// Get device by ID
    pub async fn get_device_by_id(db: &Database, device_id: Uuid) -> Result<Option<Device>> {
        let query = r#"
            SELECT
                id, user_id, device_name, device_fingerprint, trust_score,
                risk_level, os, os_version, browser, browser_version,
                ip_address, user_agent, location_data, last_seen_at,
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
    use crate::{
        database::Database,
        error::Result,
        models::WebauthnCredential,
    };
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
                id, user_id, credential_id, public_key, attestation_type,
                authenticator_data, client_data_json, user_handle,
                signature_count, backup_eligible, backup_state,
                created_at, last_used_at
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
                &credential.attestation_object,
                &credential.authenticator_data,
                &credential.user_handle,
                &credential.signature_counter,
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
        Ok(row.try_into()?)
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
}

/// Database operations for organizations
pub mod organizations {
    use crate::{
        database::Database,
        error::{AuthencError, Result},
        models::{Organization, OrganizationInvitation},
    };
    use chrono::Utc;
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
        Ok(row.try_into()?)
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
        Ok(row.try_into()?)
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
    use crate::{
        database::Database,
        error::Result,
        models::AuditEvent,
    };
    
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
        let user_id = Uuid::new_v4();
        let now = Utc::now();

        let client = db.get_connection().await?;
        let user_id = Uuid::new_v4();
        let now = Utc::now();

        let query = r#"
            INSERT INTO users (
                id, username, email, email_verified, first_name, last_name,
                phone_number, phone_verified, password_hash, totp_secret,
                totp_backup_codes, webauthn_enabled, account_locked,
                account_locked_until, failed_login_attempts, last_login_at,
                last_failed_login_at, password_changed_at, password_expires_at,
                require_password_change, realm_id, organization_id, attributes,
                enabled, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)
            RETURNING
                id, username, email, email_verified, first_name, last_name,
                phone_number, phone_verified, password_hash, totp_secret,
                totp_backup_codes, webauthn_enabled, account_locked,
                account_locked_until, failed_login_attempts, last_login_at,
                last_failed_login_at, password_changed_at, password_expires_at,
                require_password_change, realm_id, organization_id, attributes,
                enabled, created_at, updated_at, deleted_at
        "#;

        let row = client
            .query_one(
                query,
                &[
                    &user_id,
                    &username,
                    &email,
                    &false, // email_verified
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
                    &None::<chrono::DateTime<Utc>>, // last_login_at
                    &None::<chrono::DateTime<Utc>>, // last_failed_login_at
                    &None::<chrono::DateTime<Utc>>, // password_changed_at
                    &None::<chrono::DateTime<Utc>>, // password_expires_at
                    &false,                         // require_password_change
                    &realm_id,
                    &organization_id,
                    &attributes_json,
                    &true, // enabled
                    &now,
                    &now,
                ],
            )
            .await?;

        // Convert row to User by extracting values directly
        let user = User {
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
            last_login_at: row.get(15),
            last_failed_login_at: row.get(16),
            password_changed_at: row.get(17),
            password_expires_at: row.get(18),
            require_password_change: row.get(19),
            realm_id: row.get(20),
            organization_id: row.get(21),
            attributes: row
                .get::<_, Option<String>>(22)
                .and_then(|s: String| serde_json::from_str(&s).ok()),
            enabled: row.get(23),
            created_at: row.get(24),
            updated_at: row.get(25),
            deleted_at: row.get(26),
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
                enabled, created_at, updated_at, deleted_at
            FROM users
            WHERE id = $1 AND deleted_at IS NULL
        "#;

        let row = client.query_opt(query, &[&user_id]).await?;
        Ok(match row {
            Some(r) => Some(User {
                id: r.get(0),
                username: r.get(1),
                email: r.get(2),
                email_verified: r.get(3),
                first_name: r.get(4),
                last_name: r.get(5),
                phone_number: r.get(6),
                phone_verified: r.get(7),
                password_hash: r.get(8),
                totp_secret: r.get(9),
                totp_backup_codes: r.get(10),
                webauthn_enabled: r.get(11),
                account_locked: r.get(12),
                account_locked_until: r.get(13),
                failed_login_attempts: r.get(14),
                last_login_at: r.get(15),
                last_failed_login_at: r.get(16),
                password_changed_at: r.get(17),
                password_expires_at: r.get(18),
                require_password_change: r.get(19),
                realm_id: r.get(20),
                organization_id: r.get(21),
                attributes: r
                    .get::<_, Option<String>>(22)
                    .and_then(|s: String| serde_json::from_str(&s).ok()),
                enabled: r.get(23),
                created_at: r.get(24),
                updated_at: r.get(25),
                deleted_at: r.get(26),
            }),
            None => None,
        })
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
                enabled, created_at, updated_at, deleted_at
            FROM users
            WHERE username = $1 AND deleted_at IS NULL
        "#;

        let row = client.query_opt(query, &[&username]).await?;
        Ok(match row {
            Some(r) => Some(User {
                id: r.get(0),
                username: r.get(1),
                email: r.get(2),
                email_verified: r.get(3),
                first_name: r.get(4),
                last_name: r.get(5),
                phone_number: r.get(6),
                phone_verified: r.get(7),
                password_hash: r.get(8),
                totp_secret: r.get(9),
                totp_backup_codes: r.get(10),
                webauthn_enabled: r.get(11),
                account_locked: r.get(12),
                account_locked_until: r.get(13),
                failed_login_attempts: r.get(14),
                last_login_at: r.get(15),
                last_failed_login_at: r.get(16),
                password_changed_at: r.get(17),
                password_expires_at: r.get(18),
                require_password_change: r.get(19),
                realm_id: r.get(20),
                organization_id: r.get(21),
                attributes: r
                    .get::<_, Option<String>>(22)
                    .and_then(|s: String| serde_json::from_str(&s).ok()),
                enabled: r.get(23),
                created_at: r.get(24),
                updated_at: r.get(25),
                deleted_at: r.get(26),
            }),
            None => None,
        })
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
                enabled, created_at, updated_at, deleted_at
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
                id, username, email, email_verified, first_name, last_name,
                phone_number, phone_verified, password_hash, totp_secret,
                totp_backup_codes, webauthn_enabled, account_locked,
                account_locked_until, failed_login_attempts, last_login_at,
                last_failed_login_at, password_changed_at, password_expires_at,
                require_password_change, realm_id, organization_id, attributes,
                enabled, created_at, updated_at, deleted_at
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
            last_login_at: row.get(15),
            last_failed_login_at: row.get(16),
            password_changed_at: row.get(17),
            password_expires_at: row.get(18),
            require_password_change: row.get(19),
            realm_id: row.get(20),
            organization_id: row.get(21),
            attributes: row
                .get::<_, Option<String>>(22)
                .and_then(|s: String| serde_json::from_str(&s).ok()),
            enabled: row.get(23),
            created_at: row.get(24),
            updated_at: row.get(25),
            deleted_at: row.get(26),
        }
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
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45)
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
