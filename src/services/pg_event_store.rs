use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json;
use std::sync::Arc;

use crate::database::Database;
use crate::error::{AuthencError as Error, Result};
use crate::models::events::{AdminEvent, Event, EventType};
use crate::services::events::EventStoreProvider;

/// PostgreSQL-based event store provider
pub struct PgEventStoreProvider {
    database: Arc<Database>,
}

impl PgEventStoreProvider {
    /// Create a new PostgreSQL event store provider
    pub fn new(database: Arc<Database>) -> Self {
        Self { database }
    }

    /// Initialize the database tables
    pub async fn init_tables(&self) -> Result<()> {
        // Create events table
        let create_events_table = r#"
            CREATE TABLE IF NOT EXISTS events (
                id VARCHAR(36) PRIMARY KEY,
                time TIMESTAMP WITH TIME ZONE NOT NULL,
                event_type VARCHAR(100) NOT NULL,
                realm_id VARCHAR(36) NOT NULL,
                realm_name VARCHAR(255),
                client_id VARCHAR(36),
                user_id VARCHAR(36),
                session_id VARCHAR(255),
                ip_address INET,
                error TEXT,
                details JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        "#;

        self.database
            .execute(create_events_table, &[])
            .await
            .map_err(|e| Error::database(e.to_string()))?;

        // Create indexes for events table
        let create_events_indexes = vec![
            "CREATE INDEX IF NOT EXISTS idx_events_realm_id ON events(realm_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_user_id ON events(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_client_id ON events(client_id)",
            "CREATE INDEX IF NOT EXISTS idx_events_time ON events(time)",
            "CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)",
        ];

        for index_query in create_events_indexes {
            self.database
                .execute(index_query, &[])
                .await
                .map_err(|e| Error::database(e.to_string()))?;
        }

        // Create admin_events table
        let create_admin_events_table = r#"
            CREATE TABLE IF NOT EXISTS admin_events (
                id VARCHAR(36) PRIMARY KEY,
                time TIMESTAMP WITH TIME ZONE NOT NULL,
                realm_id VARCHAR(36) NOT NULL,
                realm_name VARCHAR(255),
                operation_type VARCHAR(20) NOT NULL,
                resource_type VARCHAR(100) NOT NULL,
                resource_path TEXT NOT NULL,
                representation TEXT,
                error TEXT,
                auth_details JSONB,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
        "#;

        self.database
            .execute(create_admin_events_table, &[])
            .await
            .map_err(|e| Error::database(e.to_string()))?;

        // Add realm_name column to admin_events if it doesn't exist (migration)
        let alter_admin_events_table = "ALTER TABLE admin_events ADD COLUMN IF NOT EXISTS realm_name VARCHAR(255)";
        self.database
            .execute(alter_admin_events_table, &[])
            .await
            .map_err(|e| Error::database(e.to_string()))?;

        // Create indexes for admin_events table
        let create_admin_events_indexes = vec![
            "CREATE INDEX IF NOT EXISTS idx_admin_events_realm_id ON admin_events(realm_id)",
            "CREATE INDEX IF NOT EXISTS idx_admin_events_resource_type ON admin_events(resource_type)",
            "CREATE INDEX IF NOT EXISTS idx_admin_events_operation_type ON admin_events(operation_type)",
            "CREATE INDEX IF NOT EXISTS idx_admin_events_time ON admin_events(time)",
        ];

        for index_query in create_admin_events_indexes {
            self.database
                .execute(index_query, &[])
                .await
                .map_err(|e| Error::database(e.to_string()))?;
        }

        Ok(())
    }
}

#[async_trait]
impl EventStoreProvider for PgEventStoreProvider {
    async fn store_event(&self, event: &Event) -> Result<()> {
        let details_json =
            serde_json::to_string(&event.details).map_err(|e| Error::validation(e.to_string()))?;

        let query = r#"
            INSERT INTO events (
                id, time, event_type, realm_id, realm_name, client_id,
                user_id, session_id, ip_address, error, details
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#;

        self.database
            .query::<tokio_postgres::Row>(
                query,
                &[
                    &event.id,
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
            .map_err(|e| Error::database(e.to_string()))?;

        Ok(())
    }

    async fn store_admin_event(&self, event: &AdminEvent) -> Result<()> {
        let auth_details_json = serde_json::to_string(&event.auth_details)
            .map_err(|e| Error::validation(e.to_string()))?;

        let query = r#"
            INSERT INTO admin_events (
                id, time, realm_id, realm_name, operation_type, resource_type, resource_path,
                representation, error, auth_details
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#;

        self.database
            .query::<tokio_postgres::Row>(
                query,
                &[
                    &event.id,
                    &event.time,
                    &event.realm_id,
                    &event.realm_name,
                    &event.operation_type.as_str(),
                    &event.resource_type.as_str(),
                    &event.resource_path,
                    &event.representation,
                    &event.error,
                    &auth_details_json,
                ],
            )
            .await
            .map_err(|e| Error::database(e.to_string()))?;

        Ok(())
    }

    async fn query_events(
        &self,
        realm_id: Option<&str>,
        event_type: Option<&str>,
        user_id: Option<&str>,
        client_id: Option<&str>,
        date_from: Option<DateTime<Utc>>,
        date_to: Option<DateTime<Utc>>,
        first_result: usize,
        max_results: usize,
    ) -> Result<Vec<Event>> {
        let query = r#"
            SELECT id, time, event_type, realm_id, realm_name, client_id,
                   user_id, session_id, ip_address, error, details
            FROM events
            WHERE ($1::text IS NULL OR realm_id = $1)
              AND ($2::text IS NULL OR event_type = $2)
              AND ($3::text IS NULL OR user_id = $3)
              AND ($4::text IS NULL OR client_id = $4)
              AND ($5::timestamptz IS NULL OR time >= $5)
              AND ($6::timestamptz IS NULL OR time <= $6)
            ORDER BY time DESC
            LIMIT $7 OFFSET $8
        "#;

        let rows = self
            .database
            .query::<tokio_postgres::Row>(
                query,
                &[
                    &realm_id,
                    &event_type,
                    &user_id,
                    &client_id,
                    &date_from,
                    &date_to,
                    &(max_results as i64),
                    &(first_result as i64),
                ],
            )
            .await
            .map_err(|e| Error::database(e.to_string()))?;

        let mut events = Vec::new();
        for row in rows {
            let event_type_str: &str = row.get(2);
            let event_type = match event_type_str {
                "LOGIN" => EventType::Login,
                "LOGIN_ERROR" => EventType::LoginError,
                "LOGOUT" => EventType::Logout,
                "LOGOUT_ERROR" => EventType::LogoutError,
                "CODE_TO_TOKEN" => EventType::CodeToToken,
                "CODE_TO_TOKEN_ERROR" => EventType::CodeToTokenError,
                "CLIENT_LOGIN" => EventType::ClientLogin,
                "CLIENT_LOGIN_ERROR" => EventType::ClientLoginError,
                "REFRESH_TOKEN" => EventType::RefreshToken,
                "REFRESH_TOKEN_ERROR" => EventType::RefreshTokenError,
                "INTROSPECT_TOKEN" => EventType::IntrospectToken,
                "INTROSPECT_TOKEN_ERROR" => EventType::IntrospectTokenError,
                "REGISTER" => EventType::Register,
                "REGISTER_ERROR" => EventType::RegisterError,
                "UPDATE_PROFILE" => EventType::UpdateProfile,
                "UPDATE_PROFILE_ERROR" => EventType::UpdateProfileError,
                "UPDATE_EMAIL" => EventType::UpdateEmail,
                "UPDATE_EMAIL_ERROR" => EventType::UpdateEmailError,
                "VERIFY_EMAIL" => EventType::VerifyEmail,
                "VERIFY_EMAIL_ERROR" => EventType::VerifyEmailError,
                "VERIFY_PROFILE" => EventType::VerifyProfile,
                "VERIFY_PROFILE_ERROR" => EventType::VerifyProfileError,
                "SEND_VERIFY_EMAIL" => EventType::SendVerifyEmail,
                "SEND_VERIFY_EMAIL_ERROR" => EventType::SendVerifyEmailError,
                "SEND_RESET_PASSWORD" => EventType::SendResetPassword,
                "SEND_RESET_PASSWORD_ERROR" => EventType::SendResetPasswordError,
                "RESET_PASSWORD" => EventType::ResetPassword,
                "RESET_PASSWORD_ERROR" => EventType::ResetPasswordError,
                "UPDATE_CREDENTIAL" => EventType::UpdateCredential,
                "UPDATE_CREDENTIAL_ERROR" => EventType::UpdateCredentialError,
                "REMOVE_CREDENTIAL" => EventType::RemoveCredential,
                "REMOVE_CREDENTIAL_ERROR" => EventType::RemoveCredentialError,
                "FEDERATED_IDENTITY_LINK" => EventType::FederatedIdentityLink,
                "FEDERATED_IDENTITY_LINK_ERROR" => EventType::FederatedIdentityLinkError,
                "REMOVE_FEDERATED_IDENTITY" => EventType::RemoveFederatedIdentity,
                "REMOVE_FEDERATED_IDENTITY_ERROR" => EventType::RemoveFederatedIdentityError,
                "FEDERATED_IDENTITY_OVERRIDE_LINK" => EventType::FederatedIdentityOverrideLink,
                "FEDERATED_IDENTITY_OVERRIDE_LINK_ERROR" => {
                    EventType::FederatedIdentityOverrideLinkError
                }
                "GRANT_CONSENT" => EventType::GrantConsent,
                "GRANT_CONSENT_ERROR" => EventType::GrantConsentError,
                "UPDATE_CONSENT" => EventType::UpdateConsent,
                "UPDATE_CONSENT_ERROR" => EventType::UpdateConsentError,
                "REVOKE_GRANT" => EventType::RevokeGrant,
                "REVOKE_GRANT_ERROR" => EventType::RevokeGrantError,
                "OAUTH2_EXTENSION_GRANT" => EventType::Oauth2ExtensionGrant,
                "OAUTH2_EXTENSION_GRANT_ERROR" => EventType::Oauth2ExtensionGrantError,
                "USER_DISABLED_BY_PERMANENT_LOCKOUT" => EventType::UserDisabledByPermanentLockout,
                "USER_DISABLED_BY_PERMANENT_LOCKOUT_ERROR" => {
                    EventType::UserDisabledByPermanentLockoutError
                }
                "USER_DISABLED_BY_TEMPORARY_LOCKOUT" => EventType::UserDisabledByTemporaryLockout,
                "USER_DISABLED_BY_TEMPORARY_LOCKOUT_ERROR" => {
                    EventType::UserDisabledByTemporaryLockoutError
                }
                "INVITE_ORG" => EventType::InviteOrg,
                "INVITE_ORG_ERROR" => EventType::InviteOrgError,
                _ => continue, // Skip unknown event types
            };

            let details: serde_json::Value = row.get(10);
            let details_map = if let Some(obj) = details.as_object() {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            } else {
                std::collections::HashMap::new()
            };

            let event = Event {
                id: row.get(0),
                time: row.get(1),
                event_type,
                realm_id: row.get(3),
                realm_name: row.get(4),
                client_id: row.get(5),
                user_id: row.get(6),
                session_id: row.get(7),
                ip_address: row.get(8),
                error: row.get(9),
                details: details_map,
            };

            events.push(event);
        }

        Ok(events)
    }

    async fn query_admin_events(
        &self,
        realm_id: Option<&str>,
        operation_type: Option<&str>,
        resource_type: Option<&str>,
        auth_user: Option<&str>,
        date_from: Option<DateTime<Utc>>,
        date_to: Option<DateTime<Utc>>,
        first_result: usize,
        max_results: usize,
    ) -> Result<Vec<AdminEvent>> {
        let query = r#"
            SELECT id, time, realm_id, realm_name, operation_type, resource_type, resource_path,
                   representation, error, auth_details
            FROM admin_events
            WHERE ($1::text IS NULL OR realm_id = $1)
              AND ($2::text IS NULL OR operation_type = $2)
              AND ($3::text IS NULL OR resource_type = $3)
              AND ($4::text IS NULL OR auth_details->>'user_id' = $4)
              AND ($5::timestamptz IS NULL OR time >= $5)
              AND ($6::timestamptz IS NULL OR time <= $6)
            ORDER BY time DESC
            LIMIT $7 OFFSET $8
        "#;

        let rows = self
            .database
            .query::<tokio_postgres::Row>(
                query,
                &[
                    &realm_id,
                    &operation_type,
                    &resource_type,
                    &auth_user,
                    &date_from,
                    &date_to,
                    &(max_results as i64),
                    &(first_result as i64),
                ],
            )
            .await
            .map_err(|e| Error::database(e.to_string()))?;

        let mut events = Vec::new();
        for row in rows {
            use crate::models::events::{
                AuthDetails, OperationType as OpType, ResourceType as ResType,
            };

            let operation_type_str: &str = row.get(4);
            let operation_type = match operation_type_str {
                "CREATE" => OpType::Create,
                "UPDATE" => OpType::Update,
                "DELETE" => OpType::Delete,
                "ACTION" => OpType::Action,
                _ => continue,
            };

            let resource_type_str: &str = row.get(5);
            let resource_type = match resource_type_str {
                "REALM" => ResType::Realm,
                "REALM_ROLE" => ResType::RealmRole,
                "REALM_ROLE_MAPPING" => ResType::RealmRoleMapping,
                "REALM_SCOPE_MAPPING" => ResType::RealmScopeMapping,
                "AUTH_FLOW" => ResType::AuthFlow,
                "AUTH_EXECUTION_FLOW" => ResType::AuthExecutionFlow,
                "AUTH_EXECUTION" => ResType::AuthExecution,
                "AUTHENTICATOR_CONFIG" => ResType::AuthenticatorConfig,
                "REQUIRED_ACTION_CONFIG" => ResType::RequiredActionConfig,
                "REQUIRED_ACTION" => ResType::RequiredAction,
                "IDENTITY_PROVIDER" => ResType::IdentityProvider,
                "IDENTITY_PROVIDER_MAPPER" => ResType::IdentityProviderMapper,
                "PROTOCOL_MAPPER" => ResType::ProtocolMapper,
                "USER" => ResType::User,
                "USER_LOGIN_FAILURE" => ResType::UserLoginFailure,
                "USER_SESSION" => ResType::UserSession,
                "USER_FEDERATION_MAPPER" => ResType::UserFederationMapper,
                "USER_FEDERATION_PROVIDER" => ResType::UserFederationProvider,
                "GROUP" => ResType::Group,
                "GROUP_MEMBERSHIP" => ResType::GroupMembership,
                "CLIENT" => ResType::Client,
                "CLIENT_SCOPE" => ResType::ClientScope,
                "CLIENT_SCOPE_MAPPING" => ResType::ClientScopeMapping,
                "CLIENT_SCOPE_CLIENT_MAPPING" => ResType::ClientScopeClientMapping,
                "CLIENT_TEMPLATE" => ResType::ClientTemplate,
                "CLIENT_TEMPLATE_MAPPING" => ResType::ClientTemplateMapping,
                "CLUSTER_NODE" => ResType::ClusterNode,
                "COMPONENT" => ResType::Component,
                "AUTHORIZATION_RESOURCE_SERVER" => ResType::AuthorizationResourceServer,
                "AUTHORIZATION_RESOURCE" => ResType::AuthorizationResource,
                "AUTHORIZATION_SCOPE" => ResType::AuthorizationScope,
                "AUTHORIZATION_POLICY" => ResType::AuthorizationPolicy,
                "CUSTOM" => ResType::Custom,
                "USER_PROFILE" => ResType::UserProfile,
                "ORGANIZATION" => ResType::Organization,
                "ORGANIZATION_MEMBERSHIP" => ResType::OrganizationMembership,
                _ => continue,
            };

            let auth_details_json: serde_json::Value = row.get(9);
            let auth_details = if let Some(obj) = auth_details_json.as_object() {
                AuthDetails {
                    user_id: obj
                        .get("user_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    username: obj
                        .get("username")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    ip_address: obj
                        .get("ip_address")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    user_agent: obj
                        .get("user_agent")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                }
            } else {
                AuthDetails {
                    user_id: "".to_string(),
                    username: None,
                    ip_address: None,
                    user_agent: None,
                }
            };

            let event = AdminEvent {
                id: row.get(0),
                time: row.get(1),
                realm_id: row.get(2),
                realm_name: row.get(3),
                auth_details,
                resource_type,
                operation_type,
                resource_path: row.get(6),
                representation: row.get(7),
                error: row.get(8),
            };

            events.push(event);
        }

        Ok(events)
    }

    async fn clear_old_events(&self, older_than: DateTime<Utc>) -> Result<usize> {
        let query = "DELETE FROM events WHERE time < $1";
        let result = self
            .database
            .execute(query, &[&older_than])
            .await
            .map_err(|e| Error::database(e.to_string()))?;

        Ok(result as usize)
    }
}
