use crate::app::AppState;
use authenc_database::database::Database;
use authenc_database::database::operations::identity_providers::get_identity_provider_by_entity_id;
use crate::error::AuthencError;
use crate::handlers::federated_auth::MockAdminService;
use authenc_models::models::user::JITUserProvisioningRequest;
use authenc_services::services::admin::AdminService;
use authenc_services::services::federation::jit_provisioning::{
    DefaultJITProvisioningService, JITProvisioningService,
};
use authenc_services::services::protocols::saml::{SamlIdentityProvider, SamlService, SamlServiceProvider};
use async_trait::async_trait;
use axum::{
    Router,
    extract::{Query, State},
    response::{Html, Redirect},
    routing::{get, post},
};
use std::sync::Arc;

/// Admin Service for SAML JIT provisioning
struct SamlAdminService {
    db: Arc<Database>,
}

#[allow(unsafe_code)]
unsafe impl Send for SamlAdminService {}
#[allow(unsafe_code)]
unsafe impl Sync for SamlAdminService {}

impl SamlAdminService {
    fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

#[async_trait]
impl AdminService for SamlAdminService {
    async fn get_system_stats(&self) -> Result<crate::services::admin::SystemStats, String> {
        Err("Not implemented".to_string())
    }

    async fn get_users(
        &self,
        _realm_id: &uuid::Uuid,
        _page: u32,
        _limit: u32,
    ) -> Result<authenc_services::services::admin::UserListResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn get_user(&self, user_id: &uuid::Uuid) -> Result<authenc_services::services::admin::UserResponse, String> {
        use authenc_database::database::operations::{groups, roles, users};
        match users::get_user_by_id(&self.db, *user_id).await {
            Ok(Some(user)) => {
                let realm_id = user.realm_id.unwrap_or(uuid::Uuid::nil());
                let user_roles = roles::get_user_roles(&self.db, &user.id)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|r| r.name)
                    .collect();
                let user_groups = groups::get_user_groups(&self.db, user.id)
                    .await
                    .unwrap_or_default();
                let group_names = user_groups.iter().map(|g| g.name.clone()).collect();

                Ok(authenc_services::services::admin::UserResponse {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    enabled: user.enabled,
                    email_verified: user.email_verified,
                    realm_id,
                    organization_id: user.organization_id,
                    roles: user_roles,
                    groups: group_names,
                    created_at: user.created_at,
                    last_login: user.last_login_at,
                    login_attempts: user.failed_login_attempts as u32,
                    locked_until: user.account_locked_until,
                })
            }
            Ok(None) => Err(format!("User with ID {} not found", user_id)),
            Err(e) => Err(format!("Failed to get user: {}", e)),
        }
    }

    async fn create_user(
        &self,
        request: crate::services::admin::CreateUserRequest,
    ) -> Result<crate::services::admin::UserResponse, String> {
        // Use the database operations to create user
        use authenc_database::database::operations::{groups, roles, users};
        use authenc_models::models::user::CreateUserRequest as DbCreateUserRequest;

        let db_request = DbCreateUserRequest {
            username: request.username.clone(),
            email: request.email.clone(),
            password: request.password.clone(),
            first_name: request.first_name.clone(),
            last_name: request.last_name.clone(),
            phone_number: request.phone_number.clone(),
            attributes: request.attributes.clone(),
            realm_id: Some(request.realm_id),
            organization_id: None,
            enabled: Some(true),
            email_verified: Some(true),
            require_password_change: Some(false),
        };

        match users::create_user(&self.db, &db_request).await {
            Ok(user) => {
                // Assign roles if provided
                if !request.roles.is_empty() {
                    let all_roles = roles::list_roles_by_realm(&self.db, &request.realm_id)
                        .await
                        .map_err(|e| format!("Failed to fetch realm roles: {}", e))?;

                    for role_name in &request.roles {
                        if let Some(role) = all_roles.iter().find(|r| r.name == *role_name) {
                            roles::assign_role_to_user(&self.db, &user.id, &role.id)
                                .await
                                .map_err(|e| {
                                    format!("Failed to assign role {}: {}", role_name, e)
                                })?;
                        }
                    }
                }

                // Assign groups if provided
                if !request.groups.is_empty() {
                    let all_groups =
                        groups::get_groups_by_realm(&self.db, request.realm_id, None, None)
                            .await
                            .map_err(|e| format!("Failed to fetch realm groups: {}", e))?;

                    for group_name in &request.groups {
                        if let Some(group) = all_groups.iter().find(|g| g.name == *group_name) {
                            groups::add_user_to_group(&self.db, user.id, group.id, None, None)
                                .await
                                .map_err(|e| {
                                    format!("Failed to add user to group {}: {}", group_name, e)
                                })?;
                        }
                    }
                }

                let user_roles = roles::get_user_roles(&self.db, &user.id)
                    .await
                    .map_err(|e| format!("Failed to get user roles: {}", e))?;

                let user_groups = groups::get_user_groups(&self.db, user.id)
                    .await
                    .map_err(|e| format!("Failed to get user groups: {}", e))?;

                Ok(crate::services::admin::UserResponse {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    email_verified: user.email_verified,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    enabled: user.enabled,
                    realm_id: user.realm_id.unwrap_or_default(),
                    organization_id: user.organization_id,
                    roles: user_roles.into_iter().map(|r| r.name).collect(),
                    groups: user_groups.into_iter().map(|g| g.name).collect(),
                    created_at: user.created_at,
                    last_login: user.last_login_at,
                    login_attempts: user.failed_login_attempts as u32,
                    locked_until: user.account_locked_until,
                })
            }
            Err(e) => Err(format!("Failed to create user: {}", e)),
        }
    }

    async fn update_user(
        &self,
        user_id: &uuid::Uuid,
        request: crate::services::admin::UpdateUserRequest,
    ) -> Result<crate::services::admin::UserResponse, String> {
        use authenc_database::database::operations::{groups, roles, users};
        let db_request = authenc_models::models::user::UpdateUserRequest {
            username: request.username,
            email: request.email,
            first_name: request.first_name,
            last_name: request.last_name,
            phone_number: request.phone_number,
            enabled: request.enabled,
            email_verified: request.email_verified,
            phone_verified: request.phone_verified,
            require_password_change: request.require_password_change,
            attributes: request.attributes,
        };

        match users::update_user(&self.db, *user_id, &db_request).await {
            Ok(user) => {
                let realm_id = user.realm_id.unwrap_or(uuid::Uuid::nil());

                // Handle group updates if provided
                if let Some(group_names) = &request.groups {
                    for group_name in group_names {
                        if let Ok(Some(group)) =
                            groups::get_group_by_name(&self.db, realm_id, group_name)
                                .await
                        {
                            let _ = groups::add_user_to_group(
                                &self.db, user.id, group.id, None, None,
                            )
                            .await;
                        }
                    }
                }

                let user_roles = roles::get_user_roles(&self.db, &user.id)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|r| r.name)
                    .collect();

                let user_groups = groups::get_user_groups(&self.db, user.id)
                    .await
                    .unwrap_or_default();
                let group_names = user_groups.iter().map(|g| g.name.clone()).collect();

                Ok(crate::services::admin::UserResponse {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    enabled: user.enabled,
                    email_verified: user.email_verified,
                    realm_id,
                    organization_id: user.organization_id,
                    roles: user_roles,
                    groups: group_names,
                    created_at: user.created_at,
                    last_login: user.last_login_at,
                    login_attempts: user.failed_login_attempts as u32,
                    locked_until: user.account_locked_until,
                })
            }
            Err(e) => Err(format!("Failed to update user: {}", e)),
        }
    }

    async fn delete_user(&self, user_id: &uuid::Uuid) -> Result<(), String> {
        use authenc_database::database::operations::users;
        match users::delete_user(&self.db, *user_id).await {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Failed to delete user: {}", e)),
        }
    }

    async fn get_roles(
        &self,
        realm_id: &uuid::Uuid,
    ) -> Result<Vec<authenc_services::services::admin::RoleResponse>, String> {
        use authenc_database::database::operations::roles;
        match roles::list_roles_by_realm(&self.db, realm_id).await {
            Ok(roles) => {
                let mut responses = Vec::new();
                for role in roles {
                    responses.push(authenc_services::services::admin::RoleResponse {
                        id: role.id,
                        name: role.name,
                        description: role.description.unwrap_or_default(),
                        realm_id: role.realm_id.unwrap_or(uuid::Uuid::nil()),
                        composite: role.composite,
                        client_role: role.client_role,
                        container_id: role.client_id,
                        attributes: role
                            .attributes
                            .and_then(|attrs| serde_json::from_value(attrs).ok())
                            .unwrap_or_default(),
                    });
                }
                Ok(responses)
            }
            Err(e) => Err(format!("Failed to get roles: {}", e)),
        }
    }

    async fn get_role(&self, role_id: &uuid::Uuid) -> Result<authenc_services::services::admin::RoleResponse, String> {
        use authenc_database::database::operations::roles;
        match roles::get_role_by_id(&self.db, role_id).await {
            Ok(Some(role)) => Ok(authenc_services::services::admin::RoleResponse {
                id: role.id,
                name: role.name,
                description: role.description.unwrap_or_default(),
                realm_id: role.realm_id.unwrap_or(uuid::Uuid::nil()),
                composite: role.composite,
                client_role: role.client_role,
                container_id: role.client_id,
                attributes: role
                    .attributes
                    .and_then(|attrs| serde_json::from_value(attrs).ok())
                    .unwrap_or_default(),
            }),
            Ok(None) => Err(format!("Role with ID {} not found", role_id)),
            Err(e) => Err(format!("Failed to get role: {}", e)),
        }
    }

    async fn create_role(
        &self,
        request: authenc_services::services::admin::CreateRoleRequest,
    ) -> Result<authenc_services::services::admin::RoleResponse, String> {
        use authenc_database::database::operations::roles;
        match roles::create_role(
            &self.db,
            &request.name,
            Some(&request.description),
            &request.realm_id,
        )
        .await
        {
            Ok(role) => {
                Ok(authenc_services::services::admin::RoleResponse {
                    id: role.id,
                    name: role.name,
                    description: role.description.unwrap_or_default(),
                    realm_id: role.realm_id.unwrap_or(uuid::Uuid::nil()),
                    composite: role.composite,
                    client_role: role.client_role,
                    container_id: role.client_id,
                    attributes: role
                        .attributes
                        .and_then(|attrs| serde_json::from_value(attrs).ok())
                        .unwrap_or_default(),
                })
            }
            Err(e) => Err(format!("Failed to create role: {}", e)),
        }
    }

    async fn update_role(
        &self,
        role_id: &uuid::Uuid,
        request: authenc_services::services::admin::CreateRoleRequest,
    ) -> Result<authenc_services::services::admin::RoleResponse, String> {
        let now = chrono::Utc::now();
        let attr_json = serde_json::to_string(&request.attributes).unwrap_or_default();
        let query = r#"
            UPDATE roles
            SET name = $2, description = $3, composite = $4, client_role = $5,
                attributes = $6, updated_at = $7
            WHERE id = $1 AND deleted_at IS NULL
            RETURNING id, name, description, realm_id, composite, client_role,
                      client_id, attributes, created_at, updated_at
        "#;

        match self.db.query_one::<tokio_postgres::Row>(query, &[
            role_id,
            &request.name,
            &Some(request.description.clone()),
            &request.composite,
            &request.client_role,
            &Some(attr_json),
            &now
        ]).await {
            Ok(row) => Ok(authenc_services::services::admin::RoleResponse {
                id: row.get(0),
                name: row.get(1),
                description: row.get::<_, Option<String>>(2).unwrap_or_default(),
                realm_id: row.get::<_, Option<uuid::Uuid>>(3).unwrap_or(uuid::Uuid::nil()),
                composite: row.get(4),
                client_role: row.get(5),
                container_id: row.get(6),
                attributes: row.get::<_, Option<String>>(7)
                    .and_then(|s: String| serde_json::from_str::<serde_json::Value>(&s).ok())
                    .and_then(|v| v.as_object().cloned())
                    .map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_array().map(|a| a.iter().map(|s| s.as_str().unwrap_or_default().to_string()).collect()).unwrap_or_default())).collect())
                    .unwrap_or_default(),
            }),
            Err(e) => Err(format!("Failed to update role: {}", e)),
        }
    }

    async fn delete_role(&self, role_id: &uuid::Uuid) -> Result<(), String> {
        let now = chrono::Utc::now();
        let query = "UPDATE roles SET deleted_at = $2, updated_at = $2 WHERE id = $1 AND deleted_at IS NULL";
        match self.db.execute(query, &[role_id, &now]).await {
            Ok(affected) if affected > 0 => Ok(()),
            Ok(_) => Err("Role not found or already deleted".to_string()),
            Err(e) => Err(format!("Failed to delete role: {}", e)),
        }
    }

    async fn get_sessions(
        &self,
        _user_id: Option<uuid::Uuid>,
        _page: u32,
        _limit: u32,
    ) -> Result<crate::services::admin::SessionListResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn terminate_session(&self, _session_id: &str) -> Result<(), String> {
        Err("Not implemented".to_string())
    }

    async fn get_audit_logs(
        &self,
        _filter: crate::services::admin::AuditLogFilter,
    ) -> Result<crate::services::admin::AuditLogResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn get_policies(
        &self,
        _realm_id: &uuid::Uuid,
        _page: u32,
        _limit: u32,
    ) -> Result<Vec<crate::services::admin::PolicyResponse>, String> {
        Err("Not implemented".to_string())
    }

    async fn create_policy(
        &self,
        _request: crate::services::admin::CreatePolicyRequest,
    ) -> Result<crate::services::admin::PolicyResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn get_zero_trust_dashboard(
        &self,
        _realm_id: &uuid::Uuid,
    ) -> Result<crate::services::admin::ZeroTrustDashboard, String> {
        Err("Not implemented".to_string())
    }

    async fn get_identity_providers(
        &self,
        _realm_id: &uuid::Uuid,
    ) -> Result<Vec<crate::services::admin::IdentityProviderResponse>, String> {
        Err("Not implemented".to_string())
    }

    async fn create_identity_provider(
        &self,
        _request: crate::services::admin::CreateIdentityProviderRequest,
    ) -> Result<crate::services::admin::IdentityProviderResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn update_identity_provider(
        &self,
        _provider_id: &uuid::Uuid,
        _request: crate::services::admin::UpdateIdentityProviderRequest,
    ) -> Result<crate::services::admin::IdentityProviderResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn delete_identity_provider(&self, _provider_id: &uuid::Uuid) -> Result<(), String> {
        Err("Not implemented".to_string())
    }

    async fn get_identity_provider(
        &self,
        _provider_id: &uuid::Uuid,
    ) -> Result<crate::services::admin::IdentityProviderResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn test_identity_provider(
        &self,
        _provider_id: &uuid::Uuid,
    ) -> Result<crate::services::admin::TestIdentityProviderResponse, String> {
        Err("Not implemented".to_string())
    }
}

/// Create SAML routes
pub fn create_saml_routes() -> Router<Database> {
    Router::new()
        .route("/sp/metadata", get(sp_metadata))
        .route("/idp/metadata", get(idp_metadata))
        .route("/auth", get(saml_auth))
        .route("/acs", post(saml_acs))
        .route("/slo", get(saml_slo))
}

fn get_default_sp_config() -> SamlServiceProvider {
    SamlServiceProvider {
        entity_id: "https://authenc.example.com/saml/sp".to_string(),
        realm_id: uuid::Uuid::nil(), // Placeholder Realm ID
        assertion_consumer_service_url: "https://authenc.example.com/saml/acs".to_string(),
        single_logout_service_url: Some("https://authenc.example.com/saml/slo".to_string()),
        name_id_format: "urn:oasis:names:tc:SAML:1.0:nameid-format:emailAddress".to_string(),
        want_assertions_signed: true,
        want_response_signed: true,
    }
}

fn get_default_idp_config() -> SamlIdentityProvider {
    SamlIdentityProvider {
        id: uuid::Uuid::nil(), // Placeholder ID
        entity_id: "https://idp.example.com/saml/idp".to_string(),
        sso_url: "https://idp.example.com/saml/auth".to_string(),
        slo_url: Some("https://idp.example.com/saml/slo".to_string()),
        certificate: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...".to_string(),
        name_id_format: "urn:oasis:names:tc:SAML:1.0:nameid-format:emailAddress".to_string(),
        want_authn_requests_signed: true,
    }
}

/// SAML service provider metadata endpoint
pub async fn sp_metadata(
    State(db): State<Database>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> std::result::Result<Html<String>, AuthencError> {
    let mut service = SamlService::new(Arc::new(db));

    // In production, load from configuration
    let sp = get_default_sp_config();
    service.register_service_provider(sp.clone());

    let default_entity_id = sp.entity_id.clone();
    let entity_id = params.get("entity_id").unwrap_or(&default_entity_id);

    match service.generate_sp_metadata(entity_id) {
        Ok(metadata) => Ok(Html(metadata)),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// SAML identity provider metadata endpoint
pub async fn idp_metadata(
    State(db): State<Database>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> std::result::Result<Html<String>, AuthencError> {
    let mut service = SamlService::new(Arc::new(db));

    // In production, load from configuration

    let mut idp = get_default_idp_config();
    // Override default IDP config (which points to external IDP) with "authenc" details
    // to represent the local Identity Provider configuration.
    idp.entity_id = "https://authenc.example.com/saml/idp".to_string();
    idp.sso_url = "https://authenc.example.com/saml/auth".to_string();
    idp.slo_url = Some("https://authenc.example.com/saml/slo".to_string());

    service.register_identity_provider(idp.clone());

    let default_entity_id = idp.entity_id.clone();
    let entity_id = params.get("entity_id").unwrap_or(&default_entity_id);

    match service.generate_idp_metadata(entity_id) {
        Ok(metadata) => Ok(Html(metadata)),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// SAML authentication initiation
pub async fn saml_auth(
    State(db): State<Database>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> std::result::Result<Redirect, AuthencError> {
    let mut service = SamlService::new(Arc::new(db));

    // Register service provider
    let sp = get_default_sp_config();
    service.register_service_provider(sp.clone());

    // Register identity provider
    let idp = get_default_idp_config();
    service.register_identity_provider(idp.clone());

    let default_sp_entity_id = sp.entity_id.clone();
    let sp_entity_id = params.get("sp").unwrap_or(&default_sp_entity_id);

    let default_idp_entity_id = idp.entity_id.clone();
    let idp_entity_id = params.get("idp").unwrap_or(&default_idp_entity_id);

    let relay_state = params.get("RelayState").map(|s| s.as_str());

    match service
        .generate_authn_request(sp_entity_id, idp_entity_id, relay_state)
        .await
    {
        Ok(redirect_url) => Ok(Redirect::to(&redirect_url)),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// SAML assertion consumer service (ACS) endpoint
pub async fn saml_acs(
    State(db): State<Database>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    _body: String,
) -> std::result::Result<Html<String>, AuthencError> {
    let mut service = SamlService::new(Arc::new(db.clone()));

    // Extract SAMLResponse from form data or query parameters
    let saml_response = if let Some(response) = params.get("SAMLResponse") {
        response
    } else {
        // In production, parse from form body
        return Err(AuthencError::validation("Bad request"));
    };

    let relay_state = params.get("RelayState").map(|s| s.as_str());

    // Extract issuer and XML to identify IdP and avoid double parsing
    let (issuer, xml) = service
        .get_issuer_and_xml_from_response(saml_response)
        .map_err(|e| AuthencError::validation(format!("Failed to parse SAML response: {}", e)))?;

    // Look up Identity Provider from database to get realm_id
    let idp_data = get_identity_provider_by_entity_id(&db, &issuer)
        .await
        .map_err(|e| AuthencError::internal(format!("Database error: {}", e)))?
        .ok_or_else(|| {
            AuthencError::resource_not_found(format!(
                "Identity Provider not found for issuer: {}",
                issuer
            ))
        })?;

    // Register IDP configuration with service
    let idp_config: SamlIdentityProvider = serde_json::from_value(idp_data.config.clone())
        .map_err(|e| {
            AuthencError::internal(format!("Invalid Identity Provider configuration: {}", e))
        })?;

    service.register_identity_provider(idp_config);

    // Use process_xml_response to avoid double decompression
    match service
        .process_xml_response(&xml, relay_state, &issuer)
        .await
    {
        Ok(user_info) => {
            // Create JIT provisioning service
            let admin_service = Arc::new(SamlAdminService::new(Arc::new(db.clone())));
            let jit_service = Arc::new(DefaultJITProvisioningService::new(
                Arc::new(db.clone()),
                admin_service,
            ));

// Helper to extract first value from attributes
            let get_attribute_value = |key: &str| -> Option<String> {
                user_info
                    .attributes
                    .get(key)
                    .and_then(|v| v.first())
                    .cloned()
            };

            // Prepare JIT provisioning request using realm_id from IDP config
            log::info!(
                "Preparing JIT provisioning request for IDP: {}",
                idp_data.id
            );
            let jit_request = JITUserProvisioningRequest {
                identity_provider_id: idp_data.id,
                external_id: user_info.name_id.clone(),
                external_username: get_attribute_value("username"),
                external_email: get_attribute_value("email"),
                first_name: get_attribute_value("firstName"),
                last_name: get_attribute_value("lastName"),
                external_attributes: Some(
                    serde_json::to_value(&user_info.attributes)
                        .map_err(|_| AuthencError::internal("Failed to serialize attributes"))?,
                ),
                realm_id: idp_data.realm_id,
            };

            // Provision user using JIT
            match jit_service.provision_user(jit_request).await {
                Ok(jit_response) => {
                    // In production, create session and redirect to application
                    let html = format!(
                        r#"<!DOCTYPE html>
<html>
<head><title>SAML Login Success</title></head>
<body>
<h1>Login Successful</h1>
<p>Welcome, {}!</p>
<p>User ID: {}</p>
<p>Session Index: {}</p>
<p>Authentication Context: {}</p>
<p>JIT Provisioned: {}</p>
<pre>{:?}</pre>
</body>
</html>"#,
                        jit_response.user.username,
                        jit_response.user.id,
                        user_info.session_index,
                        user_info.authn_context_class_ref,
                        jit_response.created,
                        user_info.attributes
                    );
                    Ok(Html(html))
                }
                Err(e) => {
                    let html = format!(
                        r#"<!DOCTYPE html>
<html>
<head><title>SAML Login Failed</title></head>
<body>
<h1>JIT Provisioning Failed</h1>
<p>Error: {}</p>
</body>
</html>"#,
                        e
                    );
                    Ok(Html(html))
                }
            }
        }
        Err(_) => {
            let html = r#"<!DOCTYPE html>
<html>
<head><title>SAML Login Failed</title></head>
<body>
<h1>Login Failed</h1>
<p>SAML authentication failed. Please try again.</p>
</body>
</html>"#;
            Ok(Html(html.to_string()))
        }
    }
}

/// SAML single logout endpoint
pub async fn saml_slo(
    State(_db): State<Database>,
    Query(_params): Query<std::collections::HashMap<String, String>>,
) -> std::result::Result<Redirect, AuthencError> {
    // In production, implement SAML logout
    // For now, redirect to home page
    Ok(Redirect::to("/"))
}
