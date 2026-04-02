use crate::app::AppState;
use authenc_database::database::Database;
use crate::error::AuthencError;
use authenc_models::models::user::{JITUserProvisioningRequest, JITUserProvisioningResponse};
use authenc_services::services::admin::AdminService;
use authenc_services::services::federation::jit_provisioning::{
    DefaultJITProvisioningService, JITProvisioningService,
};
use axum::{Router, extract::State, response::Json, routing::post};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Federated authentication request
#[derive(Deserialize)]
pub struct FederatedAuthRequest {
    /// ID of the identity provider
    pub identity_provider_id: Uuid,
    /// External user ID from the identity provider
    pub external_id: String,
    /// External username from the identity provider
    pub external_username: Option<String>,
    /// External email from the identity provider
    pub external_email: Option<String>,
    /// User's first name from the identity provider
    pub first_name: Option<String>,
    /// User's last name from the identity provider
    pub last_name: Option<String>,
    /// Additional attributes from the identity provider
    pub external_attributes: Option<serde_json::Value>,
    /// ID of the realm where the user should be created
    pub realm_id: Uuid,
    /// Protocol used (saml, oidc, oauth2)
    pub protocol: String,
}

/// Federated authentication response
#[derive(Serialize)]
pub struct FederatedAuthResponse {
    /// Whether authentication was successful
    pub success: bool,
    /// The provisioned user
    pub user: Option<crate::models::User>,
    /// JIT provisioning result
    pub jit_provisioned: Option<JITUserProvisioningResponse>,
    /// Error message if authentication failed
    pub error: Option<String>,
}

/// Mock Admin Service for federated authentication
pub struct MockAdminService {
    db: Arc<Database>,
}

impl MockAdminService {
    /// Creates a new MockAdminService
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl AdminService for MockAdminService {
    async fn get_system_stats(
        &self,
    ) -> std::result::Result<crate::services::admin::SystemStats, String> {
        Err("Not implemented".to_string())
    }

    async fn get_users(
        &self,
        _realm_id: &Uuid,
        _page: u32,
        _limit: u32,
    ) -> std::result::Result<authenc_services::services::admin::UserListResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn get_user(&self, user_id: &Uuid) -> std::result::Result<authenc_services::services::admin::UserResponse, String> {
        use authenc_database::database::operations::{groups, roles, users};
        match users::get_user_by_id(&self.db, *user_id).await {
            Ok(Some(user)) => {
                let realm_id = user.realm_id.unwrap_or(Uuid::nil());
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
        request: authenc_services::services::admin::CreateUserRequest,
    ) -> std::result::Result<authenc_services::services::admin::UserResponse, String> {
        // Use the database operations to create user
        use authenc_database::database::operations::{groups, roles, users};
        use authenc_models::models::user::CreateUserRequest as DbCreateUserRequest;

        let db_request = DbCreateUserRequest {
            username: request.username,
            email: request.email,
            password: request.password,
            first_name: request.first_name,
            last_name: request.last_name,
            phone_number: request.phone_number,
            attributes: request.attributes,
            realm_id: Some(request.realm_id),
            organization_id: None, // Not provided in admin CreateUserRequest
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

                // Fetch roles and groups concurrently for the response
                let roles_future = roles::get_user_roles(&self.db, &user.id);
                let groups_future = groups::get_user_groups(&self.db, user.id);
                let (roles_result, groups_result): (
                    crate::error::Result<Vec<crate::models::Role>>,
                    crate::error::Result<Vec<crate::models::Group>>
                ) = tokio::join!(roles_future, groups_future);

                let roles = roles_result
                    .map_err(|e| format!("Failed to get user roles: {}", e))?
                    .into_iter()
                    .map(|r| r.name)
                    .collect();

                let groups = groups_result
                    .map_err(|e| format!("Failed to get user groups: {}", e))?
                    .into_iter()
                    .map(|g| g.name)
                    .collect();

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
                    roles,
                    groups,
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
        user_id: &Uuid,
        request: authenc_services::services::admin::UpdateUserRequest,
    ) -> std::result::Result<authenc_services::services::admin::UserResponse, String> {
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
                let realm_id = user.realm_id.unwrap_or(Uuid::nil());

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
            Err(e) => Err(format!("Failed to update user: {}", e)),
        }
    }

    async fn delete_user(&self, user_id: &Uuid) -> std::result::Result<(), String> {
        use authenc_database::database::operations::users;
        match users::delete_user(&self.db, *user_id).await {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Failed to delete user: {}", e)),
        }
    }

    async fn get_roles(
        &self,
        realm_id: &Uuid,
    ) -> std::result::Result<Vec<authenc_services::services::admin::RoleResponse>, String> {
        use authenc_database::database::operations::roles;
        match roles::list_roles_by_realm(&self.db, realm_id).await {
            Ok(roles) => {
                let mut responses = Vec::new();
                for role in roles {
                    responses.push(authenc_services::services::admin::RoleResponse {
                        id: role.id,
                        name: role.name,
                        description: role.description.unwrap_or_default(),
                        realm_id: role.realm_id.unwrap_or(Uuid::nil()),
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

    async fn get_role(&self, role_id: &Uuid) -> std::result::Result<authenc_services::services::admin::RoleResponse, String> {
        use authenc_database::database::operations::roles;
        match roles::get_role_by_id(&self.db, role_id).await {
            Ok(Some(role)) => Ok(authenc_services::services::admin::RoleResponse {
                id: role.id,
                name: role.name,
                description: role.description.unwrap_or_default(),
                realm_id: role.realm_id.unwrap_or(Uuid::nil()),
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
    ) -> std::result::Result<authenc_services::services::admin::RoleResponse, String> {
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
                    realm_id: role.realm_id.unwrap_or(Uuid::nil()),
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
        role_id: &Uuid,
        request: authenc_services::services::admin::UpdateRoleRequest,
    ) -> std::result::Result<authenc_services::services::admin::RoleResponse, String> {
        use authenc_database::database::operations::roles;
        // Fetch raw role from DB to preserve Option/NULL status
        let existing = roles::get_role_by_id(&self.db, role_id)
            .await
            .map_err(|e| format!("Failed to get role: {}", e))?
            .ok_or_else(|| format!("Role with ID {} not found", role_id))?;

        let name = request.name.unwrap_or(existing.name);
        let composite = request.composite.unwrap_or(existing.composite);
        let client_role = request.client_role.unwrap_or(existing.client_role);

        // Preserve NULL when no update is provided
        let description: Option<String> = if request.description.is_some() {
            request.description
        } else {
            existing.description
        };

        let attr_json: Option<String> = if let Some(attrs) = request.attributes {
            Some(serde_json::to_string(&attrs).unwrap_or_default())
        } else {
            existing.attributes.and_then(|v| serde_json::to_string(&v).ok())
        };

        let now = chrono::Utc::now();
        let update_query = r#"
            UPDATE roles
            SET name = $2, description = $3, composite = $4, client_role = $5,
                attributes = $6, updated_at = $7
            WHERE id = $1 AND deleted_at IS NULL
        "#;

        let affected = self.db.execute(update_query, &[
            role_id,
            &name,
            &description,
            &composite,
            &client_role,
            &attr_json,
            &now
        ]).await.map_err(|e| format!("Failed to update role: {}", e))?;

        if affected == 0 {
            return Err(format!("Role with ID {} not found", role_id));
        }

        // Fetch the updated role
        self.get_role(role_id).await
    }

    async fn delete_role(&self, role_id: &Uuid) -> std::result::Result<(), String> {
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
        _user_id: Option<Uuid>,
        _page: u32,
        _limit: u32,
    ) -> std::result::Result<authenc_services::services::admin::SessionListResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn terminate_session(&self, _session_id: &str) -> std::result::Result<(), String> {
        Err("Not implemented".to_string())
    }

    async fn get_audit_logs(
        &self,
        _filter: authenc_services::services::admin::AuditLogFilter,
    ) -> std::result::Result<authenc_services::services::admin::AuditLogResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn get_policies(
        &self,
        _realm_id: &Uuid,
        _page: u32,
        _limit: u32,
    ) -> std::result::Result<Vec<authenc_services::services::admin::PolicyResponse>, String> {
        Err("Not implemented".to_string())
    }

    async fn create_policy(
        &self,
        _request: authenc_services::services::admin::CreatePolicyRequest,
    ) -> std::result::Result<authenc_services::services::admin::PolicyResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn get_zero_trust_dashboard(
        &self,
        _realm_id: &Uuid,
    ) -> std::result::Result<authenc_services::services::admin::ZeroTrustDashboard, String> {
        Err("Not implemented".to_string())
    }

    async fn get_identity_providers(
        &self,
        _realm_id: &Uuid,
    ) -> std::result::Result<Vec<authenc_services::services::admin::IdentityProviderResponse>, String> {
        Err("Not implemented".to_string())
    }

    async fn create_identity_provider(
        &self,
        _request: authenc_services::services::admin::CreateIdentityProviderRequest,
    ) -> std::result::Result<authenc_services::services::admin::IdentityProviderResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn update_identity_provider(
        &self,
        _provider_id: &Uuid,
        _request: authenc_services::services::admin::UpdateIdentityProviderRequest,
    ) -> std::result::Result<authenc_services::services::admin::IdentityProviderResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn delete_identity_provider(
        &self,
        _provider_id: &Uuid,
    ) -> std::result::Result<(), String> {
        Err("Not implemented".to_string())
    }

    async fn get_identity_provider(
        &self,
        _provider_id: &Uuid,
    ) -> std::result::Result<authenc_services::services::admin::IdentityProviderResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn test_identity_provider(
        &self,
        _provider_id: &Uuid,
    ) -> std::result::Result<authenc_services::services::admin::TestIdentityProviderResponse, String> {
        Err("Not implemented".to_string())
    }
}

/// Handle federated authentication with JIT provisioning
pub async fn federated_auth(
    State(state): State<Arc<AppState>>,
    Json(request): Json<FederatedAuthRequest>,
) -> std::result::Result<Json<FederatedAuthResponse>, AuthencError> {
    // Create JIT provisioning service
    let admin_service = Arc::new(MockAdminService::new(state.database.clone()));
    let jit_service = Arc::new(DefaultJITProvisioningService::new(
        state.database.clone(),
        admin_service,
    ));

    // Convert request to JIT provisioning request
    let jit_request = JITUserProvisioningRequest {
        identity_provider_id: request.identity_provider_id,
        external_id: request.external_id,
        external_username: request.external_username,
        external_email: request.external_email,
        first_name: request.first_name,
        last_name: request.last_name,
        external_attributes: request.external_attributes,
        realm_id: request.realm_id,
    };

    // Provision user using JIT
    match jit_service.provision_user(jit_request).await {
        Ok(jit_response) => {
            let user = jit_response.user.clone(); // Clone the user to avoid partial move
            Ok(Json(FederatedAuthResponse {
                success: true,
                user: Some(user),
                jit_provisioned: Some(jit_response),
                error: None,
            }))
        }
        Err(e) => Ok(Json(FederatedAuthResponse {
            success: false,
            user: None,
            jit_provisioned: None,
            error: Some(format!("JIT provisioning failed: {}", e)),
        })),
    }
}

/// Create federated authentication routes
pub fn create_federated_auth_routes() -> Router<Arc<AppState>> {
    Router::new().route("/federated-auth", post(federated_auth))
}
