use crate::app::AppState;
use crate::database::Database;
use crate::error::AuthencError;
use crate::models::user::{JITUserProvisioningRequest, JITUserProvisioningResponse};
use crate::services::admin::AdminService;
use crate::services::federation::jit_provisioning::{
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
struct MockAdminService {
    db: Arc<Database>,
}

impl MockAdminService {
    fn new(db: Arc<Database>) -> Self {
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
    ) -> std::result::Result<crate::services::admin::UserListResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn create_user(
        &self,
        request: crate::services::admin::CreateUserRequest,
    ) -> std::result::Result<crate::services::admin::UserResponse, String> {
        // Use the database operations to create user
        use crate::database::operations::{groups, roles, users};
        use crate::models::user::CreateUserRequest as DbCreateUserRequest;

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
        };

        match users::create_user(&self.db, &db_request).await {
            Ok(user) => {
                let (roles_result, groups_result) = tokio::join!(
                    roles::get_user_roles(&self.db, &user.id),
                    groups::get_user_groups(&self.db, user.id)
                );

                Ok(crate::services::admin::UserResponse {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    email_verified: user.email_verified,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    enabled: user.enabled,
                    realm_id: user.realm_id.unwrap_or_default(),
                    roles: roles_result
                        .unwrap_or_default()
                        .into_iter()
                        .map(|r| r.name)
                        .collect(),
                    groups: groups_result
                        .unwrap_or_default()
                        .into_iter()
                        .map(|g| g.name)
                        .collect(),
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
        _user_id: &Uuid,
        _request: crate::services::admin::UpdateUserRequest,
    ) -> std::result::Result<crate::services::admin::UserResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn delete_user(&self, _user_id: &Uuid) -> std::result::Result<(), String> {
        Err("Not implemented".to_string())
    }

    async fn get_roles(
        &self,
        _realm_id: &Uuid,
    ) -> std::result::Result<Vec<crate::services::admin::RoleResponse>, String> {
        Err("Not implemented".to_string())
    }

    async fn create_role(
        &self,
        _request: crate::services::admin::CreateRoleRequest,
    ) -> std::result::Result<crate::services::admin::RoleResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn get_sessions(
        &self,
        _user_id: Option<Uuid>,
        _page: u32,
        _limit: u32,
    ) -> std::result::Result<crate::services::admin::SessionListResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn terminate_session(&self, _session_id: &str) -> std::result::Result<(), String> {
        Err("Not implemented".to_string())
    }

    async fn get_audit_logs(
        &self,
        _filter: crate::services::admin::AuditLogFilter,
    ) -> std::result::Result<crate::services::admin::AuditLogResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn get_policies(
        &self,
        _realm_id: &Uuid,
    ) -> std::result::Result<Vec<crate::services::admin::PolicyResponse>, String> {
        Err("Not implemented".to_string())
    }

    async fn create_policy(
        &self,
        _request: crate::services::admin::CreatePolicyRequest,
    ) -> std::result::Result<crate::services::admin::PolicyResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn get_zero_trust_dashboard(
        &self,
        _realm_id: &Uuid,
    ) -> std::result::Result<crate::services::admin::ZeroTrustDashboard, String> {
        Err("Not implemented".to_string())
    }

    async fn get_identity_providers(
        &self,
        _realm_id: &Uuid,
    ) -> std::result::Result<Vec<crate::services::admin::IdentityProviderResponse>, String> {
        Err("Not implemented".to_string())
    }

    async fn create_identity_provider(
        &self,
        _request: crate::services::admin::CreateIdentityProviderRequest,
    ) -> std::result::Result<crate::services::admin::IdentityProviderResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn update_identity_provider(
        &self,
        _provider_id: &Uuid,
        _request: crate::services::admin::UpdateIdentityProviderRequest,
    ) -> std::result::Result<crate::services::admin::IdentityProviderResponse, String> {
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
    ) -> std::result::Result<crate::services::admin::IdentityProviderResponse, String> {
        Err("Not implemented".to_string())
    }

    async fn test_identity_provider(
        &self,
        _provider_id: &Uuid,
    ) -> std::result::Result<crate::services::admin::TestIdentityProviderResponse, String> {
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
