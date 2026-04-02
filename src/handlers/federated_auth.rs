use crate::app::AppState;
use authenc_database::database::Database;
use crate::error::AuthencError;
use authenc_models::models::user::{JITUserProvisioningRequest, JITUserProvisioningResponse};
use authenc_services::services::admin::{AdminManager, AdminService, AdminServiceError};
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

/// Admin Service adapter for federated authentication.
/// Delegates all operations to AdminManager to avoid code duplication.
pub struct MockAdminService {
    inner: AdminManager,
}

impl MockAdminService {
    /// Creates a new MockAdminService that delegates to AdminManager
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            inner: AdminManager::new(db),
        }
    }
}

#[async_trait::async_trait]
impl AdminService for MockAdminService {
    async fn get_system_stats(
        &self,
    ) -> std::result::Result<crate::services::admin::SystemStats, AdminServiceError> {
        self.inner.get_system_stats().await
    }

    async fn get_users(
        &self,
        realm_id: &Uuid,
        page: u32,
        limit: u32,
    ) -> std::result::Result<authenc_services::services::admin::UserListResponse, AdminServiceError> {
        self.inner.get_users(realm_id, page, limit).await
    }

    async fn get_user(&self, user_id: &Uuid) -> std::result::Result<authenc_services::services::admin::UserResponse, AdminServiceError> {
        self.inner.get_user(user_id).await
    }

    async fn create_user(
        &self,
        request: authenc_services::services::admin::CreateUserRequest,
    ) -> std::result::Result<authenc_services::services::admin::UserResponse, AdminServiceError> {
        self.inner.create_user(request).await
    }

    async fn update_user(
        &self,
        user_id: &Uuid,
        request: authenc_services::services::admin::UpdateUserRequest,
    ) -> std::result::Result<authenc_services::services::admin::UserResponse, AdminServiceError> {
        self.inner.update_user(user_id, request).await
    }

    async fn delete_user(&self, user_id: &Uuid) -> std::result::Result<(), AdminServiceError> {
        self.inner.delete_user(user_id).await
    }

    async fn get_roles(&self, realm_id: &Uuid) -> std::result::Result<Vec<authenc_services::services::admin::RoleResponse>, AdminServiceError> {
        self.inner.get_roles(realm_id).await
    }

    async fn get_role(&self, role_id: &Uuid) -> std::result::Result<authenc_services::services::admin::RoleResponse, AdminServiceError> {
        self.inner.get_role(role_id).await
    }

    async fn create_role(&self, request: authenc_services::services::admin::CreateRoleRequest) -> std::result::Result<authenc_services::services::admin::RoleResponse, AdminServiceError> {
        self.inner.create_role(request).await
    }

    async fn update_role(&self, role_id: &Uuid, request: authenc_services::services::admin::UpdateRoleRequest) -> std::result::Result<authenc_services::services::admin::RoleResponse, AdminServiceError> {
        self.inner.update_role(role_id, request).await
    }

    async fn delete_role(&self, role_id: &Uuid) -> std::result::Result<(), AdminServiceError> {
        self.inner.delete_role(role_id).await
    }

    async fn get_sessions(&self, user_id: Option<Uuid>, realm_id: Option<Uuid>, page: u32, limit: u32) -> std::result::Result<authenc_services::services::admin::SessionListResponse, AdminServiceError> {
        self.inner.get_sessions(user_id, realm_id, page, limit).await
    }

    async fn terminate_session(&self, session_id: &str) -> std::result::Result<(), AdminServiceError> {
        self.inner.terminate_session(session_id).await
    }

    async fn get_audit_logs(&self, filter: authenc_services::services::admin::AuditLogFilter) -> std::result::Result<authenc_services::services::admin::AuditLogResponse, AdminServiceError> {
        self.inner.get_audit_logs(filter).await
    }

    async fn get_policies(&self, realm_id: &Uuid, page: u32, limit: u32) -> std::result::Result<Vec<authenc_services::services::admin::PolicyResponse>, AdminServiceError> {
        self.inner.get_policies(realm_id, page, limit).await
    }

    async fn create_policy(&self, request: authenc_services::services::admin::CreatePolicyRequest) -> std::result::Result<authenc_services::services::admin::PolicyResponse, AdminServiceError> {
        self.inner.create_policy(request).await
    }

    async fn get_zero_trust_dashboard(&self, realm_id: &Uuid) -> std::result::Result<authenc_services::services::admin::ZeroTrustDashboard, AdminServiceError> {
        self.inner.get_zero_trust_dashboard(realm_id).await
    }

    async fn get_identity_providers(&self, realm_id: &Uuid) -> std::result::Result<Vec<authenc_services::services::admin::IdentityProviderResponse>, AdminServiceError> {
        self.inner.get_identity_providers(realm_id).await
    }

    async fn create_identity_provider(&self, request: authenc_services::services::admin::CreateIdentityProviderRequest) -> std::result::Result<authenc_services::services::admin::IdentityProviderResponse, AdminServiceError> {
        self.inner.create_identity_provider(request).await
    }

    async fn update_identity_provider(&self, provider_id: &Uuid, request: authenc_services::services::admin::UpdateIdentityProviderRequest) -> std::result::Result<authenc_services::services::admin::IdentityProviderResponse, AdminServiceError> {
        self.inner.update_identity_provider(provider_id, request).await
    }

    async fn delete_identity_provider(&self, provider_id: &Uuid) -> std::result::Result<(), AdminServiceError> {
        self.inner.delete_identity_provider(provider_id).await
    }

    async fn get_identity_provider(&self, provider_id: &Uuid) -> std::result::Result<authenc_services::services::admin::IdentityProviderResponse, AdminServiceError> {
        self.inner.get_identity_provider(provider_id).await
    }

    async fn test_identity_provider(&self, provider_id: &Uuid) -> std::result::Result<authenc_services::services::admin::TestIdentityProviderResponse, AdminServiceError> {
        self.inner.test_identity_provider(provider_id).await
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
