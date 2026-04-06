use crate::app::AppState;
use crate::error::AuthencError;
use authenc_models::models::user::{JITUserProvisioningRequest, JITUserProvisioningResponse};
use authenc_services::services::admin::AdminManager;
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

/// Handle federated authentication with JIT provisioning
pub async fn federated_auth(
    State(state): State<Arc<AppState>>,
    Json(request): Json<FederatedAuthRequest>,
) -> std::result::Result<Json<FederatedAuthResponse>, AuthencError> {
    // Create JIT provisioning service using AdminManager directly
    // (AdminManager already implements AdminService)
    let admin_service = Arc::new(AdminManager::new(state.database.clone()));
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
