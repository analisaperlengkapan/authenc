use crate::app::AppState;
use crate::handlers::api::auth_bearer::AuthBearer;
use crate::models::events::{OperationType, ResourceType};
use crate::models::permission::Permission;
use crate::services::events::AdminEventBuilder;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

/// Create permission management routes for a realm
pub fn create_permission_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/realms/{realm}/permissions", get(get_permissions))
        .route("/realms/{realm}/permissions", post(create_permission))
        .route(
            "/realms/{realm}/permissions/{name}",
            delete(delete_permission),
        )
}

/// Get all permissions in the specified realm
pub async fn get_permissions(
    State(state): State<Arc<AppState>>,
    Path(realm): Path<String>,
) -> Result<Json<Vec<Permission>>, StatusCode> {
    // Get realm by name to get the UUID
    let realm_obj = match state.realm_store.get_by_name(&realm) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let permissions = state
        .permission_store
        .get_by_realm(&realm_obj.id.to_string());
    Ok(Json(permissions))
}

#[derive(Deserialize)]
/// Request payload for creating a new permission within a realm
pub struct CreatePermissionRequest {
    /// Unique name identifier for the permission
    pub name: String,
    /// Resource this permission applies to
    pub resource: String,
    /// Action allowed on the resource (read, write, delete, etc.)
    pub action: String,
    /// Optional description of what the permission allows
    pub description: Option<String>,
}

/// Create a new permission in the specified realm
pub async fn create_permission(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path(realm): Path<String>,
    Json(req): Json<CreatePermissionRequest>,
) -> Result<StatusCode, StatusCode> {
    // Get realm by name to get the UUID
    let realm_obj = match state.realm_store.get_by_name(&realm) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Create the permission
    let permission = Permission {
        id: Uuid::new_v4(),
        name: req.name.clone(),
        resource: req.resource,
        action: req.action,
        description: req.description,
        realm_id: realm_obj.id,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        deleted_at: None,
    };

    state.permission_store.add_permission(permission.clone());

    // Fire admin event
    let auth_details = crate::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,   // Could be looked up from user store if needed
        ip_address: None, // Could be extracted from request headers
        user_agent: None, // Could be extracted from request headers
    };

    let resource_path = format!("/realms/{}/permissions/{}", realm, permission.name);
    let representation = serde_json::to_string(&permission).unwrap_or_default();

    let admin_event = AdminEventBuilder::new(
        realm_obj.id.to_string(),
        auth_details,
        ResourceType::AuthorizationPolicy,
        OperationType::Create,
        resource_path,
    )
    .representation(representation)
    .build();

    if let Err(e) = state
        .event_manager
        .write()
        .await
        .fire_admin_event(admin_event, true)
        .await
    {
        tracing::error!("Failed to fire admin event for permission creation: {}", e);
    }

    Ok(StatusCode::CREATED)
}

/// Delete a permission from the specified realm
pub async fn delete_permission(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path((realm, name)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    // Get realm by name to get the UUID
    let realm_obj = match state.realm_store.get_by_name(&realm) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Get the permission before deleting for event representation
    let permission = match state.permission_store.get_by_resource(&name) {
        Some(p) => p,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Delete the permission
    if !state
        .permission_store
        .delete_by_name(&realm_obj.id.to_string(), &name)
    {
        return Err(StatusCode::NOT_FOUND);
    }

    // Fire admin event
    let auth_details = crate::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,   // Could be looked up from user store if needed
        ip_address: None, // Could be extracted from request headers
        user_agent: None, // Could be extracted from request headers
    };

    let resource_path = format!("/realms/{}/permissions/{}", realm, name);
    let representation = serde_json::to_string(&permission).unwrap_or_default();

    let admin_event = AdminEventBuilder::new(
        realm_obj.id.to_string(),
        auth_details,
        ResourceType::AuthorizationPolicy,
        OperationType::Delete,
        resource_path,
    )
    .representation(representation)
    .build();

    if let Err(e) = state
        .event_manager
        .write()
        .await
        .fire_admin_event(admin_event, true)
        .await
    {
        tracing::error!("Failed to fire admin event for permission deletion: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}
