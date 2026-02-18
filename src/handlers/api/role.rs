use crate::app::AppState;
use crate::handlers::api::auth_bearer::AuthBearer;
use authenc_models::models::events::{OperationType, ResourceType};
use authenc_models::models::role::Role;
use authenc_services::services::events::AdminEventBuilder;
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

/// Create role management routes for a realm
pub fn create_role_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/realms/{realm}/roles", get(get_roles))
        .route("/realms/{realm}/roles", post(create_role))
        .route("/realms/{realm}/roles/{name}", delete(delete_role))
        .route(
            "/realms/{realm}/roles/{role}/permissions/{permission}",
            post(assign_permission_to_role),
        )
        .route(
            "/realms/{realm}/roles/{role}/permissions/{permission}",
            delete(unassign_permission_from_role),
        )
}

/// Get all roles in the specified realm
pub async fn get_roles(
    State(state): State<Arc<AppState>>,
    Path(realm): Path<String>,
) -> Result<Json<Vec<Role>>, StatusCode> {
    // Get realm by name to get the UUID
    let realm_obj = match state.realm_store.get_by_name(&realm) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    let roles = state.role_store.get_by_realm(&realm_obj.id.to_string());
    Ok(Json(roles))
}

#[derive(Deserialize, Clone)]
/// Request payload for creating a new role within a realm
pub struct CreateRoleRequest {
    /// The unique name identifier for the role
    pub name: String,
    /// Optional description of the role's purpose
    pub description: Option<String>,
    /// Whether this is a composite role (contains other roles)
    pub composite: Option<bool>,
    /// Whether this is a client-specific role
    pub client_role: Option<bool>,
    /// Client identifier if this is a client role
    pub client_id: Option<String>,
    /// Additional role attributes as JSON
    pub attributes: Option<serde_json::Value>,
}

/// Create a new role in the specified realm
pub async fn create_role(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path(realm): Path<String>,
    Json(req): Json<CreateRoleRequest>,
) -> Result<StatusCode, StatusCode> {
    // Get realm by name to get the UUID
    let realm_obj = match state.realm_store.get_by_name(&realm) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Check if role already exists
    if state.role_store.get_by_name(&req.name).is_some() {
        return Err(StatusCode::CONFLICT);
    }

    // Create the role
    let role = Role {
        id: Uuid::new_v4(),
        name: req.name.clone(),
        description: req.description,
        realm_id: Some(realm_obj.id),
        composite: req.composite.unwrap_or(false),
        client_role: req.client_role.unwrap_or(false),
        client_id: req.client_id,
        attributes: req.attributes,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        deleted_at: None,
    };

    state.role_store.add_role(role.clone());

    // Fire admin event
    let auth_details = crate::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,   // Could be looked up from user store if needed
        ip_address: None, // Could be extracted from request headers
        user_agent: None, // Could be extracted from request headers
    };

    let resource_path = format!("/realms/{}/roles/{}", realm, role.name);
    let representation = serde_json::to_string(&role).unwrap_or_default();

    let admin_event = AdminEventBuilder::new(
        realm_obj.id.to_string(),
        auth_details,
        ResourceType::RealmRole,
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
        tracing::error!("Failed to fire admin event for role creation: {}", e);
    }

    Ok(StatusCode::CREATED)
}

/// Delete a role from the specified realm
pub async fn delete_role(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path((realm, name)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    // Get realm by name to get the UUID
    let realm_obj = match state.realm_store.get_by_name(&realm) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Get the role before deleting for event representation
    let role = match state.role_store.get_by_name(&name) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Delete the role
    if !state
        .role_store
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

    let resource_path = format!("/realms/{}/roles/{}", realm, name);
    let representation = serde_json::to_string(&role).unwrap_or_default();

    let admin_event = AdminEventBuilder::new(
        realm_obj.id.to_string(),
        auth_details,
        ResourceType::RealmRole,
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
        tracing::error!("Failed to fire admin event for role deletion: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Assign a permission to a role in the specified realm
pub async fn assign_permission_to_role(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path((realm, role_name, permission)): Path<(String, String, String)>,
) -> Result<StatusCode, StatusCode> {
    // Get realm by name to get the UUID
    let realm_obj = match state.realm_store.get_by_name(&realm) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Get role by name
    let role = match state.role_store.get_by_name(&role_name) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Get permission by name
    let permission_obj = match state.permission_store.get_by_resource(&permission) {
        Some(p) => p,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Assign permission to role using database operation
    crate::database::operations::roles::assign_permission_to_role(
        &state.database,
        &role.id,
        &permission_obj.id,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Fire admin event
    let auth_details = crate::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,
        ip_address: None,
        user_agent: None,
    };

    let resource_path = format!(
        "/realms/{}/roles/{}/permissions/{}",
        realm, role_name, permission
    );

    let admin_event = AdminEventBuilder::new(
        realm_obj.id.to_string(),
        auth_details,
        ResourceType::RealmRole,
        OperationType::Update,
        resource_path,
    )
    .build();

    if let Err(e) = state
        .event_manager
        .write()
        .await
        .fire_admin_event(admin_event, true)
        .await
    {
        tracing::error!(
            "Failed to fire admin event for permission assignment: {}",
            e
        );
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Remove a permission from a role in the specified realm
pub async fn unassign_permission_from_role(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path((realm, role_name, permission)): Path<(String, String, String)>,
) -> Result<StatusCode, StatusCode> {
    // Get realm by name to get the UUID
    let realm_obj = match state.realm_store.get_by_name(&realm) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Get role by name
    let role = match state.role_store.get_by_name(&role_name) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Get permission by name
    let permission_obj = match state.permission_store.get_by_resource(&permission) {
        Some(p) => p,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Remove permission from role using database operation
    crate::database::operations::roles::remove_permission_from_role(
        &state.database,
        &role.id,
        &permission_obj.id,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Fire admin event
    let auth_details = crate::models::events::AuthDetails {
        user_id: auth.sub.clone(),
        username: None,
        ip_address: None,
        user_agent: None,
    };

    let resource_path = format!(
        "/realms/{}/roles/{}/permissions/{}",
        realm, role_name, permission
    );

    let admin_event = AdminEventBuilder::new(
        realm_obj.id.to_string(),
        auth_details,
        ResourceType::RealmRole,
        OperationType::Update,
        resource_path,
    )
    .build();

    if let Err(e) = state
        .event_manager
        .write()
        .await
        .fire_admin_event(admin_event, true)
        .await
    {
        tracing::error!(
            "Failed to fire admin event for permission unassignment: {}",
            e
        );
    }

    Ok(StatusCode::NO_CONTENT)
}
