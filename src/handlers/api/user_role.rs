use crate::app::AppState;
use authenc_database::database;
use crate::handlers::api::auth_bearer::AuthBearer;
use authenc_models::models::events::{AuthDetails, OperationType, ResourceType};
use authenc_services::services::events::AdminEventBuilder;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, post},
};
use std::sync::Arc;
use uuid::Uuid;

/// Create user-role assignment routes for a realm
pub fn create_user_role_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/realms/{realm}/users/{user_id}/roles/{role}",
            post(assign_role),
        )
        .route(
            "/realms/{realm}/users/{user_id}/roles/{role}",
            delete(unassign_role),
        )
}

/// Assign a role to a user in the specified realm
pub async fn assign_role(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path((realm, user_id, role_name)): Path<(String, String, String)>,
) -> Result<StatusCode, StatusCode> {
    // Parse user ID
    let user_uuid = Uuid::parse_str(&user_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Get realm by name
    let realm_id = match uuid::Uuid::parse_str(&realm) {
        Ok(id) => id,
        Err(_) => return Err(axum::http::StatusCode::BAD_REQUEST),
    };
    let realm_obj = match state.realm_store.get_by_id(&realm_id) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Get role by name
    let role = match state.role_store.get_by_name(&role_name) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Assign role to user using database operation
    database::operations::roles::assign_role_to_user(&state.database, &user_uuid, &role.id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Fire admin event
    let auth_details = AuthDetails {
        user_id: auth.sub.clone(),
        username: None,
        ip_address: None,
        user_agent: None,
    };

    let resource_path = format!("/realms/{}/users/{}/roles/{}", realm, user_id, role_name);

    let admin_event = AdminEventBuilder::new(
        realm_obj.id.to_string(),
        auth_details,
        ResourceType::User,
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
        tracing::error!("Failed to fire admin event for role assignment: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Remove a role from a user in the specified realm
pub async fn unassign_role(
    State(state): State<Arc<AppState>>,
    AuthBearer(auth): AuthBearer,
    Path((realm, user_id, role_name)): Path<(String, String, String)>,
) -> Result<StatusCode, StatusCode> {
    // Parse user ID
    let user_uuid = Uuid::parse_str(&user_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Get realm by name
    let realm_id = match uuid::Uuid::parse_str(&realm) {
        Ok(id) => id,
        Err(_) => return Err(axum::http::StatusCode::BAD_REQUEST),
    };
    let realm_obj = match state.realm_store.get_by_id(&realm_id) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Get role by name
    let role = match state.role_store.get_by_name(&role_name) {
        Some(r) => r,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Remove role from user using database operation
    database::operations::roles::remove_role_from_user(&state.database, &user_uuid, &role.id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Fire admin event
    let auth_details = AuthDetails {
        user_id: auth.sub.clone(),
        username: None,
        ip_address: None,
        user_agent: None,
    };

    let resource_path = format!("/realms/{}/users/{}/roles/{}", realm, user_id, role_name);

    let admin_event = AdminEventBuilder::new(
        realm_obj.id.to_string(),
        auth_details,
        ResourceType::User,
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
        tracing::error!("Failed to fire admin event for role unassignment: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}
