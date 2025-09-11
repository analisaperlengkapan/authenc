use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post, delete},
    Router,
};
use crate::services::role_store::RoleStore;
use crate::models::role::Role;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

pub fn create_role_routes() -> Router<Arc<RoleStore>> {
    Router::new()
        .route("/realms/{realm}/roles", get(get_roles))
        .route("/realms/{realm}/roles", post(create_role))
        .route("/realms/{realm}/roles/{name}", delete(delete_role))
        .route("/realms/{realm}/roles/{role}/permissions/{permission}", post(assign_permission_to_role))
        .route("/realms/{realm}/roles/{role}/permissions/{permission}", delete(unassign_permission_from_role))
}

pub async fn get_roles(
    State(_store): State<Arc<RoleStore>>,
    Path(_realm): Path<String>,
) -> Result<Json<Vec<Role>>, StatusCode> {
    // TODO: Implement with new Role model structure
    Err(StatusCode::NOT_IMPLEMENTED)
}

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
}

pub async fn create_role(
    State(_store): State<Arc<RoleStore>>,
    Path(_realm): Path<String>,
    Json(_req): Json<CreateRoleRequest>,
) -> Result<StatusCode, StatusCode> {
    // TODO: Implement with new Role model structure
    Err(StatusCode::NOT_IMPLEMENTED)
}

pub async fn delete_role(
    State(_store): State<Arc<RoleStore>>,
    Path((_realm, _name)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    // TODO: Implement with new Role model structure
    Err(StatusCode::NOT_IMPLEMENTED)
}

pub async fn assign_permission_to_role(
    State(_store): State<Arc<RoleStore>>,
    Path((_realm, _role_name, _permission)): Path<(String, String, String)>,
) -> Result<StatusCode, StatusCode> {
    // TODO: Implement with new Role model structure
    Err(StatusCode::NOT_IMPLEMENTED)
}

pub async fn unassign_permission_from_role(
    State(_store): State<Arc<RoleStore>>,
    Path((_realm, _role_name, _permission)): Path<(String, String, String)>,
) -> Result<StatusCode, StatusCode> {
    // TODO: Implement with new Role model structure
    Err(StatusCode::NOT_IMPLEMENTED)
}