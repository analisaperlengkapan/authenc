use crate::app::AppState;
use crate::database::operations;
use crate::handlers::v1::auth_bearer::AuthBearer;
use axum::{
    Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::get,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

/// Create permission checking routes for a realm
pub fn create_permission_check_routes() -> Router<Arc<AppState>> {
    Router::new().route(
        "/realms/{realm}/permissions/check",
        get(check_user_permission),
    )
}

#[derive(Deserialize)]
/// Query parameters for permission checking
pub struct PermissionCheckQuery {
    /// The permission to check for the authenticated user
    pub permission: String,
}

/// Check if the authenticated user has a specific permission in the realm
pub async fn check_user_permission(
    State(state): State<Arc<AppState>>,
    Path(_realm): Path<String>,
    Query(query): Query<PermissionCheckQuery>,
    auth: AuthBearer,
) -> Result<Json<bool>, StatusCode> {
    // Extract user ID from authentication
    let user_id = Uuid::parse_str(&auth.0.sub).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Check if user has the specified permission
    let has_permission =
        operations::roles::user_has_permission(&state.database, &user_id, &query.permission)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(has_permission))
}
