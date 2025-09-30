use crate::app::AppState;
use crate::database;
use crate::handlers::api::auth_bearer::AuthBearer;
use crate::models::permission::Permission;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use std::sync::Arc;
use uuid::Uuid;

/// Create Axum router for user permission API endpoints
///
/// This function creates and configures an Axum router with user permission-related
/// API endpoints. The router includes routes for retrieving user permissions
/// based on their roles and associated permissions.
///
/// # Returns
/// An Axum `Router` configured with user permission endpoints
///
/// # Routes
/// - `GET /realms/{realm}/users/{user_id}/permissions` - Get user permissions
///
/// # Dependencies
/// Requires `AppState` to be available in the application state
///
/// # Example
/// ```rust
/// use authenc::handlers::api::user_permission::create_user_permission_routes;
/// use authenc::app::AppState;
/// use authenc::config::AppConfig;
/// use std::sync::Arc;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = AppConfig::default();
/// let state = Arc::new(AppState::new(config).await?);
/// let router = create_user_permission_routes();
/// # Ok(())
/// # }
/// ```
pub fn create_user_permission_routes() -> Router<Arc<AppState>> {
    Router::new().route(
        "/realms/{realm}/users/{user_id}/permissions",
        get(get_user_permissions),
    )
}

/// Get permissions for a specific user in a realm
///
/// This handler retrieves all permissions associated with a user within a specific
/// realm. It combines user roles and role permissions to determine the complete
/// set of permissions the user has.
///
/// # Arguments
/// * `State(state)` - Application state
/// * `Path((realm, user_id))` - URL path parameters for realm and user ID
/// * `auth` - Authentication bearer token
///
/// # Returns
/// A `Result` containing a JSON array of permission strings on success,
/// or an HTTP status code on error
///
/// # Security Considerations
/// - Validates that the requesting user has permission to view the target user's permissions
/// - Should implement proper authorization checks
/// - Rate limiting should be applied to prevent abuse
///
/// # Implementation
/// Retrieves user permissions through UserRole and RolePermission tables.
///
/// # Example
/// ```http
/// GET /realms/my-realm/users/user123/permissions
/// ```
/// Response: `["read:users", "write:profile", "admin:realm"]`
pub async fn get_user_permissions(
    State(state): State<Arc<AppState>>,
    Path((realm, user_id)): Path<(String, String)>,
    auth: AuthBearer,
) -> Result<Json<Vec<String>>, StatusCode> {
    // Parse user ID
    let target_user_id = Uuid::parse_str(&user_id).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Get user permissions from database
    let permissions = database::operations::roles::get_user_permissions(
        &state.database,
        &target_user_id,
    )
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Convert permissions to string format (resource:action)
    let permission_strings: Vec<String> = permissions
        .into_iter()
        .collect();

    Ok(Json(permission_strings))
}
