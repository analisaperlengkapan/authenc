use crate::app::AppState;
use crate::error::AuthencError;
use authenc_services::services::admin::{
    AdminManager, AdminService, AdminServiceError, AuditLogResponse,
    CreateIdentityProviderRequest, CreatePolicyRequest, CreateRoleRequest, CreateUserRequest,
    IdentityProviderResponse, PolicyResponse, RoleResponse, SecurityEvent, SessionListResponse,
    SystemStats, TestIdentityProviderResponse, UpdateIdentityProviderRequest, UpdateRoleRequest,
    UpdateUserRequest, UserListResponse, UserResponse,
};
use axum::{
    Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

/// Convert an AdminServiceError to an appropriate HTTP StatusCode
fn admin_error_to_status(e: &AdminServiceError) -> StatusCode {
    match e {
        AdminServiceError::NotFound(_) | AdminServiceError::AlreadyDeleted(_) => {
            StatusCode::NOT_FOUND
        }
        AdminServiceError::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
        AdminServiceError::BadRequest(_) => StatusCode::BAD_REQUEST,
        AdminServiceError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

#[derive(Deserialize)]
/// Query parameters for listing users with filtering and pagination
pub struct ListUsersQuery {
    /// Filter users by realm ID
    pub realm_id: Option<Uuid>,
    /// Search users by username, email, or name
    pub search: Option<String>,
    /// Filter by enabled status
    pub enabled: Option<bool>,
    /// Page number for pagination
    pub page: Option<u32>,
    /// Number of items per page
    pub limit: Option<u32>,
}

#[derive(Deserialize)]
/// Query parameters for listing user sessions with filtering and pagination
pub struct ListSessionsQuery {
    /// Filter sessions by user ID
    pub user_id: Option<Uuid>,
    /// Filter sessions by realm ID
    pub realm_id: Option<Uuid>,
    /// Page number for pagination
    pub page: Option<u32>,
    /// Number of items per page
    pub limit: Option<u32>,
}

#[derive(Deserialize)]
/// Query parameters for listing audit logs with filtering and pagination
pub struct ListAuditLogsQuery {
    /// Filter audit logs by user ID
    pub user_id: Option<Uuid>,
    /// Filter audit logs by event type
    pub event_type: Option<String>,
    /// Filter audit logs by realm ID
    pub realm_id: Option<Uuid>,
    /// Filter audit logs from this date
    pub from_date: Option<chrono::DateTime<chrono::Utc>>,
    /// Filter audit logs until this date
    pub to_date: Option<chrono::DateTime<chrono::Utc>>,
    /// Page number for pagination
    pub page: Option<u32>,
    /// Number of items per page
    pub limit: Option<u32>,
}

#[derive(Deserialize)]
/// Query parameters for listing roles with filtering and pagination
pub struct ListRolesQuery {
    /// Filter roles by realm ID
    pub realm_id: Option<Uuid>,
    /// Filter by composite roles
    pub composite: Option<bool>,
    /// Page number for pagination
    pub page: Option<u32>,
    /// Number of items per page
    pub limit: Option<u32>,
}

#[derive(Deserialize)]
/// Query parameters for listing policies with filtering and pagination
pub struct ListPoliciesQuery {
    /// Filter policies by realm ID
    pub realm_id: Option<Uuid>,
    /// Filter by enabled status
    pub enabled: Option<bool>,
    /// Page number for pagination
    pub page: Option<u32>,
    /// Number of items per page
    pub limit: Option<u32>,
}

/// Get system statistics
pub async fn get_system_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SystemStats>, StatusCode> {
    // Use AdminManager which has optimized aggregate queries
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager.get_system_stats().await {
        Ok(stats) => Ok(Json(stats)),
        Err(e) => {
            eprintln!("Failed to get system stats: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Get dashboard data
pub async fn get_dashboard_data(
    State(_state): State<Arc<AppState>>,
    Query(_query): Query<ListUsersQuery>,
) -> Result<Json<serde_json::Value>, AuthencError> {
    // Mock response - in real implementation would fetch from service
    let dashboard = serde_json::json!({
        "total_users": 100,
        "active_users": 25,
        "total_sessions": 50,
        "security_events_today": 3,
        "compliance_rate": 0.95
    });
    Ok(Json(dashboard))
}

/// List users with filtering and pagination
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListUsersQuery>,
) -> Result<Json<UserListResponse>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    // Require realm_id or use master realm from config/store if implemented.
    // For now, returning 400 Bad Request if realm_id is missing is safer than Uuid::new_v4()
    let realm_id = match query.realm_id {
        Some(id) => id,
        None => {
            // Attempt to get "master" realm, otherwise fail
            if let Some(master) = state.realm_store.get_by_name("master") {
                master.id
            } else {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    };

    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(20);

    match admin_manager.get_users(&realm_id, page, limit).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            eprintln!("Failed to list users: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Get user by ID
pub async fn get_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserResponse>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager.get_user(&user_id).await {
        Ok(user) => Ok(Json(user)),
        Err(e) => {
            eprintln!("Failed to get user: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Create a new user
pub async fn create_user(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateUserRequest>,
) -> Result<Json<UserResponse>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager.create_user(request).await {
        Ok(user) => Ok(Json(user)),
        Err(e) => {
            eprintln!("Failed to create user: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Update user
pub async fn update_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager.update_user(&user_id, request).await {
        Ok(user) => Ok(Json(user)),
        Err(e) => {
            eprintln!("Failed to update user: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Delete user
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager.delete_user(&user_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            eprintln!("Failed to delete user: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// List user sessions
pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListSessionsQuery>,
) -> Result<Json<SessionListResponse>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(20);

    match admin_manager
        .get_sessions(query.user_id, page, limit)
        .await
    {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            eprintln!("Failed to list sessions: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Terminate user session
pub async fn terminate_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager.terminate_session(&session_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            eprintln!("Failed to terminate session: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// List audit logs
pub async fn list_audit_logs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListAuditLogsQuery>,
) -> Result<Json<AuditLogResponse>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    let filter = authenc_services::services::admin::AuditLogFilter {
        user_id: query.user_id,
        event_type: query.event_type,
        realm_id: query.realm_id,
        from_date: query.from_date,
        to_date: query.to_date,
        page: query.page.unwrap_or(1),
        limit: query.limit.unwrap_or(50),
    };

    match admin_manager.get_audit_logs(filter).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            eprintln!("Failed to list audit logs: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// List roles
pub async fn list_roles(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListRolesQuery>,
) -> Result<Json<Vec<RoleResponse>>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());
    let realm_id = match query.realm_id {
        Some(id) => id,
        None => {
            // Attempt to get "master" realm, otherwise fail
            if let Some(master) = state.realm_store.get_by_name("master") {
                master.id
            } else {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    };

    match admin_manager.get_roles(&realm_id).await {
        Ok(roles) => Ok(Json(roles)),
        Err(e) => {
            eprintln!("Failed to list roles: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Create role
pub async fn create_role(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateRoleRequest>,
) -> Result<Json<RoleResponse>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager.create_role(request).await {
        Ok(role) => Ok(Json(role)),
        Err(e) => {
            eprintln!("Failed to create role: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Get role by ID
pub async fn get_role(
    State(state): State<Arc<AppState>>,
    Path(role_id): Path<Uuid>,
) -> Result<Json<RoleResponse>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager.get_role(&role_id).await {
        Ok(role) => Ok(Json(role)),
        Err(e) => {
            eprintln!("Failed to get role: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Update role
pub async fn update_role(
    State(state): State<Arc<AppState>>,
    Path(role_id): Path<Uuid>,
    Json(request): Json<UpdateRoleRequest>,
) -> Result<Json<RoleResponse>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager.update_role(&role_id, request).await {
        Ok(role) => Ok(Json(role)),
        Err(e) => {
            eprintln!("Failed to update role: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Delete role
pub async fn delete_role(
    State(state): State<Arc<AppState>>,
    Path(role_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager.delete_role(&role_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            eprintln!("Failed to delete role: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// List authorization policies
pub async fn list_policies(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListPoliciesQuery>,
) -> Result<Json<Vec<PolicyResponse>>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());
    let realm_id = match query.realm_id {
        Some(id) => id,
        None => {
            // Attempt to get "master" realm, otherwise fail
            if let Some(master) = state.realm_store.get_by_name("master") {
                master.id
            } else {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    };
    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(20);

    match admin_manager.get_policies(&realm_id, page, limit).await {
        Ok(policies) => Ok(Json(policies)),
        Err(e) => {
            eprintln!("Failed to list policies: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Create authorization policy
pub async fn create_policy(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreatePolicyRequest>,
) -> Result<Json<PolicyResponse>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager.create_policy(request).await {
        Ok(policy) => Ok(Json(policy)),
        Err(e) => {
            eprintln!("Failed to create policy: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Get security events
pub async fn get_security_events(
    State(_state): State<Arc<AppState>>,
    Query(_query): Query<ListAuditLogsQuery>,
) -> Result<Json<Vec<SecurityEvent>>, StatusCode> {
    // Mock response - in real implementation would fetch from service
    Ok(Json(vec![]))
}

/// Get risk analytics
pub async fn get_risk_analytics(
    State(_state): State<Arc<AppState>>,
    Query(_query): Query<ListUsersQuery>,
) -> Result<Json<serde_json::Value>, AuthencError> {
    // Mock response - in real implementation would fetch from service
    let analytics = serde_json::json!({
        "risk_distribution": {"low": 80, "medium": 15, "high": 5},
        "top_risk_users": [],
        "security_events": [],
        "device_trust_stats": {},
        "adaptive_controls_stats": {}
    });
    Ok(Json(analytics))
}

/// List identity providers
pub async fn list_identity_providers(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListIdentityProvidersQuery>,
) -> Result<Json<Vec<IdentityProviderResponse>>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());
    let realm_id = match query.realm_id {
        Some(id) => id,
        None => {
            // Attempt to get "master" realm, otherwise fail
            if let Some(master) = state.realm_store.get_by_name("master") {
                master.id
            } else {
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    };

    match admin_manager.get_identity_providers(&realm_id).await {
        Ok(providers) => Ok(Json(providers)),
        Err(e) => {
            eprintln!("Failed to list identity providers: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Get identity provider by ID
pub async fn get_identity_provider(
    State(state): State<Arc<AppState>>,
    Path(provider_id): Path<Uuid>,
) -> Result<Json<IdentityProviderResponse>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager.get_identity_provider(&provider_id).await {
        Ok(provider) => Ok(Json(provider)),
        Err(e) => {
            eprintln!("Failed to get identity provider: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Create identity provider
pub async fn create_identity_provider(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateIdentityProviderRequest>,
) -> Result<Json<IdentityProviderResponse>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager.create_identity_provider(request).await {
        Ok(provider) => Ok(Json(provider)),
        Err(e) => {
            eprintln!("Failed to create identity provider: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Update identity provider
pub async fn update_identity_provider(
    State(state): State<Arc<AppState>>,
    Path(provider_id): Path<Uuid>,
    Json(request): Json<UpdateIdentityProviderRequest>,
) -> Result<Json<IdentityProviderResponse>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager
        .update_identity_provider(&provider_id, request)
        .await
    {
        Ok(provider) => Ok(Json(provider)),
        Err(e) => {
            eprintln!("Failed to update identity provider: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Delete identity provider
pub async fn delete_identity_provider(
    State(state): State<Arc<AppState>>,
    Path(provider_id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager.delete_identity_provider(&provider_id).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(e) => {
            eprintln!("Failed to delete identity provider: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

/// Test identity provider connection
pub async fn test_identity_provider(
    State(state): State<Arc<AppState>>,
    Path(provider_id): Path<Uuid>,
) -> Result<Json<TestIdentityProviderResponse>, StatusCode> {
    let admin_manager = AdminManager::new(state.database.clone());

    match admin_manager.test_identity_provider(&provider_id).await {
        Ok(result) => Ok(Json(result)),
        Err(e) => {
            eprintln!("Failed to test identity provider: {}", e);
            Err(admin_error_to_status(&e))
        }
    }
}

#[derive(Deserialize)]
/// Query parameters for listing identity providers
pub struct ListIdentityProvidersQuery {
    /// Filter identity providers by realm ID
    pub realm_id: Option<Uuid>,
    /// Filter by provider type
    pub provider_type: Option<String>,
    /// Filter by enabled status
    pub enabled: Option<bool>,
}

/// Create admin routes
pub fn create_admin_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/stats", get(get_system_stats))
        .route("/dashboard", get(get_dashboard_data))
        .route("/users", get(list_users))
        .route("/users", post(create_user))
        .route("/users/{user_id}", get(get_user))
        .route("/users/{user_id}", put(update_user))
        .route("/users/{user_id}", delete(delete_user))
        .route("/sessions", get(list_sessions))
        .route("/sessions/{session_id}", delete(terminate_session))
        .route("/audit-logs", get(list_audit_logs))
        .route("/roles", get(list_roles))
        .route("/roles", post(create_role))
        .route("/roles/{role_id}", get(get_role))
        .route("/roles/{role_id}", put(update_role))
        .route("/roles/{role_id}", delete(delete_role))
        .route("/policies", get(list_policies))
        .route("/policies", post(create_policy))
        .route("/security-events", get(get_security_events))
        .route("/risk-analytics", get(get_risk_analytics))
        .route("/identity-providers", get(list_identity_providers))
        .route("/identity-providers", post(create_identity_provider))
        .route(
            "/identity-providers/{provider_id}",
            get(get_identity_provider),
        )
        .route(
            "/identity-providers/{provider_id}",
            put(update_identity_provider),
        )
        .route(
            "/identity-providers/{provider_id}",
            delete(delete_identity_provider),
        )
        .route(
            "/identity-providers/{provider_id}/test",
            post(test_identity_provider),
        )
}
