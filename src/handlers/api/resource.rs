use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, put},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::AuthencError;
use crate::models::permission_ticket::PermissionTicketResponse;
use crate::models::resource::ResourceResponse;
use crate::models::user::UserResponse;
use crate::services::permission_ticket_store::{PermissionTicketStore, PermissionTicketStoreTrait};
use crate::services::resource_store::{ResourceStore, ResourceStoreTrait};
use crate::services::scope_store::{ScopeStore, ScopeStoreTrait};
use crate::services::stores::user_store::{UserStore, UserStoreTrait};

/// Create resource management routes for account console
pub fn create_resource_routes() -> Router<(
    Arc<ResourceStore>,
    Arc<PermissionTicketStore>,
    Arc<ScopeStore>,
    Arc<UserStore>,
)> {
    Router::new()
        .route("/resources/{resource_id}", get(get_resource))
        .route("/resources/{resource_id}/permissions", get(get_resource_permissions))
        .route("/resources/{resource_id}/permissions", put(update_resource_permissions))
        .route("/resources/{resource_id}/permissions/requests", get(get_permission_requests))
        .route("/resources/{resource_id}/user", get(get_user_info))
}

/// Get a specific resource
pub async fn get_resource(
    State((resource_store, _, _, _)): State<(
        Arc<ResourceStore>,
        Arc<PermissionTicketStore>,
        Arc<ScopeStore>,
        Arc<UserStore>,
    )>,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<ResourceResponse>, AuthencError> {
    let resource = resource_store
        .get_resource(resource_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("Resource not found".to_string()))?;

    Ok(Json(resource.into()))
}

/// Get permissions for a specific resource
pub async fn get_resource_permissions(
    State((resource_store, ticket_store, _, _)): State<(
        Arc<ResourceStore>,
        Arc<PermissionTicketStore>,
        Arc<ScopeStore>,
        Arc<UserStore>,
    )>,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<Vec<PermissionResponse>>, AuthencError> {
    // Verify resource exists
    let _resource = resource_store
        .get_resource(resource_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("Resource not found".to_string()))?;

    // Get granted permission tickets for this resource
    let tickets = ticket_store
        .get_tickets_for_resource(resource_id, Some(true))
        .await?;

    // Convert to permission responses
    let permissions = tickets
        .into_iter()
        .map(|ticket| PermissionResponse {
            username: ticket.requester.clone(),
            scopes: vec![], // TODO: Get scope names from scope store
        })
        .collect();

    Ok(Json(permissions))
}

/// Update permissions for a specific resource
#[derive(Deserialize)]
pub struct UpdatePermissionsRequest {
    pub permissions: Vec<PermissionUpdate>,
}

#[derive(Deserialize)]
pub struct PermissionUpdate {
    pub username: String,
    pub scopes: Vec<String>,
}

pub async fn update_resource_permissions(
    State((resource_store, ticket_store, scope_store, user_store)): State<(
        Arc<ResourceStore>,
        Arc<PermissionTicketStore>,
        Arc<ScopeStore>,
        Arc<UserStore>,
    )>,
    Path(resource_id): Path<Uuid>,
    Json(request): Json<UpdatePermissionsRequest>,
) -> Result<StatusCode, AuthencError> {
    // Verify resource exists
    let resource = resource_store
        .get_resource(resource_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("Resource not found".to_string()))?;

    // Process each permission update
    for permission in request.permissions {
        // Get user
        let user = user_store
            .get_user_by_username(&permission.username)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("User not found".to_string()))?;

        // Process each scope
        for scope_name in &permission.scopes {
            // Get scope
            let scope = scope_store
                .get_scope_by_name(scope_name, resource.resource_server_id)
                .await?
                .ok_or_else(|| AuthencError::resource_not_found(format!("Scope '{}' not found", scope_name)))?;

            // Create or update permission ticket
            let ticket_request = crate::models::permission_ticket::CreatePermissionTicketRequest {
                resource_id,
                scope_id: scope.id,
                requester: user.id.to_string(),
            };

            let _ticket = ticket_store
                .create_ticket(
                    ticket_request,
                    resource.owner.clone(),
                    resource.realm_id,
                    resource.resource_server_id,
                )
                .await?;

            // Grant the ticket
            // TODO: Implement ticket granting
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Get permission requests for a specific resource
pub async fn get_permission_requests(
    State((resource_store, ticket_store, _, _)): State<(
        Arc<ResourceStore>,
        Arc<PermissionTicketStore>,
        Arc<ScopeStore>,
        Arc<UserStore>,
    )>,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<Vec<PermissionResponse>>, AuthencError> {
    // Verify resource exists
    let _resource = resource_store
        .get_resource(resource_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("Resource not found".to_string()))?;

    // Get pending permission tickets for this resource
    let tickets = ticket_store
        .get_tickets_for_resource(resource_id, Some(false))
        .await?;

    // Convert to permission responses
    let permissions = tickets
        .into_iter()
        .map(|ticket| PermissionResponse {
            username: ticket.requester.clone(),
            scopes: vec![], // TODO: Get scope names from scope store
        })
        .collect();

    Ok(Json(permissions))
}

/// Get user information for permission display
#[derive(Deserialize)]
pub struct UserQuery {
    pub value: String,
}

pub async fn get_user_info(
    State((_, _, _, user_store)): State<(
        Arc<ResourceStore>,
        Arc<PermissionTicketStore>,
        Arc<ScopeStore>,
        Arc<UserStore>,
    )>,
    Query(query): Query<UserQuery>,
) -> Result<Json<UserResponse>, AuthencError> {
    // Try to find user by username first, then by email
    let user = if let Some(user) = user_store.get_user_by_username(&query.value).await? {
        user
    } else if let Some(user) = user_store.get_user_by_email(&query.value).await? {
        user
    } else {
        return Err(AuthencError::resource_not_found("User not found".to_string()));
    };

    Ok(Json(user.into()))
}

/// Permission response structure
#[derive(serde::Serialize)]
pub struct PermissionResponse {
    pub username: String,
    pub scopes: Vec<String>,
}
