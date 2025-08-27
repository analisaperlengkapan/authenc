use crate::database::Database;
use crate::error::{AuthencError, Result};
use crate::services::organization::{OrganizationService, OrganizationUpdate};
use axum::{
    extract::{Path, Query, State},
    response::Json,
    routing::{get, post, put, delete},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Create organization routes
pub fn create_organization_routes() -> Router<Arc<Database>> {
    Router::new()
        .route("/", post(create_organization))
        .route("/", get(list_organizations))
        .route("/{id}", get(get_organization))
        .route("/{id}", put(update_organization))
        .route("/{id}", delete(delete_organization))
        .route("/{id}/members", get(get_members))
        .route("/{id}/members", post(add_member))
        .route("/{id}/members/{user_id}", delete(remove_member))
        .route("/{id}/members/{user_id}/role", put(update_member_role))
        .route("/{id}/invitations", post(create_invitation))
        .route("/{id}/invitations/accept", post(accept_invitation))
        .route("/{id}/settings", get(get_settings))
        .route("/{id}/settings", put(update_settings))
        .route("/user/{user_id}", get(get_user_organizations))
}

/// Create organization request
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
}

/// Create organization handler
pub async fn create_organization(
    State(db): State<Arc<Database>>,
    Json(request): Json<CreateOrganizationRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(db);

    // In production, get user ID from authentication context
    let created_by = Uuid::new_v4();

    match service.create_organization(
        &request.name,
        &request.display_name,
        request.description.as_deref(),
        created_by,
    ).await {
        Ok(organization) => Ok(Json(serde_json::json!({
            "success": true,
            "organization": organization
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// List organizations handler
pub async fn list_organizations(
    State(db): State<Arc<Database>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(db);

    // In production, implement pagination and filtering
    let organizations: Vec<serde_json::Value> = vec![]; // service.list_organizations().await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "organizations": organizations
    })))
}

/// Get organization handler
pub async fn get_organization(
    State(db): State<Arc<Database>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(db);

    match service.get_organization(&id).await {
        Ok(Some(organization)) => Ok(Json(serde_json::json!({
            "success": true,
            "organization": organization
        }))),
        Ok(None) => Err(AuthencError::resource_not_found("Resource not found")),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Update organization handler
pub async fn update_organization(
    State(db): State<Arc<Database>>,
    Path(id): Path<Uuid>,
    Json(updates): Json<OrganizationUpdate>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(db);

    match service.update_organization(&id, &updates).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Organization updated successfully"
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Delete organization handler
pub async fn delete_organization(
    State(db): State<Arc<Database>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(db);

    match service.delete_organization(&id).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Organization deleted successfully"
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Get organization members handler
pub async fn get_members(
    State(db): State<Arc<Database>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(db);

    match service.get_members(&id).await {
        Ok(members) => Ok(Json(serde_json::json!({
            "success": true,
            "members": members
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Add member request
#[derive(Debug, Serialize, Deserialize)]
pub struct AddMemberRequest {
    pub user_id: Uuid,
    pub role: String,
}

/// Add member handler
pub async fn add_member(
    State(db): State<Arc<Database>>,
    Path(id): Path<Uuid>,
    Json(request): Json<AddMemberRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(db);

    let role = match request.role.as_str() {
        "owner" => crate::services::organization::OrganizationRole::Owner,
        "admin" => crate::services::organization::OrganizationRole::Admin,
        "member" => crate::services::organization::OrganizationRole::Member,
        "guest" => crate::services::organization::OrganizationRole::Guest,
        _ => return Err(AuthencError::validation("Bad request")),
    };

    // In production, get invited_by from authentication context
    let invited_by = Uuid::new_v4();

    match service.add_member(&id, &request.user_id, role, Some(invited_by)).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Member added successfully"
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Remove member handler
pub async fn remove_member(
    State(db): State<Arc<Database>>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(db);

    match service.remove_member(&id, &user_id).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Member removed successfully"
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Update member role request
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateMemberRoleRequest {
    pub role: String,
}

/// Update member role handler
pub async fn update_member_role(
    State(db): State<Arc<Database>>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateMemberRoleRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(db);

    let role = match request.role.as_str() {
        "owner" => crate::services::organization::OrganizationRole::Owner,
        "admin" => crate::services::organization::OrganizationRole::Admin,
        "member" => crate::services::organization::OrganizationRole::Member,
        "guest" => crate::services::organization::OrganizationRole::Guest,
        _ => return Err(AuthencError::validation("Bad request")),
    };

    match service.update_member_role(&id, &user_id, role).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Member role updated successfully"
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Create invitation request
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateInvitationRequest {
    pub email: String,
    pub role: String,
    pub expires_in_days: u32,
}

/// Create invitation handler
pub async fn create_invitation(
    State(db): State<Arc<Database>>,
    Path(id): Path<Uuid>,
    Json(request): Json<CreateInvitationRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(db);

    let role = match request.role.as_str() {
        "owner" => crate::services::organization::OrganizationRole::Owner,
        "admin" => crate::services::organization::OrganizationRole::Admin,
        "member" => crate::services::organization::OrganizationRole::Member,
        "guest" => crate::services::organization::OrganizationRole::Guest,
        _ => return Err(AuthencError::validation("Bad request")),
    };

    // In production, get invited_by from authentication context
    let invited_by = Uuid::new_v4();

    match service.create_invitation(&id, &request.email, role, invited_by, request.expires_in_days).await {
        Ok(invitation) => Ok(Json(serde_json::json!({
            "success": true,
            "invitation": invitation
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Accept invitation request
#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptInvitationRequest {
    pub token: String,
}

/// Accept invitation handler
pub async fn accept_invitation(
    State(db): State<Arc<Database>>,
    Json(request): Json<AcceptInvitationRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(db);

    // In production, get user_id from authentication context
    let user_id = Uuid::new_v4();

    match service.accept_invitation(&request.token, user_id).await {
        Ok(organization) => Ok(Json(serde_json::json!({
            "success": true,
            "organization": organization,
            "message": "Successfully joined organization"
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Get organization settings handler
pub async fn get_settings(
    State(db): State<Arc<Database>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(db);

    match service.get_settings(&id).await {
        Ok(settings) => Ok(Json(serde_json::json!({
            "success": true,
            "settings": settings
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Update organization settings handler
pub async fn update_settings(
    State(db): State<Arc<Database>>,
    Path(id): Path<Uuid>,
    Json(settings): Json<crate::services::organization::OrganizationSettings>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(db);

    match service.update_settings(&settings).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Settings updated successfully"
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}

/// Get user's organizations handler
pub async fn get_user_organizations(
    State(db): State<Arc<Database>>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(db);

    match service.get_user_organizations(&user_id).await {
        Ok(organizations) => Ok(Json(serde_json::json!({
            "success": true,
            "organizations": organizations
        }))),
        Err(_) => Err(AuthencError::internal("Internal server error")),
    }
}
