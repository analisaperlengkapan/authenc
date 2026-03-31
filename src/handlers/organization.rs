use crate::app::AppState;
use crate::error::{AuthencError, Result};
use authenc_services::services::organization::{OrganizationService, OrganizationUpdate, OrganizationRole};
use axum::{
    extract::{Extension, Path, Query, State},
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Create organization routes
pub fn create_organization_routes() -> Router<Arc<AppState>> {
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
    pub domain: Option<String>,
}

/// Create organization handler
pub async fn create_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Json(request): Json<CreateOrganizationRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(state.database.clone());

    let created_by = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    match service
        .create_organization(
            &request.name,
            &request.display_name,
            request.description.as_deref(),
            created_by,
            request.domain.as_deref(),
        )
        .await
    {
        Ok(organization) => Ok(Json(serde_json::json!({
            "success": true,
            "organization": organization
        }))),
        Err(e) => Err(e),
    }
}

/// List organizations handler
pub async fn list_organizations(
    State(state): State<Arc<AppState>>,
    Query(_params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(state.database.clone());

    match service.list_organizations().await {
        Ok(organizations) => Ok(Json(serde_json::json!({
            "success": true,
            "organizations": organizations
        }))),
        Err(e) => Err(e),
    }
}

/// Get organization handler
pub async fn get_organization(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(state.database.clone());

    match service.get_organization(&id).await {
        Ok(Some(organization)) => Ok(Json(serde_json::json!({
            "success": true,
            "organization": organization
        }))),
        Ok(None) => Err(AuthencError::resource_not_found("Resource not found")),
        Err(e) => Err(e),
    }
}

/// Update organization handler
pub async fn update_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path(id): Path<Uuid>,
    Json(updates): Json<OrganizationUpdate>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(state.database.clone());

    let caller_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    let is_owner = service.has_role(&id, &caller_id, &OrganizationRole::Owner).await?;
    let is_admin = service.has_role(&id, &caller_id, &OrganizationRole::Admin).await?;
    if !is_owner && !is_admin {
        return Err(AuthencError::forbidden("Only organization owners or admins can update organizations"));
    }

    match service.update_organization(&id, &updates).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Organization updated successfully"
        }))),
        Err(e) => Err(e),
    }
}

/// Delete organization handler
pub async fn delete_organization(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(state.database.clone());

    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    if !service.has_role(&id, &user_id, &OrganizationRole::Owner).await? {
        return Err(AuthencError::forbidden("Only organization owners can delete organizations"));
    }

    match service.delete_organization(&id).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Organization deleted successfully"
        }))),
        Err(e) => Err(e),
    }
}

/// Get organization members handler
pub async fn get_members(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(state.database.clone());

    let caller_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    if !service.is_member(&id, &caller_id).await? {
        return Err(AuthencError::forbidden("Only organization members can view the member list"));
    }

    match service.get_members(&id).await {
        Ok(members) => Ok(Json(serde_json::json!({
            "success": true,
            "members": members
        }))),
        Err(e) => Err(e),
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
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path(id): Path<Uuid>,
    Json(request): Json<AddMemberRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(state.database.clone());

    let role = match request.role.as_str() {
        "owner" => OrganizationRole::Owner,
        "admin" => OrganizationRole::Admin,
        "member" => OrganizationRole::Member,
        "guest" => OrganizationRole::Guest,
        _ => return Err(AuthencError::validation("Bad request")),
    };

    let invited_by = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    let is_owner = service.has_role(&id, &invited_by, &OrganizationRole::Owner).await?;
    let is_admin = service.has_role(&id, &invited_by, &OrganizationRole::Admin).await?;
    if !is_owner && !is_admin {
        return Err(AuthencError::forbidden("Only organization owners or admins can add members"));
    }

    // Only owners can assign the owner role
    if matches!(role, OrganizationRole::Owner) && !is_owner {
        return Err(AuthencError::forbidden("Only organization owners can assign the owner role"));
    }

    match service
        .add_member(&id, &request.user_id, role, Some(invited_by))
        .await
    {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Member added successfully"
        }))),
        Err(e) => Err(e),
    }
}

/// Remove member handler
pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(state.database.clone());

    let caller_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    let is_owner = service.has_role(&id, &caller_id, &OrganizationRole::Owner).await?;
    let is_admin = service.has_role(&id, &caller_id, &OrganizationRole::Admin).await?;
    if !is_owner && !is_admin {
        return Err(AuthencError::forbidden("Only organization owners or admins can remove members"));
    }

    // Prevent removing an owner unless the caller is also an owner
    let target_is_owner = service.has_role(&id, &user_id, &OrganizationRole::Owner).await?;
    if target_is_owner && !is_owner {
        return Err(AuthencError::forbidden("Only organization owners can remove other owners"));
    }

    // Use the transaction-safe removal that atomically checks last-owner constraint
    match service.remove_member_safe(&id, &user_id).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Member removed successfully"
        }))),
        Err(e) => Err(e),
    }
}

/// Update member role request
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateMemberRoleRequest {
    pub role: String,
}

/// Update member role handler
pub async fn update_member_role(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateMemberRoleRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(state.database.clone());

    let caller_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    if !service.has_role(&id, &caller_id, &OrganizationRole::Owner).await? {
        return Err(AuthencError::forbidden("Only organization owners can update member roles"));
    }

    let role = match request.role.as_str() {
        "owner" => OrganizationRole::Owner,
        "admin" => OrganizationRole::Admin,
        "member" => OrganizationRole::Member,
        "guest" => OrganizationRole::Guest,
        _ => return Err(AuthencError::validation("Bad request")),
    };

    // Use the transaction-safe update that atomically checks last-owner constraint
    match service.update_member_role_safe(&id, &user_id, role).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Member role updated successfully"
        }))),
        Err(e) => Err(e),
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
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path(id): Path<Uuid>,
    Json(request): Json<CreateInvitationRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(state.database.clone());

    let role = match request.role.as_str() {
        "owner" => OrganizationRole::Owner,
        "admin" => OrganizationRole::Admin,
        "member" => OrganizationRole::Member,
        "guest" => OrganizationRole::Guest,
        _ => return Err(AuthencError::validation("Bad request")),
    };

    let invited_by = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    let is_owner = service.has_role(&id, &invited_by, &OrganizationRole::Owner).await?;
    let is_admin = service.has_role(&id, &invited_by, &OrganizationRole::Admin).await?;
    if !is_owner && !is_admin {
        return Err(AuthencError::forbidden("Only organization owners or admins can create invitations"));
    }

    // Only owners can create invitations with the owner role
    if matches!(role, OrganizationRole::Owner) && !is_owner {
        return Err(AuthencError::forbidden("Only organization owners can assign the owner role"));
    }

    match service
        .create_invitation(
            &id,
            &request.email,
            role,
            invited_by,
            request.expires_in_days,
        )
        .await
    {
        Ok(invitation) => Ok(Json(serde_json::json!({
            "success": true,
            "invitation": {
                "id": invitation.id,
                "organization_id": invitation.organization_id,
                "email": invitation.email,
                "role": invitation.role,
                "invited_by": invitation.invited_by,
                "invited_at": invitation.invited_at,
                "expires_at": invitation.expires_at,
            },
            "token": invitation.token,
        }))),
        Err(e) => Err(e),
    }
}

/// Accept invitation request
#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptInvitationRequest {
    pub token: String,
}

/// Accept invitation handler
pub async fn accept_invitation(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path(id): Path<Uuid>,
    Json(request): Json<AcceptInvitationRequest>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(state.database.clone());

    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    match service.accept_invitation(&request.token, user_id, &id).await {
        Ok(organization) => Ok(Json(serde_json::json!({
            "success": true,
            "organization": organization,
            "message": "Successfully joined organization"
        }))),
        Err(e) => Err(e),
    }
}

/// Get organization settings handler
pub async fn get_settings(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = OrganizationService::new(state.database.clone());

    let caller_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    if !service.is_member(&id, &caller_id).await? {
        return Err(AuthencError::forbidden("Only organization members can view settings"));
    }

    match service.get_settings(&id).await {
        Ok(settings) => Ok(Json(serde_json::json!({
            "success": true,
            "settings": settings
        }))),
        Err(e) => Err(e),
    }
}

/// Update organization settings handler
pub async fn update_settings(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path(id): Path<Uuid>,
    Json(settings): Json<crate::services::organization::OrganizationSettings>,
) -> Result<Json<serde_json::Value>> {
    if id != settings.organization_id {
        return Err(AuthencError::validation("Path organization ID does not match body organization_id"));
    }

    let service = OrganizationService::new(state.database.clone());

    let caller_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    let is_owner = service.has_role(&id, &caller_id, &OrganizationRole::Owner).await?;
    let is_admin = service.has_role(&id, &caller_id, &OrganizationRole::Admin).await?;
    if !is_owner && !is_admin {
        return Err(AuthencError::forbidden("Only organization owners or admins can update settings"));
    }

    match service.update_settings(&settings).await {
        Ok(_) => Ok(Json(serde_json::json!({
            "success": true,
            "message": "Settings updated successfully"
        }))),
        Err(e) => Err(e),
    }
}

/// Get user's organizations handler
pub async fn get_user_organizations(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth::AuthUser>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let caller_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Users can only query their own organizations
    if caller_id != user_id {
        return Err(AuthencError::forbidden("You can only view your own organizations"));
    }

    let service = OrganizationService::new(state.database.clone());

    match service.get_user_organizations(&user_id).await {
        Ok(organizations) => Ok(Json(serde_json::json!({
            "success": true,
            "organizations": organizations
        }))),
        Err(e) => Err(e),
    }
}
