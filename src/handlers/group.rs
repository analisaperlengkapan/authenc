use crate::database::Database;
use crate::database::operations::groups;
use crate::models::group::{CreateGroupRequest, GroupResponse, UpdateGroupRequest};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::Deserialize;

use tracing::error;
use uuid::Uuid;

/// Query parameters for listing groups
#[derive(Deserialize)]
pub struct GroupListQuery {
    /// Offset for pagination (first record index)
    #[serde(default)]
    pub first: Option<i64>,
    /// Maximum number of records to return
    #[serde(default)]
    pub max: Option<i64>,
}

/// Create a new group
pub async fn create_group(
    State(db): State<Database>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let group = groups::create_group(
        &db,
        req.realm_id,
        &req.name,
        None, // parent_id - not in CreateGroupRequest, use None for top-level
        req.description.as_deref(),
        &serde_json::Value::Object(serde_json::Map::new()), // Default empty attributes
    )
    .await
    .map_err(|e| {
        error!("Failed to create group: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    // Get member and subgroup counts
    let member_count = groups::count_group_members(&db, group.id)
        .await
        .unwrap_or(0);
    let subgroup_count = groups::count_subgroups(&db, group.id).await.unwrap_or(0);

    let mut response = GroupResponse::from(group);
    response.member_count = member_count;
    response.subgroup_count = subgroup_count;

    Ok((StatusCode::CREATED, Json(response)))
}

/// Get all groups in a realm
pub async fn get_groups(
    State(db): State<Database>,
    Path(realm_id): Path<Uuid>,
    Query(query): Query<GroupListQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let groups = groups::get_groups_by_realm(&db, realm_id, query.first, query.max)
        .await
        .map_err(|e| {
            error!("Failed to get groups: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    let mut responses = Vec::new();
    for group in groups {
        let member_count = groups::count_group_members(&db, group.id)
            .await
            .unwrap_or(0);
        let subgroup_count = groups::count_subgroups(&db, group.id).await.unwrap_or(0);

        let mut response = GroupResponse::from(group);
        response.member_count = member_count;
        response.subgroup_count = subgroup_count;
        responses.push(response);
    }

    Ok(Json(responses))
}

/// Get a specific group by ID
pub async fn get_group_by_id(
    State(db): State<Database>,
    Path(group_id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let group = groups::get_group_by_id(&db, group_id)
        .await
        .map_err(|e| {
            error!("Failed to get group: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Group not found".to_string()))?;

    let member_count = groups::count_group_members(&db, group.id)
        .await
        .unwrap_or(0);
    let subgroup_count = groups::count_subgroups(&db, group.id).await.unwrap_or(0);

    let mut response = GroupResponse::from(group);
    response.member_count = member_count;
    response.subgroup_count = subgroup_count;

    Ok(Json(response))
}

/// Update a group
pub async fn update_group(
    State(db): State<Database>,
    Path(group_id): Path<Uuid>,
    Json(req): Json<UpdateGroupRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let group = groups::update_group(
        &db,
        group_id,
        req.name.clone(),
        req.parent_id.map(Some),
        req.description.clone().map(Some),
        req.attributes.clone(),
    )
    .await
    .map_err(|e| {
        error!("Failed to update group: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    let member_count = groups::count_group_members(&db, group.id)
        .await
        .unwrap_or(0);
    let subgroup_count = groups::count_subgroups(&db, group.id).await.unwrap_or(0);

    let mut response = GroupResponse::from(group);
    response.member_count = member_count;
    response.subgroup_count = subgroup_count;

    Ok(Json(response))
}

/// Delete a group
pub async fn delete_group(
    State(db): State<Database>,
    Path(group_id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    groups::delete_group(&db, group_id).await.map_err(|e| {
        error!("Failed to delete group: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get subgroups of a group
pub async fn get_subgroups(
    State(db): State<Database>,
    Path(group_id): Path<Uuid>,
    Query(_query): Query<GroupListQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let subgroups = groups::get_subgroups(&db, group_id, true)
        .await
        .map_err(|e| {
            error!("Failed to get subgroups: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    let mut responses = Vec::new();
    for group in subgroups {
        let member_count = groups::count_group_members(&db, group.id)
            .await
            .unwrap_or(0);
        let subgroup_count = groups::count_subgroups(&db, group.id).await.unwrap_or(0);

        let mut response = GroupResponse::from(group);
        response.member_count = member_count;
        response.subgroup_count = subgroup_count;
        responses.push(response);
    }

    Ok(Json(responses))
}

/// Add user to group
pub async fn add_group_member(
    State(db): State<Database>,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    groups::add_user_to_group(&db, user_id, group_id, None, None)
        .await
        .map_err(|e| {
            error!("Failed to add user to group: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Remove user from group
pub async fn remove_group_member(
    State(db): State<Database>,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    groups::remove_user_from_group(&db, user_id, group_id)
        .await
        .map_err(|e| {
            error!("Failed to remove user from group: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get members of a group
pub async fn get_group_members(
    State(db): State<Database>,
    Path(group_id): Path<Uuid>,
    Query(query): Query<GroupListQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let member_ids = groups::get_group_members(&db, group_id, query.first, query.max)
        .await
        .map_err(|e| {
            error!("Failed to get group members: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;

    Ok(Json(member_ids))
}

/// Get user's groups
pub async fn get_user_groups(
    State(db): State<Database>,
    Path(user_id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let user_groups = groups::get_user_groups(&db, user_id).await.map_err(|e| {
        error!("Failed to get user groups: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    let mut responses = Vec::new();
    for group in user_groups {
        let member_count = groups::count_group_members(&db, group.id)
            .await
            .unwrap_or(0);
        let subgroup_count = groups::count_subgroups(&db, group.id).await.unwrap_or(0);

        let mut response = GroupResponse::from(group);
        response.member_count = member_count;
        response.subgroup_count = subgroup_count;
        responses.push(response);
    }

    Ok(Json(responses))
}
