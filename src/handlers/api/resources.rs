use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::get,
    Router,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::AuthencError;
use crate::models::resource::ResourceResponse;
use crate::services::permission_ticket_store::{PermissionTicketStore, PermissionTicketStoreTrait};
use crate::services::resource_store::{ResourceStore, ResourceStoreTrait};

/// Create resources management routes for account console
pub fn create_resources_routes() -> Router<(
    Arc<ResourceStore>,
    Arc<PermissionTicketStore>,
)> {
    Router::new()
        .route("/resources", get(get_resources))
        .route("/resources/shared-with-me", get(get_shared_with_me))
        .route("/resources/shared-with-others", get(get_shared_with_others))
        .route("/resources/pending-requests", get(get_pending_requests))
}

/// Query parameters for resource listing
#[derive(Deserialize)]
pub struct ResourceQuery {
    pub name: Option<String>,
    pub first: Option<i32>,
    pub max: Option<i32>,
}

/// Get resources owned by the current user
pub async fn get_resources(
    State((resource_store, _)): State<(
        Arc<ResourceStore>,
        Arc<PermissionTicketStore>,
    )>,
    Query(query): Query<ResourceQuery>,
) -> Result<Json<ResourcesResponse>, AuthencError> {
    // TODO: Get current user from authentication context
    let current_user_id = "current_user_id"; // Placeholder

    let resources = resource_store
        .get_resources_by_owner(current_user_id, query.first, query.max)
        .await?;

    let total_count = resources.len() as i64;
    let response = ResourcesResponse {
        resources: resources.into_iter().map(|r| r.into()).collect(),
        total_count,
        links: None, // TODO: Implement pagination links
    };

    Ok(Json(response))
}

/// Get resources shared with the current user
pub async fn get_shared_with_me(
    State((resource_store, ticket_store)): State<(
        Arc<ResourceStore>,
        Arc<PermissionTicketStore>,
    )>,
    Query(query): Query<ResourceQuery>,
) -> Result<Json<ResourcesResponse>, AuthencError> {
    // TODO: Get current user from authentication context
    let current_user_id = "current_user_id"; // Placeholder

    // Get resource IDs that are shared with the current user
    let resource_ids = ticket_store
        .get_granted_resources(
            current_user_id,
            query.name.as_deref(),
            query.first,
            query.max,
        )
        .await?;

    // Get the actual resources
    let mut resources = Vec::new();
    for resource_id in resource_ids {
        if let Some(resource) = resource_store.get_resource(resource_id).await? {
            resources.push(resource);
        }
    }

    let total_count = resources.len() as i64;
    let response = ResourcesResponse {
        resources: resources.into_iter().map(|r| r.into()).collect(),
        total_count,
        links: None, // TODO: Implement pagination links
    };

    Ok(Json(response))
}

/// Get resources owned by the current user that are shared with others
pub async fn get_shared_with_others(
    State((resource_store, ticket_store)): State<(
        Arc<ResourceStore>,
        Arc<PermissionTicketStore>,
    )>,
    Query(query): Query<ResourceQuery>,
) -> Result<Json<ResourcesResponse>, AuthencError> {
    // TODO: Get current user from authentication context
    let current_user_id = "current_user_id"; // Placeholder

    // Get resource IDs owned by current user that are shared with others
    let resource_ids = ticket_store
        .get_granted_owner_resources(current_user_id, query.first, query.max)
        .await?;

    // Get the actual resources
    let mut resources = Vec::new();
    for resource_id in resource_ids {
        if let Some(resource) = resource_store.get_resource(resource_id).await? {
            resources.push(resource);
        }
    }

    let total_count = resources.len() as i64;
    let response = ResourcesResponse {
        resources: resources.into_iter().map(|r| r.into()).collect(),
        total_count,
        links: None, // TODO: Implement pagination links
    };

    Ok(Json(response))
}

/// Get pending permission requests for the current user
pub async fn get_pending_requests(
    State((resource_store, ticket_store)): State<(
        Arc<ResourceStore>,
        Arc<PermissionTicketStore>,
    )>,
    Query(query): Query<ResourceQuery>,
) -> Result<Json<ResourcesResponse>, AuthencError> {
    // TODO: Get current user from authentication context
    let current_user_id = "current_user_id"; // Placeholder

    // Get pending permission tickets for the current user
    let tickets = ticket_store
        .get_tickets_for_requester(current_user_id, Some(false))
        .await?;

    // Get unique resources from the tickets
    let mut resource_ids = std::collections::HashSet::new();
    for ticket in &tickets {
        resource_ids.insert(ticket.resource_id);
    }

    // Get the actual resources
    let mut resources = Vec::new();
    for resource_id in resource_ids {
        if let Some(resource) = resource_store.get_resource(resource_id).await? {
            resources.push(resource);
        }
    }

    let total_count = resources.len() as i64;
    let response = ResourcesResponse {
        resources: resources.into_iter().map(|r| r.into()).collect(),
        total_count,
        links: None, // TODO: Implement pagination links
    };

    Ok(Json(response))
}

/// Response structure for resource collections
#[derive(serde::Serialize)]
pub struct ResourcesResponse {
    /// List of resources
    pub resources: Vec<ResourceResponse>,
    /// Total count of resources
    pub total_count: i64,
    /// Pagination links
    pub links: Option<PaginationLinks>,
}

/// Pagination links structure
#[derive(serde::Serialize)]
pub struct PaginationLinks {
    /// Link to first page
    pub first: Option<String>,
    /// Link to previous page
    pub prev: Option<String>,
    /// Link to next page
    pub next: Option<String>,
    /// Link to last page
    pub last: Option<String>,
}
