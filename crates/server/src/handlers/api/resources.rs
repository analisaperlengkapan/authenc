use axum::{
    Router,
    extract::{Extension, Query, State},
    response::Json,
    routing::get,
};
use serde::Deserialize;
use std::sync::Arc;

use authenc_api::error::AuthencError;
use crate::middleware::auth::AuthUser;
use authenc_api::models::resource::ResourceResponse;
use authenc_services::services::stores::permission_ticket_store::{PermissionTicketStore, PermissionTicketStoreTrait};
use authenc_services::services::stores::resource_store::{ResourceStore, ResourceStoreTrait};

/// Create resources management routes for account console
pub fn create_resources_routes() -> Router<(Arc<ResourceStore>, Arc<PermissionTicketStore>)> {
    Router::new()
        .route("/resources", get(get_resources))
        .route("/resources/shared-with-me", get(get_shared_with_me))
        .route("/resources/shared-with-others", get(get_shared_with_others))
        .route("/resources/pending-requests", get(get_pending_requests))
}

/// Query parameters for resource listing
#[derive(Deserialize)]
pub struct ResourceQuery {
    /// Optional name filter for resources
    pub name: Option<String>,
    /// Starting index for pagination
    pub first: Option<i32>,
    /// Maximum number of results to return
    pub max: Option<i32>,
}

/// Get resources owned by the current user
pub async fn get_resources(
    Extension(auth_user): Extension<AuthUser>,
    State((resource_store, _)): State<(Arc<ResourceStore>, Arc<PermissionTicketStore>)>,
    Query(query): Query<ResourceQuery>,
) -> Result<Json<ResourcesResponse>, AuthencError> {
    let current_user_id = &auth_user.id;

    let resources = resource_store
        .get_resources_by_owner(current_user_id, query.first, query.max)
        .await?;

    let total_count = resources.len() as i64;

    // Generate pagination links
    let links = generate_pagination_links(query.first, query.max, total_count);

    let response = ResourcesResponse {
        resources: resources.into_iter().map(|r| r.into()).collect(),
        total_count,
        links,
    };

    Ok(Json(response))
}

/// Get resources shared with the current user
pub async fn get_shared_with_me(
    Extension(auth_user): Extension<AuthUser>,
    State((resource_store, ticket_store)): State<(Arc<ResourceStore>, Arc<PermissionTicketStore>)>,
    Query(query): Query<ResourceQuery>,
) -> Result<Json<ResourcesResponse>, AuthencError> {
    let current_user_id = &auth_user.id;

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

    // Generate pagination links
    let links = generate_pagination_links(query.first, query.max, total_count);

    let response = ResourcesResponse {
        resources: resources.into_iter().map(|r| r.into()).collect(),
        total_count,
        links,
    };

    Ok(Json(response))
}

/// Get resources owned by the current user that are shared with others
pub async fn get_shared_with_others(
    Extension(auth_user): Extension<AuthUser>,
    State((resource_store, ticket_store)): State<(Arc<ResourceStore>, Arc<PermissionTicketStore>)>,
    Query(query): Query<ResourceQuery>,
) -> Result<Json<ResourcesResponse>, AuthencError> {
    let current_user_id = &auth_user.id;

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

    // Generate pagination links
    let links = generate_pagination_links(query.first, query.max, total_count);

    let response = ResourcesResponse {
        resources: resources.into_iter().map(|r| r.into()).collect(),
        total_count,
        links,
    };

    Ok(Json(response))
}

/// Get pending permission requests for the current user
pub async fn get_pending_requests(
    Extension(auth_user): Extension<AuthUser>,
    State((resource_store, ticket_store)): State<(Arc<ResourceStore>, Arc<PermissionTicketStore>)>,
    Query(query): Query<ResourceQuery>,
) -> Result<Json<ResourcesResponse>, AuthencError> {
    let current_user_id = &auth_user.id;

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

    // Generate pagination links
    let links = generate_pagination_links(query.first, query.max, total_count);

    let response = ResourcesResponse {
        resources: resources.into_iter().map(|r| r.into()).collect(),
        total_count,
        links,
    };

    Ok(Json(response))
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

/// Generate pagination links based on current query parameters
fn generate_pagination_links(
    first: Option<i32>,
    max: Option<i32>,
    total_count: i64,
) -> Option<PaginationLinks> {
    let first = first.unwrap_or(0);
    let max = max.unwrap_or(20);

    if total_count <= max as i64 {
        // No pagination needed
        return None;
    }

    let mut links = PaginationLinks {
        first: Some(format!("?first=0&max={}", max)),
        prev: None,
        next: None,
        last: None,
    };

    // Previous page
    if first > 0 {
        let prev_first = std::cmp::max(0, first - max);
        links.prev = Some(format!("?first={}&max={}", prev_first, max));
    }

    // Next page
    if (first + max) < total_count as i32 {
        let next_first = first + max;
        links.next = Some(format!("?first={}&max={}", next_first, max));
    }

    // Last page
    if total_count > max as i64 {
        let last_first = ((total_count - 1) / max as i64 * max as i64) as i32;
        links.last = Some(format!("?first={}&max={}", last_first, max));
    }

    Some(links)
}
