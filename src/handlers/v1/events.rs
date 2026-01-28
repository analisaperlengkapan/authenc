use crate::app::AppState;
use crate::models::events::{AdminEvent, Event};
use crate::services::event_retention::{RetentionCleanupResult, RetentionStats};
use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::Arc;

/// Create event querying routes for audit and monitoring
pub fn create_event_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/events", get(query_events))
        .route("/admin-events", get(query_admin_events))
        .route("/retention/stats", get(get_retention_stats))
        .route("/retention/cleanup", post(perform_manual_cleanup))
}

#[derive(Deserialize)]
/// Query parameters for event filtering
pub struct EventQuery {
    /// Filter by realm ID
    pub realm_id: Option<String>,
    /// Filter by event type
    pub event_type: Option<String>,
    /// Filter by user ID
    pub user_id: Option<String>,
    /// Filter by client ID
    pub client_id: Option<String>,
    /// Filter by date from (ISO 8601 format)
    pub date_from: Option<String>,
    /// Filter by date to (ISO 8601 format)
    pub date_to: Option<String>,
    /// Maximum number of results to return
    pub max_results: Option<usize>,
    /// Number of results to skip (for pagination)
    pub first_result: Option<usize>,
}

#[derive(Deserialize)]
/// Query parameters for admin event filtering
pub struct AdminEventQuery {
    /// Filter by realm ID
    pub realm_id: Option<String>,
    /// Filter by operation type
    pub operation_type: Option<String>,
    /// Filter by resource type
    pub resource_type: Option<String>,
    /// Filter by auth user
    pub auth_user: Option<String>,
    /// Filter by date from (ISO 8601 format)
    pub date_from: Option<String>,
    /// Filter by date to (ISO 8601 format)
    pub date_to: Option<String>,
    /// Maximum number of results to return
    pub max_results: Option<usize>,
    /// Number of results to skip (for pagination)
    pub first_result: Option<usize>,
}

/// Query user events with filtering
pub async fn query_events(
    State(state): State<Arc<AppState>>,
    Query(query): Query<EventQuery>,
) -> Result<Json<Vec<Event>>, StatusCode> {
    // Parse date filters
    let date_from = if let Some(date_str) = &query.date_from {
        match chrono::DateTime::parse_from_rfc3339(date_str) {
            Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        }
    } else {
        None
    };

    let date_to = if let Some(date_str) = &query.date_to {
        match chrono::DateTime::parse_from_rfc3339(date_str) {
            Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        }
    } else {
        None
    };

    let first_result = query.first_result.unwrap_or(0);
    let max_results = query.max_results.unwrap_or(100).min(1000); // Cap at 1000

    match state
        .event_manager
        .read()
        .await
        .query_events(
            query.realm_id.as_deref(),
            query.event_type.as_deref(),
            query.user_id.as_deref(),
            query.client_id.as_deref(),
            date_from,
            date_to,
            first_result,
            max_results,
        )
        .await
    {
        Ok(events) => Ok(Json(events)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Query admin events with filtering
pub async fn query_admin_events(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdminEventQuery>,
) -> Result<Json<Vec<AdminEvent>>, StatusCode> {
    // Parse date filters
    let date_from = if let Some(date_str) = &query.date_from {
        match chrono::DateTime::parse_from_rfc3339(date_str) {
            Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        }
    } else {
        None
    };

    let date_to = if let Some(date_str) = &query.date_to {
        match chrono::DateTime::parse_from_rfc3339(date_str) {
            Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
            Err(_) => return Err(StatusCode::BAD_REQUEST),
        }
    } else {
        None
    };

    let first_result = query.first_result.unwrap_or(0);
    let max_results = query.max_results.unwrap_or(100).min(1000); // Cap at 1000

    match state
        .event_manager
        .read()
        .await
        .query_admin_events(
            query.realm_id.as_deref(),
            query.operation_type.as_deref(),
            query.resource_type.as_deref(),
            query.auth_user.as_deref(),
            date_from,
            date_to,
            first_result,
            max_results,
        )
        .await
    {
        Ok(events) => Ok(Json(events)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Get event retention statistics
pub async fn get_retention_stats(
    State(state): State<Arc<AppState>>,
) -> Result<Json<RetentionStats>, StatusCode> {
    match state.event_retention_service.get_retention_stats().await {
        Ok(stats) => Ok(Json(stats)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Perform manual event cleanup
pub async fn perform_manual_cleanup(
    State(state): State<Arc<AppState>>,
) -> Result<Json<RetentionCleanupResult>, StatusCode> {
    match state.event_retention_service.perform_cleanup().await {
        Ok(result) => Ok(Json(result)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
