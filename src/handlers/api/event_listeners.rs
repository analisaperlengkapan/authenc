//! Event Listener System API Endpoints
//!
//! REST API for event listener management and webhook configuration

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    app::AppState,
    database::operations::events as event_ops,
    error::{AuthencError, Result},
};

/// Query parameters for event log
#[derive(Debug, Deserialize)]
pub struct EventLogQueryParams {
    /// Filter by event category
    pub event_category: Option<String>,
    /// Filter by specific event type
    pub event_type: Option<String>,
    /// Filter by resource type
    pub resource_type: Option<String>,
    /// Filter by user ID
    pub user_id: Option<Uuid>,
    /// Start date for filtering (ISO 8601 format)
    pub from_date: Option<String>,
    /// End date for filtering (ISO 8601 format)
    pub to_date: Option<String>,
    /// Return only successful events
    pub success_only: Option<bool>,
    /// Pagination offset
    pub offset: Option<i64>,
    /// Maximum number of results to return
    pub limit: Option<i64>,
}

/// Event listener registration request
#[derive(Debug, Deserialize)]
pub struct RegisterListenerRequest {
    /// Name of the event listener
    pub name: String,
    /// Type of event listener
    pub listener_type: String,
    /// Configuration parameters
    pub config: JsonValue,
    /// Types of events to listen for
    pub event_types: Option<Vec<String>>,
    /// Priority order for execution
    pub priority: Option<i32>,
    /// Whether to process events asynchronously
    pub is_async: Option<bool>,
    /// Whether to retry on failure
    pub retry_on_failure: Option<bool>,
    /// Maximum number of retry attempts
    pub max_retries: Option<i32>,
}

/// Webhook registration request
#[derive(Debug, Deserialize)]
pub struct RegisterWebhookRequest {
    /// ID of the parent event listener
    pub listener_id: Uuid,
    /// Webhook URL endpoint
    pub url: String,
    /// HTTP method for the webhook
    pub http_method: String,
    /// Authentication type
    pub auth_type: Option<String>,
    /// Authentication credentials
    pub auth_credentials: Option<JsonValue>,
    /// Custom HTTP headers
    pub custom_headers: Option<JsonValue>,
    /// Template for webhook payload
    pub payload_template: Option<String>,
    /// Secret key for webhook verification
    pub secret_key: Option<String>,
    /// Whether to verify SSL certificates
    pub verify_ssl: Option<bool>,
    /// Timeout in seconds for webhook requests
    pub timeout_seconds: Option<i32>,
}

/// Query event log with filtering
pub async fn query_event_log(
    State(state): State<Arc<AppState>>,
    Path(realm_id): Path<Uuid>,
    Query(params): Query<EventLogQueryParams>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    let from_date = if let Some(ref date_str) = params.from_date {
        Some(
            chrono::DateTime::parse_from_rfc3339(date_str)
                .map_err(|e| AuthencError::validation(format!("Invalid from_date: {}", e)))?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    let to_date = if let Some(ref date_str) = params.to_date {
        Some(
            chrono::DateTime::parse_from_rfc3339(date_str)
                .map_err(|e| AuthencError::validation(format!("Invalid to_date: {}", e)))?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    use authenc_database::database::operations::events::QueryEventLogParams;

    let query_params = QueryEventLogParams {
        realm_id,
        event_category: params.event_category,
        event_type: params.event_type,
        resource_type: params.resource_type,
        resource_id: None,
        user_id: params.user_id,
        from_date,
        to_date,
        success_only: params.success_only,
        offset: params.offset.unwrap_or(0),
        limit: params.limit.unwrap_or(100),
    };

    let events = event_ops::query_event_log(db, query_params).await?;

    Ok(Json(json!({
        "events": events,
        "total": events.len(),
    })))
}

/// Get event statistics for a realm
pub async fn get_event_statistics(
    State(state): State<Arc<AppState>>,
    Path(realm_id): Path<Uuid>,
    Query(params): Query<EventLogQueryParams>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    let from_date = if let Some(ref date_str) = params.from_date {
        Some(
            chrono::DateTime::parse_from_rfc3339(date_str)
                .map_err(|e| AuthencError::validation(format!("Invalid from_date: {}", e)))?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    let to_date = if let Some(ref date_str) = params.to_date {
        Some(
            chrono::DateTime::parse_from_rfc3339(date_str)
                .map_err(|e| AuthencError::validation(format!("Invalid to_date: {}", e)))?
                .with_timezone(&chrono::Utc),
        )
    } else {
        None
    };

    // Use defaults if dates not provided (last 30 days)
    let from = from_date.unwrap_or_else(|| chrono::Utc::now() - chrono::Duration::days(30));
    let to = to_date.unwrap_or_else(chrono::Utc::now);

    let stats = event_ops::get_event_statistics(db, realm_id, from, to).await?;

    Ok(Json(stats))
}

/// Register a new event listener
pub async fn register_listener(
    State(state): State<Arc<AppState>>,
    Path(realm_id): Path<Uuid>,
    Json(req): Json<RegisterListenerRequest>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    let listener_id = event_ops::register_event_listener(
        db,
        realm_id,
        &req.name,
        &req.listener_type,
        true,
        Some(&req.config),
        req.event_types,
        req.priority.unwrap_or(100),
        req.is_async.unwrap_or(false),
        req.retry_on_failure.unwrap_or(false),
        req.max_retries.unwrap_or(3),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": listener_id,
            "message": "Event listener registered successfully"
        })),
    ))
}

/// List enabled event listeners for a realm
pub async fn list_listeners(
    State(state): State<Arc<AppState>>,
    Path(realm_id): Path<Uuid>,
) -> Result<impl IntoResponse> {
    let db = &state.database;
    let listeners = event_ops::get_enabled_listeners(db, realm_id).await?;

    Ok(Json(json!({
        "listeners": listeners,
        "total": listeners.len(),
    })))
}

/// Register a webhook for event notifications
pub async fn register_webhook(
    State(state): State<Arc<AppState>>,
    Path(realm_id): Path<Uuid>,
    Json(req): Json<RegisterWebhookRequest>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    let auth_type = req.auth_type.unwrap_or_else(|| "none".to_string());
    let webhook_id = event_ops::register_webhook(
        db,
        req.listener_id,
        realm_id,
        &req.url,
        &req.http_method,
        Some(&auth_type),
        req.auth_credentials.as_ref(),
        req.custom_headers.as_ref(),
        req.payload_template.as_deref(),
        req.secret_key.as_deref(),
        req.verify_ssl.unwrap_or(true),
        req.timeout_seconds.unwrap_or(30),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": webhook_id,
            "message": "Webhook registered successfully"
        })),
    ))
}

/// Get failed executions for retry
pub async fn get_failed_executions(
    State(state): State<Arc<AppState>>,
    Path(realm_id): Path<Uuid>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse> {
    let db = &state.database;

    let max_retry_count = params
        .get("max_retry_count")
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(3);

    let failed_executions = event_ops::get_failed_executions_for_retry(db, max_retry_count).await?;

    let filtered: Vec<JsonValue> = failed_executions
        .into_iter()
        .filter(|exec| {
            exec.get("realm_id")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok())
                .map(|id| id == realm_id)
                .unwrap_or(false)
        })
        .collect();

    Ok(Json(json!({
        "executions": filtered,
        "total": filtered.len(),
    })))
}

/// Create router for event listener API endpoints
pub fn create_event_listener_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/{realm}/event-log", get(query_event_log))
        .route("/{realm}/event-statistics", get(get_event_statistics))
        .route(
            "/{realm}/event-listeners",
            post(register_listener).get(list_listeners),
        )
        .route("/{realm}/event-webhooks", post(register_webhook))
        .route(
            "/{realm}/event-failed-executions",
            get(get_failed_executions),
        )
}
