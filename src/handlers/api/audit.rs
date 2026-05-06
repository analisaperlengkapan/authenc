use authenc_models::models::audit_log::{AuditLog, AuditLogFilter};
use authenc_services::services::stores::pg_audit_log_store::PgAuditLogStore;
use crate::handlers::api::auth_bearer::AuthBearer;
use axum::{
    Router,
    extract::{Path, State, Query},
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Create audit log routes for a realm
pub fn create_audit_routes() -> Router<Arc<PgAuditLogStore>> {
    Router::new()
        .route("/realms/{realm}/audit", post(add_audit_log))
        .route("/realms/{realm}/audit", get(get_audit_logs))
}

#[derive(Deserialize)]
/// Request payload for creating a new audit log entry
pub struct CreateAuditLogRequest {
    /// The actor who performed the action
    pub actor: String,
    /// The action that was performed
    pub action: String,
    /// The target of the action
    pub target: String,
    /// Optional additional details about the action
    pub details: Option<String>,
}

#[derive(Serialize)]
/// Response payload for retrieving audit logs
pub struct AuditLogResponse {
    /// Total number of audit logs matching the filter
    pub total: u64,
    /// List of audit log entries for the current page
    pub logs: Vec<AuditLog>,
}

/// Add a new audit log entry to the specified realm
pub async fn add_audit_log(
    State(store): State<Arc<PgAuditLogStore>>,
    _auth: AuthBearer, // Ensure authentication for writing logs
    Path(_realm): Path<String>, // Realm parameter currently unused due to backend schema limitations
    Json(req): Json<CreateAuditLogRequest>,
) -> Result<StatusCode, StatusCode> {
    // Note: 'target' field from request is currently unused as AuditLog model lacks a corresponding field.
    // This is a known limitation to be addressed in a future schema update.

    let log = AuditLog {
        timestamp: Utc::now(),
        event: req.action,
        user_id: Some(req.actor),
        client_id: None,
        status: "success".to_string(),
        detail: req.details,
    };

    match store.add_log(&log).await {
        Ok(_) => Ok(StatusCode::CREATED),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Retrieve audit logs for the specified realm with filtering and pagination
pub async fn get_audit_logs(
    State(store): State<Arc<PgAuditLogStore>>,
    _auth: AuthBearer, // Ensures authentication
    Path(_realm): Path<String>, // Realm parameter currently unused due to backend schema limitations
    Query(mut filter): Query<AuditLogFilter>,
) -> Result<Json<AuditLogResponse>, StatusCode> {
    // Set default pagination if not provided
    if filter.limit.is_none() {
        filter.limit = Some(50);
    }
    if filter.offset.is_none() {
        filter.offset = Some(0);
    }

    match store.query(&filter).await {
        Ok((logs, total)) => Ok(Json(AuditLogResponse { total, logs })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
