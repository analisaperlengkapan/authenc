use crate::models::audit_log::AuditLog;
use crate::services::stores::pg_audit_log_store::PgAuditLogStore;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use chrono::Utc;
use serde::Deserialize;
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

/// Add a new audit log entry to the specified realm
pub async fn add_audit_log(
    State(store): State<Arc<PgAuditLogStore>>,
    Path(_realm): Path<String>,
    Json(req): Json<CreateAuditLogRequest>,
) -> Result<StatusCode, StatusCode> {
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

/// Retrieve all audit logs for the specified realm
pub async fn get_audit_logs(
    State(store): State<Arc<PgAuditLogStore>>,
    Path(_realm): Path<String>,
) -> Result<Json<Vec<AuditLog>>, StatusCode> {
    match store.all().await {
        Ok(logs) => Ok(Json(logs)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
