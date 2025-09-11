use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use crate::services::pg_audit_log_store::PgAuditLogStore;
use crate::models::audit_log::AuditLog;
use serde::Deserialize;
use std::sync::Arc;
use chrono::Utc;

pub fn create_audit_routes() -> Router<Arc<PgAuditLogStore>> {
    Router::new()
        .route("/realms/{realm}/audit", post(add_audit_log))
        .route("/realms/{realm}/audit", get(get_audit_logs))
}

#[derive(Deserialize)]
pub struct CreateAuditLogRequest {
    pub actor: String,
    pub action: String,
    pub target: String,
    pub details: Option<String>,
}

pub async fn add_audit_log(
    State(store): State<Arc<PgAuditLogStore>>,
    Path(realm): Path<String>,
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

pub async fn get_audit_logs(
    State(store): State<Arc<PgAuditLogStore>>,
    Path(_realm): Path<String>,
) -> Result<Json<Vec<AuditLog>>, StatusCode> {
    match store.all().await {
        Ok(logs) => Ok(Json(logs)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
