//! Audit log handlers for Axum
//!
//! This module provides endpoints for querying and exporting audit logs
//! with filtering and pagination support.

use crate::database::operations;
use crate::middleware::auth::AuthUser;
use crate::models::audit_log::AuditLog;
use crate::services::pg_audit_log_store::PgAuditLogStore;
use crate::services::stores::user_store::UserStore;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Json, Response},
    routing::get,
    Extension, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use std::sync::Arc;
use uuid::Uuid;

/// Query parameters for audit log filtering
#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    /// Filter by event type
    pub event: Option<String>,
    /// Filter by user ID
    pub user_id: Option<String>,
    /// Filter by client ID
    pub client_id: Option<String>,
    /// Filter by status (success/failure)
    pub status: Option<String>,
    /// Filter by start date (ISO8601)
    pub from: Option<String>,
    /// Filter by end date (ISO8601)
    pub to: Option<String>,
    /// Maximum number of results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

/// Response for audit log queries
#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    /// Total number of matching logs
    pub total: usize,
    /// List of audit log entries
    pub logs: Vec<AuditLog>,
}

/// State for audit handlers
pub struct AuditHandlerState {
    /// Audit log store
    pub audit_log_store: Arc<PgAuditLogStore>,
    /// User store for authentication
    pub user_store: Arc<UserStore>,
}

impl AuditHandlerState {
    /// Create new audit handler state
    pub fn new(audit_log_store: Arc<PgAuditLogStore>, user_store: Arc<UserStore>) -> Self {
        Self {
            audit_log_store,
            user_store,
        }
    }
}

/// Error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Error message
    pub error: String,
}

/// Check if user is admin using AuthUser from middleware and DB verification
async fn is_admin(user: &AuthUser, user_store: &UserStore) -> bool {
    // 1. Extract user ID
    let user_id = match Uuid::parse_str(&user.id) {
        Ok(uid) => uid,
        Err(e) => {
            tracing::warn!("Invalid user ID in auth user: {}", e);
            return false;
        }
    };

    // 2. Check user roles from database to ensure up-to-date permissions
    // Note: We check DB instead of trusting the token roles immediately for higher security on admin actions
    match operations::roles::get_user_roles(user_store.database(), &user_id).await {
        Ok(roles) => roles.iter().any(|r| r.name == "admin"),
        Err(e) => {
            tracing::error!("Failed to fetch roles for user {}: {}", user_id, e);
            false
        }
    }
}

/// Apply filters to audit logs
fn apply_filters(mut logs: Vec<AuditLog>, query: &AuditLogQuery) -> Vec<AuditLog> {
    if let Some(ref event) = query.event {
        logs.retain(|l| l.event == *event);
    }
    if let Some(ref user_id) = query.user_id {
        logs.retain(|l| l.user_id.as_deref() == Some(user_id.as_str()));
    }
    if let Some(ref client_id) = query.client_id {
        logs.retain(|l| l.client_id.as_deref() == Some(client_id.as_str()));
    }
    if let Some(ref status) = query.status {
        logs.retain(|l| l.status == *status);
    }
    if let Some(ref from) = query.from {
        if let Ok(from_dt) = DateTime::parse_from_rfc3339(from) {
            let from_utc = from_dt.with_timezone(&Utc);
            logs.retain(|l| l.timestamp >= from_utc);
        }
    }
    if let Some(ref to) = query.to {
        if let Ok(to_dt) = DateTime::parse_from_rfc3339(to) {
            let to_utc = to_dt.with_timezone(&Utc);
            logs.retain(|l| l.timestamp <= to_utc);
        }
    }
    logs
}

/// Get audit logs with filtering and pagination
///
/// GET /logs
pub async fn get_audit_logs(
    State(state): State<Arc<AuditHandlerState>>,
    Extension(user): Extension<AuthUser>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check admin authorization
    if !is_admin(&user, &state.user_store).await {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Admin access required".to_string(),
            }),
        ));
    }

    // Get all logs
    let logs = match state.audit_log_store.all().await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Audit log query error: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to query audit logs".to_string(),
                }),
            ));
        }
    };

    // Apply filters
    let logs = apply_filters(logs, &query);

    // Apply pagination
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(100);
    let total = logs.len();
    let logs: Vec<AuditLog> = logs.into_iter().skip(offset).take(limit).collect();

    Ok(Json(AuditLogResponse { total, logs }))
}

/// Export audit logs as CSV
///
/// GET /logs/export
pub async fn export_audit_logs_csv(
    State(state): State<Arc<AuditHandlerState>>,
    Extension(user): Extension<AuthUser>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // Check admin authorization
    if !is_admin(&user, &state.user_store).await {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Admin access required".to_string(),
            }),
        ));
    }

    // Get all logs
    let logs = match state.audit_log_store.all().await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Audit log query error: {}", e);
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to query audit logs".to_string(),
                }),
            ));
        }
    };

    // Apply filters
    let logs = apply_filters(logs, &query);

    // Generate CSV
    let mut wtr = String::new();
    wtr.push_str("timestamp,event,user_id,client_id,status,detail\n");
    for log in logs {
        let ts = log.timestamp.to_rfc3339();
        let event = &log.event;
        let user_id = log.user_id.as_deref().unwrap_or("");
        let client_id = log.client_id.as_deref().unwrap_or("");
        let status = &log.status;
        let detail = log
            .detail
            .as_deref()
            .unwrap_or("")
            .replace('\n', " ")
            .replace('"', "'");
        let _ = writeln!(
            wtr,
            "\"{ts}\",\"{event}\",\"{user_id}\",\"{client_id}\",\"{status}\",\"{detail}\""
        );
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/csv")
        .header(
            "Content-Disposition",
            "attachment; filename=\"audit_logs.csv\"",
        )
        .body(wtr.into())
        .unwrap())
}

/// Create audit log routes for the application
pub fn create_audit_log_routes() -> Router<Arc<AuditHandlerState>> {
    Router::new()
        .route("/logs", get(get_audit_logs))
        .route("/logs/export", get(export_audit_logs_csv))
}
