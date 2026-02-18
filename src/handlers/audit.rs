//! Audit log handlers for Axum
//!
//! This module provides endpoints for querying and exporting audit logs
//! with filtering and pagination support.

use authenc_database::database::operations;
use crate::middleware::auth::AuthUser;
use authenc_models::models::audit_log::{AuditLog, AuditLogFilter};
use authenc_services::services::stores::pg_audit_log_store::PgAuditLogStore;
use authenc_services::services::stores::user_store::UserStore;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Json, Response},
    routing::get,
    Extension, Router,
};
use serde::Serialize;
use std::fmt::Write;
use std::sync::Arc;
use uuid::Uuid;

/// Query parameters for audit log filtering
pub type AuditLogQuery = AuditLogFilter;

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

/// Get audit logs with filtering and pagination
///
/// GET /logs
pub async fn get_audit_logs(
    State(state): State<Arc<AuditHandlerState>>,
    Extension(user): Extension<AuthUser>,
    Query(mut query): Query<AuditLogQuery>,
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

    // Set default pagination
    if query.limit.is_none() {
        query.limit = Some(100);
    }
    if query.offset.is_none() {
        query.offset = Some(0);
    }

    // Query logs with database-side filtering and pagination
    let (logs, total) = match state.audit_log_store.query(&query).await {
        Ok(res) => res,
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

    Ok(Json(AuditLogResponse { total: total as usize, logs }))
}

/// Export audit logs as CSV
///
/// GET /logs/export
pub async fn export_audit_logs_csv(
    State(state): State<Arc<AuditHandlerState>>,
    Extension(user): Extension<AuthUser>,
    Query(mut query): Query<AuditLogQuery>,
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

    // Export all matching logs, ignoring pagination
    query.limit = None;
    query.offset = None;

    // Query logs with database-side filtering
    let (logs, _) = match state.audit_log_store.query(&query).await {
        Ok(res) => res,
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

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/csv")
        .header(
            "Content-Disposition",
            "attachment; filename=\"audit_logs.csv\"",
        )
        .body(wtr.into())
        .map_err(|e| {
            tracing::error!("Failed to build response body: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Failed to generate CSV download".to_string(),
                }),
            )
        })
}

/// Create audit log routes for the application
pub fn create_audit_log_routes() -> Router<Arc<AuditHandlerState>> {
    Router::new()
        .route("/logs", get(get_audit_logs))
        .route("/logs/export", get(export_audit_logs_csv))
}
