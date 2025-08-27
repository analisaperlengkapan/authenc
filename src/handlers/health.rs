use axum::{extract::State, http::StatusCode, response::Json};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::database::Database;

/// Health check endpoint for Axum
pub async fn health() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/// Readiness check endpoint with database connectivity for Axum
pub async fn ready(State(db): State<Arc<Database>>) -> Result<Json<Value>, StatusCode> {
    match db.health_check().await {
        Ok(_) => Ok(Json(json!({
            "status": "ready",
            "database": "connected",
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))),
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// Liveness probe for Axum
pub async fn live() -> Json<Value> {
    Json(json!({
        "status": "alive",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}
