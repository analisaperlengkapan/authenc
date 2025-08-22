use actix_web::{web, HttpResponse, Responder};
use serde_json::json;

use crate::database::Database;

/// Health check endpoint
pub async fn health() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/// Readiness check endpoint with database connectivity
pub async fn ready(db: web::Data<Database>) -> impl Responder {
    match db.health_check().await {
        Ok(_) => HttpResponse::Ok().json(json!({
            "status": "ready",
            "database": "connected",
            "timestamp": chrono::Utc::now().to_rfc3339()
        })),
        Err(_) => HttpResponse::ServiceUnavailable().json(json!({
            "status": "not ready",
            "database": "disconnected",
            "timestamp": chrono::Utc::now().to_rfc3339()
        }))
    }
}

/// Liveness probe
pub async fn live() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "status": "alive",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

/// Configure health routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("", web::get().to(health))
       .route("/ready", web::get().to(ready))
       .route("/live", web::get().to(live));
}
