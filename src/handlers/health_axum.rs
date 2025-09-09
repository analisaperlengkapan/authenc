use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use chrono::Utc;
use std::sync::Arc;

use crate::database::Database;

/// Health check response
#[derive(Debug, serde::Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    timestamp: String,
}

/// Readiness response
#[derive(Debug, serde::Serialize)]
struct ReadyResponse {
    status: &'static str,
    database: &'static str,
    error: Option<String>,
    timestamp: String,
}

/// Liveness response
#[derive(Debug, serde::Serialize)]
struct LiveResponse {
    status: &'static str,
    timestamp: String,
}

/// Basic health check endpoint
pub async fn health() -> impl IntoResponse {
    let response = HealthResponse {
        status: "healthy",
        version: env!("CARGO_PKG_VERSION"),
        timestamp: Utc::now().to_rfc3339(),
    };

    Json(response)
}

/// Readiness check endpoint with database connectivity check
pub async fn ready(State(db): State<Arc<Database>>) -> impl IntoResponse {
    let db_status = match db.health_check().await {
        Ok(_) => "connected",
        Err(e) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadyResponse {
                    status: "not ready",
                    database: "disconnected",
                    error: Some(e.to_string()),
                    timestamp: Utc::now().to_rfc3339(),
                }),
            );
        }
    };

    let response = ReadyResponse {
        status: "ready",
        database: db_status,
        error: None,
        timestamp: Utc::now().to_rfc3339(),
    };

    (StatusCode::OK, Json(response))
}

/// Liveness check endpoint
pub async fn live() -> impl IntoResponse {
    let response = LiveResponse {
        status: "alive",
        timestamp: Utc::now().to_rfc3339(),
    };

    Json(response)
}

/// Create health routes
pub fn create_health_routes() -> axum::Router<Arc<Database>> {
    use axum::routing::get;

    axum::Router::new()
        .route("/", get(health))
        .route("/ready", get(ready))
        .route("/live", get(live))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = Router::new().route("/", get(health));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["status"], "healthy");
    }

    #[tokio::test]
    async fn test_ready_endpoint() {
        // For testing, we'll create a mock database state
        // In a real scenario, you'd use a test database
        let config = crate::AppConfig::default();
        let app_state = crate::app::AppState::new(config)
            .await
            .expect("Failed to create app state");
        let db = app_state.database;

        let app = create_health_routes().with_state(db);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["status"], "ready");
        assert_eq!(body["database"], "connected");
    }

    #[tokio::test]
    async fn test_live_endpoint() {
        let app = Router::new().route("/live", get(live));

        let response = app
            .oneshot(Request::builder().uri("/live").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["status"], "alive");
    }
}
