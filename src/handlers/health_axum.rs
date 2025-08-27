use axum::http::StatusCode;
use axum::response::{Json, IntoResponse};
use chrono::Utc;

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

/// Basic health check endpoint (stateless)
pub async fn health() -> impl IntoResponse {
    let response = HealthResponse {
        status: "healthy",
        version: env!("CARGO_PKG_VERSION"),
        timestamp: Utc::now().to_rfc3339(),
    };

    Json(response)
}

/// Readiness check endpoint (stateless for now)
pub async fn ready() -> impl IntoResponse {
    let response = ReadyResponse {
        status: "ready",
        database: "connected", // TODO: Add proper database check when state is available
        error: None,
        timestamp: Utc::now().to_rfc3339(),
    };

    (StatusCode::OK, Json(response))
}

/// Liveness probe (stateless)
pub async fn live() -> impl IntoResponse {
    let response = LiveResponse {
        status: "alive",
        timestamp: Utc::now().to_rfc3339(),
    };

    Json(response)
}

/// Create health routes
pub fn create_health_routes() -> axum::Router {
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
        let app = Router::new().route("/ready", get(ready));

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
