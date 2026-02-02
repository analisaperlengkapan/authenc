use axum::extract::{FromRef, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use chrono::Utc;
use std::sync::Arc;

/// Wrapper state for database connectivity checks
#[derive(Clone)]
pub struct HealthState(pub Arc<authenc_db::database::Database>);

impl FromRef<Arc<authenc_db::database::Database>> for HealthState {
    fn from_ref(db: &Arc<authenc_db::database::Database>) -> Self {
        Self(db.clone())
    }
}

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
pub async fn ready(State(state): State<HealthState>) -> impl IntoResponse {
    let db_status = match state.0.health_check().await {
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
pub fn create_health_routes<S>() -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
    HealthState: FromRef<S>,
{
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
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use serde_json::Value;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_endpoint() {
        use authenc_db::database::Database;
        use http_body_util::BodyExt;

        // Setup with mock DB (required by router state)
        let db = Database::mock().await;
        // Pass Arc<Database> directly, which implements FromRef<Arc<Database>>
        let app = create_health_routes().with_state(Arc::new(db));

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
        use authenc_db::database::{Database, MockStatus};
        use http_body_util::BodyExt;

        // Test case 1: Database is healthy
        let db = Database::mock().await.with_mock_status(MockStatus::Healthy);
        let app = create_health_routes().with_state(Arc::new(db));

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

        // Test case 2: Database is unhealthy
        // Verify that the health check correctly handles database errors
        let db = Database::mock()
            .await
            .with_mock_status(MockStatus::Unhealthy(
                "Database connection failed".to_string(),
            ));
        let app = create_health_routes().with_state(Arc::new(db));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["status"], "not ready");
        assert_eq!(body["database"], "disconnected");
        assert_eq!(body["error"], "Database error: Database connection failed");
    }

    #[tokio::test]
    async fn test_live_endpoint() {
        use authenc_db::database::Database;
        use http_body_util::BodyExt;

        // Setup with mock DB (required by router state)
        let db = Database::mock().await;
        let app = create_health_routes().with_state(Arc::new(db));

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
