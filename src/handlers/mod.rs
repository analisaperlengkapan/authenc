// Re-export axum router for convenience
use axum::{routing::get, Router};
use std::sync::Arc;

// Database
use crate::database::Database;

// Handlers
pub mod health_axum;
pub mod jwt_ed25519;
pub mod oidc_ed25519;
pub use health_axum::create_health_routes;

// Legacy Actix handlers (temporarily disabled during migration)
// mod audit;
// mod group;
mod health;
// mod oidc_client;
pub mod oidc_jwt;
pub mod oidc_keys;
// mod oidc_provider;
// mod session;
// mod totp;
// mod totp_verify;

/// Create the main application router with all routes
pub fn create_router(db: Arc<Database>) -> Router {
    Router::new()
        .route("/health", get(health_axum::health))
        .route("/ready", get(health_axum::ready))
        .route("/live", get(health_axum::live))
        // Add more route groups here as they're migrated to Axum
        // .nest("/api", api_routes())
        // .nest("/auth", auth_routes())
        .with_state(db)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_endpoint() {
        let db = Arc::new(Database::mock().await);
        let app = create_router(db);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "healthy");
    }
}
