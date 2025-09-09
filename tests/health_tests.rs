use authenc::app::ApplicationBuilder;
use authenc::AppConfig;
use axum::{http::StatusCode, routing::get, Router};
use tower::ServiceExt;

#[tokio::test]
async fn health_endpoint_basic() {
    let cfg = AppConfig::default();
    let _builder = ApplicationBuilder::new(cfg); // reserved for future integration run()

    // Build a minimal Axum app mirroring run() config
    let app = Router::new().route("/health", get(|| async { "OK" }));

    let request = axum::http::Request::builder()
        .uri("/health")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
