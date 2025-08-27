use axum::{http::StatusCode, response::IntoResponse, routing::get, Router};
use tower::ServiceExt;

async fn metrics() -> impl IntoResponse {
    "metrics ok"
}

#[tokio::test]
async fn metrics_route_enabled() {
    let app = Router::new().route("/metrics", get(metrics));
    
    let request = axum::http::Request::builder()
        .uri("/metrics")
        .body(axum::body::Body::empty())
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(body, "metrics ok");
}
