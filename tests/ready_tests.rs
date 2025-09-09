use axum::{http::StatusCode, response::Json, routing::get, Router};
use serde_json::json;
use tower::ServiceExt;

async fn ready() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ready",
        "checks": { "database": "healthy" }
    }))
}

#[tokio::test]
async fn ready_endpoint_returns_ok() {
    let app = Router::new().route("/ready", get(ready));

    let request = axum::http::Request::builder()
        .uri("/ready")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(v["status"], "ready");
    assert_eq!(v["checks"]["database"], "healthy");
}
