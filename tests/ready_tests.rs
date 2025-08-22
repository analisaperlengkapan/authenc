use actix_web::{test, web, App, HttpResponse};

async fn ready() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ready",
        "checks": { "database": "healthy" }
    }))
}

#[actix_web::test]
async fn ready_endpoint_returns_ok() {
    let app = test::init_service(App::new().route("/ready", web::get().to(ready))).await;
    let req = test::TestRequest::get().uri("/ready").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body = test::read_body(resp).await;
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["status"], "ready");
    assert_eq!(v["checks"]["database"], "healthy");
}
