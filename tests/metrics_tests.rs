use actix_web::{test, web, App, HttpResponse};

async fn metrics() -> HttpResponse { HttpResponse::Ok().body("metrics ok") }

#[actix_web::test]
async fn metrics_route_enabled() {
    let app = test::init_service(App::new().route("/metrics", web::get().to(metrics))).await;
    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
    let body = test::read_body(resp).await;
    assert_eq!(body, "metrics ok");
}
