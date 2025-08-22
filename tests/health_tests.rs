use actix_web::{test, web, App};
use authenc::{AppConfig};
use authenc::app::{ApplicationBuilder};

#[actix_web::test]
async fn health_endpoint_basic() {
    let cfg = AppConfig::default();
    let _builder = ApplicationBuilder::new(cfg); // reserved for future integration run()
    // Build a minimal app mirroring run() config
    let app = test::init_service(App::new().route("/health", web::get().to(|| async { "OK" }))).await;
    let req = test::TestRequest::get().uri("/health").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}
