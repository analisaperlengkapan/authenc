use actix_web::{test, web, App, HttpResponse};
use authenc::middleware::security::SecurityHeaders;

async fn ok() -> HttpResponse { HttpResponse::Ok().finish() }

#[actix_web::test]
async fn security_headers_present() {
    let app = test::init_service(App::new().wrap(SecurityHeaders::default()).route("/", web::get().to(ok))).await;
    let resp = test::call_service(&app, test::TestRequest::get().uri("/").to_request()).await;
    assert_eq!(resp.status(), 200);
    let headers = resp.headers();
    assert!(headers.contains_key("x-content-type-options"));
    assert!(headers.contains_key("x-frame-options"));
    assert!(headers.contains_key("x-xss-protection"));
}
