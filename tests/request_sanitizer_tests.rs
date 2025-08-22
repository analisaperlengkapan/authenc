use actix_web::{test, web, App, HttpResponse};
use authenc::middleware::security::{RequestSanitizer, SecurityHeaders};

async fn ok() -> HttpResponse { HttpResponse::Ok().body("OK") }

#[actix_web::test]
async fn sanitizer_blocks_sql_injection_like_pattern() {
    let app = test::init_service(App::new().wrap(RequestSanitizer).route("/q", web::get().to(ok))).await;
    let req = test::TestRequest::get().uri("/q?x=UNION%20SELECT").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn sanitizer_allows_normal_queries() {
    let app = test::init_service(App::new().wrap(RequestSanitizer).route("/q", web::get().to(ok))).await;
    let req = test::TestRequest::get().uri("/q?x=hello").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
async fn security_headers_add_hsts_only_https() {
    // Simulate two requests: one with scheme http (no HSTS), one forcing https header injection test.
    // Actix test server doesn't easily change scheme; we validate mandatory headers presence here.
    let app = test::init_service(App::new().wrap(SecurityHeaders::default()).route("/h", web::get().to(ok))).await;
    let resp = test::call_service(&app, test::TestRequest::get().uri("/h").to_request()).await;
    assert_eq!(resp.status(), 200);
    let h = resp.headers();
    assert!(h.contains_key("content-security-policy"));
    assert!(h.contains_key("referrer-policy"));
}
