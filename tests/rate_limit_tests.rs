use actix_web::{test, web, App, HttpResponse};
use authenc::middleware::rate_limit::{RateLimiter, PathRateLimiter};
use std::collections::HashMap;

async fn ok() -> HttpResponse { HttpResponse::Ok().finish() }

#[actix_web::test]
async fn global_rate_limit_blocks_after_threshold() {
    let app = test::init_service(App::new().wrap(RateLimiter::new(2)).route("/x", web::get().to(ok))).await;
    for _ in 0..2 { let resp = test::call_service(&app, test::TestRequest::get().uri("/x").to_request()).await; assert_eq!(resp.status(), 200); }
    let resp = test::call_service(&app, test::TestRequest::get().uri("/x").to_request()).await; assert_eq!(resp.status(), 429);
}

#[actix_web::test]
async fn path_rate_limit_independent_paths() {
    let mut limits = HashMap::new(); limits.insert("/api/login".to_string(), 1);
    let app = test::init_service(App::new()
        .wrap(PathRateLimiter::with_limits(limits))
        .route("/api/login", web::get().to(ok))
        .route("/api/health", web::get().to(ok))).await;
    let resp = test::call_service(&app, test::TestRequest::get().uri("/api/login").to_request()).await; assert_eq!(resp.status(), 200);
    let resp = test::call_service(&app, test::TestRequest::get().uri("/api/login").to_request()).await; assert_eq!(resp.status(), 429);
    // Another path unaffected
    let resp = test::call_service(&app, test::TestRequest::get().uri("/api/health").to_request()).await; assert_eq!(resp.status(), 200);
}
