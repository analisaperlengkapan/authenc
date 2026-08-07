//! HTTP-level tests against the real router.
//!
//! These drive the assembled application — middleware stack included — rather
//! than calling handlers directly, because most of what is asserted here is a
//! property of the stack rather than of any one handler.

// `allow-unwrap-in-tests` in clippy.toml only covers `#[cfg(test)]` modules;
// an integration-test crate needs the allowance stated here. `unwrap` in a
// test is an assertion, which is exactly what we want it to be.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use authenc_identity::Db;
use axum::http::StatusCode;
use axum_test::TestServer;
use leptos::prelude::LeptosOptions;
use sqlx::PgPool;

/// Build the application the way `main` does, minus the listener.
fn server(db: Db) -> TestServer {
    // `LeptosOptions::builder()` needs an output name; the rest defaults.
    let leptos_options = LeptosOptions::builder()
        .output_name("authenc")
        .site_root(std::sync::Arc::<str>::from("target/site"))
        .build();

    let state = authenc_server::state::AppState {
        config: std::sync::Arc::new(authenc_server::config::Config::default()),
        db,
        hasher: authenc_identity::PasswordHasher::new(),
        leptos_options,
    };

    TestServer::new(authenc_server::http::router(state))
}

#[sqlx::test(migrations = "../../migrations")]
async fn liveness_answers_without_touching_the_database(db: PgPool) {
    let response = server(db).get("/health/live").await;

    response.assert_status_ok();
    response.assert_json_contains(&serde_json::json!({ "status": "ok" }));
}

#[sqlx::test(migrations = "../../migrations")]
async fn readiness_is_ok_while_the_database_answers(db: PgPool) {
    server(db).get("/health/ready").await.assert_status_ok();
}

#[sqlx::test(migrations = "../../migrations")]
async fn readiness_reports_503_when_the_database_is_gone(db: PgPool) {
    // Closing the pool is the closest we can get to a database outage without
    // stopping the server. 503 (not 500) is the contract: it tells an
    // orchestrator to stop routing here, not to restart the process.
    db.close().await;

    let response = server(db).get("/health/ready").await;

    response.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.header("content-type"),
        "application/problem+json",
        "failures must be RFC 9457 problem documents",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn every_response_carries_the_security_headers(db: PgPool) {
    let response = server(db).get("/health/live").await;

    for (header, expected) in [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("cross-origin-opener-policy", "same-origin"),
    ] {
        assert_eq!(response.header(header), expected, "missing {header}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn hsts_is_absent_outside_production(db: PgPool) {
    // Sending HSTS over plain HTTP in development would pin the browser to a
    // scheme the dev server does not speak. The old code emitted it
    // unconditionally while serving no TLS at all.
    let response = server(db).get("/health/live").await;

    assert!(
        !response.headers().contains_key("strict-transport-security"),
        "HSTS must be off when config.security.hsts is false",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn every_response_carries_a_correlation_id(db: PgPool) {
    let response = server(db).get("/health/live").await;

    assert!(
        !response.header("x-request-id").is_empty(),
        "responses must carry x-request-id so a log line can be tied to a request",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn cors_does_not_reflect_arbitrary_origins(db: PgPool) {
    // The default allow-list is empty, meaning same-origin only. The previous
    // server applied `CorsLayer::permissive()` — `Allow-Origin: *` on an IAM
    // server — while parsing and discarding the configured list.
    let response = server(db)
        .get("/health/live")
        .add_header("origin", "https://evil.example")
        .await;

    let allowed = response
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok());

    assert!(
        allowed.is_none(),
        "an unlisted origin must not be allowed, got {allowed:?}",
    );
}
