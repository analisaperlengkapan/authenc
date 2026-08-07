//! End-to-end authentication over HTTP.
//!
//! These drive the assembled router — server functions, cookies, middleware —
//! rather than calling the use case directly, because the properties that
//! matter here (what is in the `Set-Cookie` header, what a browser can read)
//! only exist at that level.

// `allow-unwrap-in-tests` in clippy.toml only covers `#[cfg(test)]` modules;
// an integration-test crate needs the allowance stated here. `unwrap` in a
// test is an assertion, which is exactly what we want it to be.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use authenc_identity::{
    Db, PasswordHasher, realm,
    user::{self, NewUser},
};
use axum::http::StatusCode;
use axum_test::TestServer;
use leptos::prelude::LeptosOptions;
use serde_json::json;
use sqlx::PgPool;

const PASSWORD: &str = "correct horse battery staple";

fn server(db: Db) -> TestServer {
    let leptos_options = LeptosOptions::builder()
        .output_name("authenc")
        .site_root(std::sync::Arc::<str>::from("target/site"))
        .build();

    let state = authenc_server::state::AppState {
        config: std::sync::Arc::new(authenc_server::config::Config::default()),
        db,
        hasher: PasswordHasher::new(),
        leptos_options,
    };

    let mut server = TestServer::new(authenc_server::http::router(state));
    // Keep cookies between requests, the way a browser does.
    server.save_cookies();
    server
}

async fn seed(db: &Db) {
    let hasher = PasswordHasher::new();
    let realm = realm::create(db, "master", "Master").await.unwrap();
    user::create(
        db,
        &hasher,
        NewUser {
            realm_id: realm.id,
            username: "alice",
            email: "alice@example.com",
            password: PASSWORD,
            first_name: None,
            last_name: None,
        },
    )
    .await
    .unwrap();
}

fn login_body(identifier: &str, password: &str) -> serde_json::Value {
    json!({ "request": { "realm": "master", "identifier": identifier, "password": password } })
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_correct_login_sets_an_http_only_session_cookie(db: PgPool) {
    seed(&db).await;

    let response = server(db)
        .post("/api/sfn/login")
        .json(&login_body("alice", PASSWORD))
        .await;

    response.assert_status_ok();

    let set_cookie = response.header("set-cookie");
    let set_cookie = set_cookie.to_str().unwrap();

    // The three properties that make the session unreachable from page script
    // and unusable cross-site.
    assert!(set_cookie.contains("HttpOnly"), "got: {set_cookie}");
    assert!(set_cookie.contains("SameSite=Lax"), "got: {set_cookie}");
    assert!(set_cookie.contains("Path=/"), "got: {set_cookie}");
    assert!(
        set_cookie.starts_with("authenc_session="),
        "got: {set_cookie}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_login_response_body_carries_no_credential(db: PgPool) {
    seed(&db).await;

    let response = server(db)
        .post("/api/sfn/login")
        .json(&login_body("alice", PASSWORD))
        .await;

    let body = response.text();
    for forbidden in ["password", "phc", "argon2", "token", "hash"] {
        assert!(
            !body.to_lowercase().contains(forbidden),
            "{forbidden} appeared in the login response: {body}",
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_session_cookie_identifies_the_user_on_the_next_request(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    server
        .post("/api/sfn/login")
        .json(&login_body("alice", PASSWORD))
        .await
        .assert_status_ok();

    // `save_cookies` replays the session cookie, as a browser would.
    let me = server.post("/api/sfn/me").await;
    me.assert_status_ok();
    assert!(me.text().contains("alice"), "got: {}", me.text());
}

#[sqlx::test(migrations = "../../migrations")]
async fn nobody_is_signed_in_without_a_cookie(db: PgPool) {
    seed(&db).await;

    let response = server(db).post("/api/sfn/me").await;

    response.assert_status_ok();
    assert!(
        !response.text().contains("alice"),
        "an anonymous request must not resolve to a user",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn logging_out_clears_the_cookie_and_the_session(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    server
        .post("/api/sfn/login")
        .json(&login_body("alice", PASSWORD))
        .await
        .assert_status_ok();

    let logout = server.post("/api/sfn/logout").await;
    logout.assert_status_ok();

    let set_cookie = logout.header("set-cookie");
    let set_cookie = set_cookie.to_str().unwrap();
    assert!(
        set_cookie.contains("Max-Age=0"),
        "the cookie must be expired, got: {set_cookie}",
    );

    // And the server side must be gone too — clearing only the cookie would
    // leave a working session for anyone who captured the value.
    assert!(!server.post("/api/sfn/me").await.text().contains("alice"));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_wrong_password_is_rejected_without_a_cookie(db: PgPool) {
    seed(&db).await;

    let response = server(db)
        .post("/api/sfn/login")
        .json(&login_body("alice", "wrong password here"))
        .await;

    // 401 specifically: asserting merely "not 200" would also pass on a 500
    // from a malformed request, which is how this test first passed while the
    // login endpoint was in fact rejecting its own argument encoding.
    response.assert_status(StatusCode::UNAUTHORIZED);
    assert!(
        response.maybe_header("set-cookie").is_none(),
        "a failed login must not establish a session",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_failed_login_does_not_reveal_whether_the_account_exists(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    let wrong_password = server
        .post("/api/sfn/login")
        .json(&login_body("alice", "wrong password here"))
        .await;
    let unknown_user = server
        .post("/api/sfn/login")
        .json(&login_body("nobody", PASSWORD))
        .await;

    assert_eq!(wrong_password.status_code(), unknown_user.status_code());
    assert_eq!(wrong_password.text(), unknown_user.text());
}

#[sqlx::test(migrations = "../../migrations")]
async fn repeated_failures_are_rate_limited_over_http(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    for _ in 0..authenc_identity::login::MAX_ATTEMPTS_PER_IDENTIFIER {
        server
            .post("/api/sfn/login")
            .json(&login_body("alice", "wrong password here"))
            .await;
    }

    // Even the correct password must now be refused.
    let response = server
        .post("/api/sfn/login")
        .json(&login_body("alice", PASSWORD))
        .await;

    response.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response.maybe_header("set-cookie").is_none(),
        "a locked-out attempt must not establish a session",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_login_page_renders_server_side(db: PgPool) {
    seed(&db).await;

    let response = server(db).get("/login").await;

    response.assert_status_ok();
    let html = response.text();
    // Server-rendered, not an empty shell waiting for JavaScript — which is
    // exactly what the previous deployment served.
    assert!(html.contains("Sign in"), "got: {html}");
    assert!(
        html.contains("autocomplete=\"current-password\""),
        "got: {html}"
    );
}
