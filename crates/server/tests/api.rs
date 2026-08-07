//! The REST API over HTTP.
//!
//! What these prove is not "the handler works" but "the handler cannot be
//! reached without the right permission". That is the property the previous
//! design could not have: authorisation there was middleware matched on URL
//! prefixes, so a route mounted on the wrong router silently lost it.

// `allow-unwrap-in-tests` in clippy.toml only covers `#[cfg(test)]` modules;
// an integration-test crate needs the allowance stated here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use authenc_contract::Permission;
use authenc_identity::{
    Db, PasswordHasher, realm, role,
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
        mailer: std::sync::Arc::new(authenc_identity::mail::CapturingMailer::new()),
        leptos_options,
    };

    let mut server = TestServer::new(authenc_server::http::router(state));
    server.save_cookies();
    server
}

/// Create a realm, and a user holding exactly `permissions`.
async fn seed_with(db: &Db, username: &str, permissions: &[Permission]) {
    let hasher = PasswordHasher::new();
    let realm = match realm::by_name(db, "master").await {
        Ok(existing) => existing,
        Err(_) => realm::create(db, "master", "Master").await.unwrap(),
    };

    let user = user::create(
        db,
        &hasher,
        NewUser {
            realm_id: realm.id,
            username,
            email: &format!("{username}@example.com"),
            password: PASSWORD,
            first_name: None,
            last_name: None,
        },
    )
    .await
    .unwrap();

    if !permissions.is_empty() {
        let role = role::ensure(db, realm.id, username, None).await.unwrap();
        role::set_permissions(db, realm.id, role.id, permissions)
            .await
            .unwrap();
        role::grant(db, user.id, role.id).await.unwrap();
    }
}

/// Sign in and start sending the session's CSRF token, as a real client must.
async fn sign_in(server: &mut TestServer, username: &str) {
    server
        .post("/api/sfn/login")
        .json(&json!({
            "request": { "realm": "master", "identifier": username, "password": PASSWORD }
        }))
        .await
        .assert_status_ok();

    let csrf = server.get("/api/v1/csrf").await;
    csrf.assert_status_ok();
    let token = csrf.json::<serde_json::Value>()["token"]
        .as_str()
        .expect("a csrf token")
        .to_owned();

    server.add_header("x-csrf-token", token);
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_api_is_closed_to_anonymous_callers(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let server = server(db);

    for path in [
        "/api/v1/whoami",
        "/api/v1/users",
        "/api/v1/roles",
        "/api/v1/realm",
    ] {
        server
            .get(path)
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_openapi_document_is_public_and_describes_every_route(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;

    // Public on purpose: a client needs the schema before it has credentials,
    // and the schema reveals shape, not contents.
    let response = server(db).get("/api/v1/openapi.json").await;
    response.assert_status_ok();

    let doc: serde_json::Value = response.json();
    let paths = doc["paths"].as_object().expect("paths object");

    for expected in [
        "/api/v1/whoami",
        "/api/v1/users",
        "/api/v1/users/{user_id}",
        "/api/v1/roles",
        "/api/v1/realm",
    ] {
        assert!(
            paths.contains_key(expected),
            "missing {expected} from {paths:?}"
        );
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn whoami_reports_the_permissions_actually_held(db: PgPool) {
    seed_with(&db, "reader", &[Permission::UserRead]).await;
    let mut server = server(db);
    sign_in(&mut server, "reader").await;

    let response = server.get("/api/v1/whoami").await;
    response.assert_status_ok();

    let body: serde_json::Value = response.json();
    assert_eq!(body["permissions"], json!(["user:read"]));
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_user_with_no_permissions_is_refused_everything(db: PgPool) {
    seed_with(&db, "nobody", &[]).await;
    let mut server = server(db);
    sign_in(&mut server, "nobody").await;

    // Authenticated but unauthorised: 403, not 401. Telling them to log in
    // again would be misleading.
    for path in ["/api/v1/users", "/api/v1/roles", "/api/v1/realm"] {
        server.get(path).await.assert_status(StatusCode::FORBIDDEN);
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn read_permission_does_not_confer_write(db: PgPool) {
    seed_with(&db, "reader", &[Permission::UserRead]).await;
    let mut server = server(db);
    sign_in(&mut server, "reader").await;

    server.get("/api/v1/users").await.assert_status_ok();

    server
        .post("/api/v1/users")
        .json(&json!({
            "username": "carol",
            "email": "carol@example.com",
            "password": PASSWORD,
        }))
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "../../migrations")]
async fn user_permissions_do_not_confer_role_management(db: PgPool) {
    seed_with(&db, "usermgr", &[Permission::UserWrite]).await;
    let mut server = server(db);
    sign_in(&mut server, "usermgr").await;

    server
        .post("/api/v1/roles")
        .json(&json!({ "name": "auditor" }))
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_administrator_can_run_the_full_user_lifecycle(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;

    let created = server
        .post("/api/v1/users")
        .json(&json!({
            "username": "carol",
            "email": "carol@example.com",
            "password": PASSWORD,
            "first_name": "Carol",
        }))
        .await;
    created.assert_status(StatusCode::CREATED);
    let user_id = created.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let listed = server.get("/api/v1/users").await;
    listed.assert_status_ok();
    assert_eq!(listed.json::<serde_json::Value>()["total"], 2);

    server
        .post(&format!("/api/v1/users/{user_id}/enabled"))
        .json(&json!({ "enabled": false }))
        .await
        .assert_status_ok();

    server
        .delete(&format!("/api/v1/users/{user_id}"))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    assert_eq!(
        server
            .get("/api/v1/users")
            .await
            .json::<serde_json::Value>()["total"],
        1,
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_created_user_never_carries_a_credential_in_the_response(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;

    let response = server
        .post("/api/v1/users")
        .json(&json!({
            "username": "carol",
            "email": "carol@example.com",
            "password": PASSWORD,
        }))
        .await;

    let body = response.text().to_lowercase();
    for forbidden in ["password", "phc", "argon2", "hash"] {
        assert!(!body.contains(forbidden), "{forbidden} leaked: {body}");
    }
}

#[sqlx::test(migrations = "../../migrations")]
async fn creating_a_user_with_a_weak_password_is_a_400(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;

    let response = server
        .post("/api/v1/users")
        .json(&json!({ "username": "carol", "email": "carol@example.com", "password": "x" }))
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        response.header("content-type"),
        "application/problem+json",
        "errors must be RFC 9457 problem documents",
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_administrator_cannot_delete_their_own_account(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    let mut server = server(db);
    sign_in(&mut server, "admin").await;

    let me = server.get("/api/v1/whoami").await;
    me.assert_status_ok();

    let users = server
        .get("/api/v1/users")
        .await
        .json::<serde_json::Value>();
    let my_id = users["items"][0]["id"].as_str().unwrap().to_owned();

    server
        .delete(&format!("/api/v1/users/{my_id}"))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "../../migrations")]
async fn disabling_a_user_ends_their_session_over_http(db: PgPool) {
    seed_with(&db, "admin", Permission::ALL).await;
    seed_with(&db, "victim", &[]).await;

    let mut admin = server(db.clone());
    sign_in(&mut admin, "admin").await;

    let mut victim = server(db);
    sign_in(&mut victim, "victim").await;
    // `whoami` needs no permission — it only reports who you are — so a
    // session with none still answers 200 while it is alive.
    victim.get("/api/v1/whoami").await.assert_status_ok();

    let users = admin.get("/api/v1/users").await.json::<serde_json::Value>();
    let victim_id = users["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "victim")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    admin
        .post(&format!("/api/v1/users/{victim_id}/enabled"))
        .json(&json!({ "enabled": false }))
        .await
        .assert_status_ok();

    // 401 now, not 403: the session itself is gone.
    victim
        .get("/api/v1/whoami")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}
