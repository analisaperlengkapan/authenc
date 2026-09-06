//! Social sign-in over HTTP.
//!
//! What these prove is not "the redirect works" but that the callback cannot
//! be driven by somebody who did not start the sign-in. That is the property
//! an OAuth *client* has to have, and it is a different one from anything the
//! provider endpoints in this repository need.

// `allow-unwrap-in-tests` in clippy.toml only covers `#[cfg(test)]` modules;
// an integration-test crate needs the allowance stated here.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use authenc_identity::{
    Db, MasterKey, PasswordHasher, SecretToken,
    federation::{self, Kind, NewProvider},
    realm,
};
use axum::http::StatusCode;
use axum_test::TestServer;
use leptos::prelude::LeptosOptions;
use sqlx::PgPool;

fn server(db: Db) -> TestServer {
    let leptos_options = LeptosOptions::builder()
        .output_name("authenc")
        .site_root(std::sync::Arc::<str>::from("target/site"))
        .build();

    let config = authenc_server::config::Config::default();
    let state = authenc_server::state::AppState {
        master_key: std::sync::Arc::new(config.master_key().unwrap()),
        relying_party: std::sync::Arc::new(config.relying_party().unwrap()),
        config: std::sync::Arc::new(config),
        db,
        hasher: PasswordHasher::new(),
        mailer: std::sync::Arc::new(authenc_identity::mail::CapturingMailer::new()),
        leptos_options,
    };

    let mut server = TestServer::new(authenc_server::http::router(state));
    server.save_cookies();
    server
}

/// A realm with one enabled provider.
async fn seed(db: &Db) {
    let realm = realm::create(db, "master", "Master").await.unwrap();
    let config = authenc_server::config::Config::default();
    federation::create(
        db,
        &config.master_key().unwrap(),
        NewProvider {
            realm_id: realm.id,
            alias: "upstream",
            kind: Kind::Google,
            display_name: "Upstream",
            client_id: "our-client-id",
            client_secret: "our-client-secret",
            authorization_endpoint: "https://provider.example/authorize",
            token_endpoint: "https://provider.example/token",
            userinfo_endpoint: None,
            issuer: Some("https://provider.example"),
            scopes: &["openid".to_owned(), "email".to_owned()],
            allow_provisioning: true,
            link_by_verified_email: false,
        },
    )
    .await
    .unwrap();
}

#[sqlx::test(migrations = "../../migrations")]
async fn starting_a_sign_in_redirects_to_the_provider(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    let response = server.get("/realms/master/federation/upstream/start").await;

    response.assert_status(StatusCode::SEE_OTHER);
    let location = response.header("location");
    let location = location.to_str().unwrap();

    assert!(
        location.starts_with("https://provider.example/authorize?"),
        "{location}"
    );
    assert!(
        location.contains("code_challenge_method=S256"),
        "{location}"
    );
    assert!(location.contains("nonce="), "{location}");
    // The callback URL comes from configuration, never from the Host header.
    assert!(
        location.contains("redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Frealms%2Fmaster%2Ffederation%2Fupstream%2Fcallback"),
        "{location}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn starting_a_sign_in_binds_the_state_to_this_browser(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    let response = server.get("/realms/master/federation/upstream/start").await;

    let cookie = response.maybe_cookie("authenc_federation");
    assert!(cookie.is_some(), "the state must be bound to the browser");

    let cookie = cookie.unwrap();
    assert!(
        cookie.http_only().unwrap_or(false),
        "not readable by script"
    );

    // And it is the same value the provider will echo.
    let location = response.header("location");
    let location = location.to_str().unwrap();
    assert!(
        location.contains(&format!("state={}", cookie.value())),
        "{location}"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn an_unknown_provider_is_refused_without_saying_so(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    let response = server
        .get("/realms/master/federation/does-not-exist/start")
        .await;

    response.assert_status(StatusCode::SEE_OTHER);
    assert_eq!(response.header("location"), "/login?error=federation");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_disabled_provider_offers_no_sign_in(db: PgPool) {
    seed(&db).await;
    let master_realm = realm::by_name(&db, "master").await.unwrap();
    let provider = federation::by_alias(&db, master_realm.id, "upstream")
        .await
        .unwrap();
    federation::set_enabled(&db, provider.id, false)
        .await
        .unwrap();

    let server = server(db);
    let response = server.get("/realms/master/federation/upstream/start").await;

    assert_eq!(response.header("location"), "/login?error=federation");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_callback_without_the_cookie_is_refused(db: PgPool) {
    // The login-CSRF case. The attacker holds a valid, unspent state — they
    // started the sign-in themselves — and hands the victim the callback URL.
    // Without the cookie the victim's browser cannot finish it.
    seed(&db).await;
    let mut attacker = server(db.clone());
    let started = attacker
        .get("/realms/master/federation/upstream/start")
        .await;
    let state = started.maybe_cookie("authenc_federation").unwrap();
    let state = state.value().to_owned();

    // A fresh browser: the victim's.
    attacker.clear_cookies();
    let victim = server(db);
    let response = victim
        .get(&format!(
            "/realms/master/federation/upstream/callback?code=stolen&state={state}"
        ))
        .await;

    response.assert_status(StatusCode::SEE_OTHER);
    assert_eq!(response.header("location"), "/login?error=federation");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_callback_whose_state_does_not_match_its_cookie_is_refused(db: PgPool) {
    seed(&db).await;
    let server = server(db.clone());

    let started = server.get("/realms/master/federation/upstream/start").await;
    let cookie = started.maybe_cookie("authenc_federation").unwrap();
    let state = SecretToken::from_client(cookie.value());

    // The cookie is this browser's; the query parameter is somebody else's.
    let response = server
        .get("/realms/master/federation/upstream/callback?code=c&state=another-sign-in")
        .await;

    response.assert_status(StatusCode::SEE_OTHER);
    assert_eq!(response.header("location"), "/login?error=federation");

    // And — this is the part that distinguishes the check from a later
    // failure — the mismatch was caught *before* anything was claimed, so the
    // visitor's own sign-in is still completable. Asserting only the redirect
    // would pass even with the comparison deleted, because the request would
    // then die at the unreachable provider instead.
    assert!(
        authenc_oauth::social::claim_state(&db, &state)
            .await
            .is_ok(),
        "a mismatched callback must not consume the pending sign-in"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_declined_sign_in_is_not_an_error_page(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    server.get("/realms/master/federation/upstream/start").await;

    let response = server
        .get("/realms/master/federation/upstream/callback?error=access_denied")
        .await;

    response.assert_status(StatusCode::SEE_OTHER);
    assert_eq!(response.header("location"), "/login?error=federation");
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_return_to_that_leaves_this_site_does_not_start_a_sign_in(db: PgPool) {
    seed(&db).await;
    let server = server(db);

    // Literal characters, because that is what reaches the browser. A
    // *percent-encoded* backslash — `/%5Cevil.example` — is not in this list
    // and is deliberately allowed: the URL parser does not decode it before
    // determining the origin, so it stays a path on this site.
    for hostile in [
        "https://evil.example",
        "//evil.example",
        "/\\evil.example",
        "/\tevil.example",
        "/\n//evil.example",
    ] {
        let response = server
            .get("/realms/master/federation/upstream/start")
            .add_query_param("return_to", hostile)
            .await;

        assert_eq!(
            response.header("location"),
            "/login?error=federation",
            "{hostile:?} was accepted as a return path"
        );
    }

    // And an ordinary path still works, so the rule refuses the right things
    // rather than everything.
    let allowed = server
        .get("/realms/master/federation/upstream/start")
        .add_query_param("return_to", "/admin/users")
        .await;
    assert!(
        allowed
            .header("location")
            .to_str()
            .unwrap()
            .starts_with("https://provider.example/"),
        "an ordinary path must still start a sign-in"
    );
}

#[sqlx::test(migrations = "../../migrations")]
async fn a_state_cannot_be_spent_twice(db: PgPool) {
    seed(&db).await;
    let server = server(db.clone());

    let started = server.get("/realms/master/federation/upstream/start").await;
    let state = started.maybe_cookie("authenc_federation").unwrap();
    let state = SecretToken::from_client(state.value());

    // Claimed once directly, standing in for a callback that got that far.
    assert!(
        authenc_oauth::social::claim_state(&db, &state)
            .await
            .is_ok()
    );

    // The callback now has nothing to claim, so it refuses — and does not
    // reach the token exchange, which would be a request to a provider that
    // does not exist in this test.
    let response = server
        .get(&format!(
            "/realms/master/federation/upstream/callback?code=c&state={}",
            state.expose()
        ))
        .await;

    response.assert_status(StatusCode::SEE_OTHER);
    assert_eq!(response.header("location"), "/login?error=federation");
}

#[sqlx::test(migrations = "../../migrations")]
async fn the_master_key_that_sealed_a_secret_is_the_one_that_opens_it(db: PgPool) {
    // Not an HTTP property, but the callback depends on it: a secret sealed
    // under one key and read under another fails closed rather than sending a
    // wrong credential to a provider.
    seed(&db).await;
    let master_realm = realm::by_name(&db, "master").await.unwrap();
    let provider = federation::by_alias(&db, master_realm.id, "upstream")
        .await
        .unwrap();

    let config = authenc_server::config::Config::default();
    assert_eq!(
        federation::client_secret(&db, &config.master_key().unwrap(), provider.id)
            .await
            .unwrap(),
        "our-client-secret"
    );
    assert!(
        federation::client_secret(&db, &MasterKey::generate().unwrap(), provider.id)
            .await
            .is_err()
    );
}
