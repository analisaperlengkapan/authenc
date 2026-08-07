//! Server functions.
//!
//! A `#[server]` function is one function that the browser calls and the server
//! runs. There is no DTO written twice, no hand-maintained fetch wrapper, and
//! no route string to get wrong — the argument and return types *are* the
//! contract, checked by the compiler on both sides.
//!
//! The previous console needed 60 lines of `authenticated_request` plumbing to
//! do this by hand, and that wrapper silently rejected `PATCH`, so renaming a
//! passkey failed without ever reaching the network.

use authenc_contract::model::{LoginRequest, LoginResponse};
use leptos::prelude::*;
use leptos::server_fn::codec::Json;

#[cfg(feature = "ssr")]
use crate::server_ctx::CookiePolicy;
use serde::{Deserialize, Serialize};

/// What the server reports about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerStatus {
    /// Version from `CARGO_PKG_VERSION` of the server binary.
    pub version: String,
    /// Whether the database answered.
    pub database_ready: bool,
}

/// Ask the server how it is doing.
///
/// Deliberately the first server function in the tree: it exercises the whole
/// path — browser call, wire format, server execution, database access, typed
/// response — so that if hydration or the server-function plumbing is broken,
/// the home page says so instead of failing silently.
#[server(name = GetServerStatus, prefix = "/api/sfn", endpoint = "status")]
pub async fn server_status() -> Result<ServerStatus, ServerFnError> {
    use authenc_identity::Db;

    let db = expect_context::<Db>();
    let database_ready = authenc_identity::ping(&db).await.is_ok();

    Ok(ServerStatus {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        database_ready,
    })
}

/// Authenticate and open a session.
///
/// On success the server sets an `HttpOnly` session cookie; nothing secret is
/// returned in the body, and there is no token for page script to hold.
///
/// The `request` argument carries the submitted credentials.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = LogIn, prefix = "/api/sfn", endpoint = "login", input = Json)]
pub async fn log_in(request: LoginRequest) -> Result<LoginResponse, ServerFnError> {
    use authenc_identity::{
        Db, PasswordHasher,
        login::{self, Attempt},
        session::Origin,
    };

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let hasher = expect_context::<PasswordHasher>();
    let policy = expect_context::<CookiePolicy>();
    let parts = expect_context::<http::request::Parts>();

    let user_agent = parts
        .headers
        .get(http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok());

    let authenticated = login::authenticate(
        &db,
        &hasher,
        Attempt {
            realm: &request.realm,
            identifier: &request.identifier,
            password: &request.password,
            origin: Origin {
                user_agent,
                ip_address: server_ctx::client_ip(&parts),
            },
        },
    )
    .await
    .map_err(server_ctx::to_server_fn_error)?;

    let roles = authenc_identity::user::role_names(&db, authenticated.user.id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    server_ctx::set_session_cookie(policy, &authenticated.session);

    Ok(LoginResponse {
        user: authenticated.user,
        roles,
    })
}

/// End the current session.
///
/// Always succeeds: logging out of a session that is already gone is the
/// outcome the caller wanted.
#[server(name = LogOut, prefix = "/api/sfn", endpoint = "logout")]
pub async fn log_out() -> Result<(), ServerFnError> {
    use authenc_identity::{Db, session};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let policy = expect_context::<CookiePolicy>();
    let parts = expect_context::<http::request::Parts>();

    if let Some(token) = server_ctx::session_token(policy, &parts) {
        session::revoke(&db, &token)
            .await
            .map_err(server_ctx::to_server_fn_error)?;
    }

    server_ctx::clear_session_cookie(policy);
    Ok(())
}

/// Who the current session belongs to, or `None` when nobody is signed in.
#[server(name = CurrentUser, prefix = "/api/sfn", endpoint = "me")]
pub async fn current_user() -> Result<Option<LoginResponse>, ServerFnError> {
    use authenc_identity::{Db, session, user};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let policy = expect_context::<CookiePolicy>();
    let parts = expect_context::<http::request::Parts>();

    let Some(token) = server_ctx::session_token(policy, &parts) else {
        return Ok(None);
    };
    let Some(session) = session::lookup(&db, &token)
        .await
        .map_err(server_ctx::to_server_fn_error)?
    else {
        return Ok(None);
    };

    let user = user::by_id(&db, session.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;
    let roles = user::role_names(&db, session.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(Some(LoginResponse { user, roles }))
}

/// Render a server-function failure as something a person can read.
///
/// One place to do this, so no page invents its own error string.
#[must_use]
pub fn describe(error: &ServerFnError) -> String {
    error.to_string()
}
