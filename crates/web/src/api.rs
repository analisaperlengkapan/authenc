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
    let permissions = authenc_identity::user::permissions(&db, authenticated.user.id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    server_ctx::set_session_cookie(policy, &authenticated.session);

    Ok(LoginResponse {
        user: authenticated.user,
        roles,
        permissions,
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
    let permissions = user::permissions(&db, session.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(Some(LoginResponse {
        user,
        roles,
        permissions,
    }))
}

/// Render a server-function failure as something a person can read.
///
/// One place to do this, so no page invents its own error string.
#[must_use]
pub fn describe(error: &ServerFnError) -> String {
    error.to_string()
}

/// Begin a password reset.
///
/// Always succeeds, whether or not the address is registered. Reporting
/// otherwise would turn this endpoint into a way to enumerate accounts.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = RequestPasswordReset, prefix = "/api/sfn", endpoint = "password-reset", input = Json)]
pub async fn request_password_reset(realm: String, email: String) -> Result<(), ServerFnError> {
    use std::sync::Arc;

    use authenc_identity::{Db, mail::Mailer, recovery};

    use crate::{server_ctx, server_ctx::PublicUrls};

    let db = expect_context::<Db>();
    let mailer = expect_context::<Arc<dyn Mailer>>();
    let urls = expect_context::<PublicUrls>();

    // An unknown realm is also silent: the caller learns nothing either way.
    let Ok(realm) = authenc_identity::realm::by_name(&db, &realm).await else {
        return Ok(());
    };

    recovery::request_password_reset(&db, mailer.as_ref(), realm.id, &email, &urls.reset)
        .await
        .map_err(server_ctx::to_server_fn_error)
}

/// Finish a password reset using the token from the emailed link.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = CompletePasswordReset, prefix = "/api/sfn", endpoint = "password-reset-complete", input = Json)]
pub async fn complete_password_reset(
    token: String,
    new_password: String,
) -> Result<(), ServerFnError> {
    use authenc_identity::{Db, PasswordHasher, SecretToken, recovery};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let hasher = expect_context::<PasswordHasher>();

    recovery::complete_password_reset(
        &db,
        &hasher,
        &SecretToken::from_client(token),
        &new_password,
    )
    .await
    .map(|_| ())
    .map_err(server_ctx::to_server_fn_error)
}

/// Confirm an email address using the token from the emailed link.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = VerifyEmail, prefix = "/api/sfn", endpoint = "verify-email", input = Json)]
pub async fn verify_email(token: String) -> Result<(), ServerFnError> {
    use authenc_identity::{Db, SecretToken, recovery};

    use crate::server_ctx;

    let db = expect_context::<Db>();

    recovery::complete_email_verification(&db, &SecretToken::from_client(token))
        .await
        .map(|_| ())
        .map_err(server_ctx::to_server_fn_error)
}

/// A page of users, with the total so the console can page through it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPage {
    /// The users on this page.
    pub items: Vec<authenc_contract::model::User>,
    /// How many exist in total.
    pub total: i64,
}

/// List users in the caller's realm.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = ListUsers, prefix = "/api/sfn", endpoint = "users", input = Json)]
pub async fn list_users(limit: i64, offset: i64) -> Result<UserPage, ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    let items = admin::list_users(&db, &actor, actor.realm_id, limit, offset)
        .await
        .map_err(server_ctx::to_server_fn_error)?;
    let total = admin::count_users(&db, &actor, actor.realm_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    Ok(UserPage { items, total })
}

/// Create a user in the caller's realm.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = CreateUser, prefix = "/api/sfn", endpoint = "users-create", input = Json)]
pub async fn create_user(
    username: String,
    email: String,
    password: String,
) -> Result<authenc_contract::model::User, ServerFnError> {
    use authenc_identity::{Db, PasswordHasher, admin, user::NewUser};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let hasher = expect_context::<PasswordHasher>();
    let actor = server_ctx::require_actor(&db)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    admin::create_user(
        &db,
        &actor,
        &hasher,
        NewUser {
            realm_id: actor.realm_id,
            username: &username,
            email: &email,
            password: &password,
            first_name: None,
            last_name: None,
        },
    )
    .await
    .map_err(server_ctx::to_server_fn_error)
}

/// Enable or disable a user.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = SetUserEnabled, prefix = "/api/sfn", endpoint = "users-enabled", input = Json)]
pub async fn set_user_enabled(
    user_id: authenc_contract::UserId,
    enabled: bool,
) -> Result<(), ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    admin::set_user_enabled(&db, &actor, user_id, enabled)
        .await
        .map(|_| ())
        .map_err(server_ctx::to_server_fn_error)
}

/// Delete a user.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = DeleteUser, prefix = "/api/sfn", endpoint = "users-delete", input = Json)]
pub async fn delete_user(user_id: authenc_contract::UserId) -> Result<(), ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    admin::delete_user(&db, &actor, user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)
}

/// List roles in the caller's realm.
#[server(name = ListRoles, prefix = "/api/sfn", endpoint = "roles", input = Json)]
pub async fn list_roles() -> Result<Vec<authenc_contract::model::Role>, ServerFnError> {
    use authenc_identity::{Db, admin};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let actor = server_ctx::require_actor(&db)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    admin::list_roles(&db, &actor, actor.realm_id)
        .await
        .map_err(server_ctx::to_server_fn_error)
}

// ---------------------------------------------------------------------------
// OAuth consent
// ---------------------------------------------------------------------------

/// One scope, as the consent screen shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeInfo {
    /// The scope's protocol name, e.g. `email`.
    pub name: String,
    /// What granting it means, in a sentence.
    pub description: String,
}

/// What the consent screen needs in order to ask an honest question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentPrompt {
    /// The client's registered display name — not a name it supplied in the
    /// request, which is the difference between consent and a phishing form.
    pub client_name: String,
    /// The scopes that will actually be granted, already narrowed to what the
    /// client is registered for.
    pub scopes: Vec<ScopeInfo>,
    /// The signed-in user, so they can see whose account they are granting.
    pub username: String,
    /// The token the approval form must post back.
    pub csrf_token: String,
}

/// Describe a pending authorization request.
///
/// Everything shown is resolved server-side from the client's registration.
/// The query string is only used to *identify* the request; nothing in it is
/// echoed to the user, because a page that displays attacker-supplied text
/// under the operator's domain is a phishing page with extra steps.
///
/// The arguments are the realm, the client asking, and the scopes it wants.
#[allow(
    missing_docs,
    reason = "the #[server] macro generates the argument struct"
)]
#[server(name = DescribeConsent, prefix = "/api/sfn", endpoint = "consent")]
pub async fn consent_prompt(
    realm: String,
    client_id: String,
    scope: String,
) -> Result<ConsentPrompt, ServerFnError> {
    use authenc_contract::AppError;
    use authenc_identity::{Db, user};
    use authenc_oauth::{client, scope as scopes};

    use crate::server_ctx;

    let db = expect_context::<Db>();
    let session = server_ctx::require_session(&db)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    let realm = authenc_identity::realm::by_name(&db, &realm)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    let user = user::by_id(&db, session.user_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    // A session in one realm must not be able to approve anything in another,
    // and a disabled account must not be able to approve at all.
    if !user.enabled || user.realm_id != realm.id {
        return Err(server_ctx::to_server_fn_error(AppError::Unauthenticated));
    }

    let client = client::by_client_id(&db, realm.id, &client_id)
        .await
        .map_err(server_ctx::to_server_fn_error)?;

    let granted = scopes::resolve(&scopes::parse(&scope), &client.scopes)
        .map_err(|error| server_ctx::to_server_fn_error(AppError::validation(error.description)))?;

    Ok(ConsentPrompt {
        client_name: client.name,
        scopes: granted
            .iter()
            .map(|name| ScopeInfo {
                name: name.clone(),
                description: scopes::describe(name).to_owned(),
            })
            .collect(),
        username: user.username,
        csrf_token: session.csrf_token(),
    })
}
