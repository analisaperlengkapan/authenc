//! Server-side helpers shared by the server functions in [`crate::api`] and by
//! the HTTP surface in `authenc-server`.
//!
//! This lives here rather than in `authenc-server` for a structural reason:
//! `server` depends on `web`, so anything both need has to sit at or below
//! `web`. Compiled only under `ssr`; none of it reaches the browser bundle.

use std::net::{IpAddr, SocketAddr};

use authenc_contract::{AppError, model::Actor};
use authenc_identity::{SecretToken, session::Issued};
use axum::http::{StatusCode, header::SET_COOKIE, request::Parts};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use leptos::prelude::{ServerFnError, use_context};
use leptos_axum::ResponseOptions;

/// How the session cookie is named and flagged.
///
/// The strictest form cannot simply be hardcoded: the `__Host-` prefix
/// requires `Secure`, and a browser will not store a `Secure` cookie over
/// plain HTTP except on localhost. Development therefore gets a plain name,
/// and production gets the locked-down form — which is safe because
/// `Config::validate` refuses to start the production profile without an
/// HTTPS public URL.
#[derive(Debug, Clone, Copy)]
pub struct CookiePolicy {
    /// Cookie name.
    pub name: &'static str,
    /// Whether to set the `Secure` attribute.
    pub secure: bool,
}

impl CookiePolicy {
    /// The development policy: works over plain HTTP on localhost.
    #[must_use]
    pub const fn development() -> Self {
        Self {
            name: "authenc_session",
            secure: false,
        }
    }

    /// The production policy.
    ///
    /// `__Host-` binds the cookie to exactly this origin — no `Domain`,
    /// `Path=/`, `Secure` — so a sibling subdomain cannot overwrite it.
    #[must_use]
    pub const fn production() -> Self {
        Self {
            name: "__Host-authenc_session",
            secure: true,
        }
    }

    /// Build the `Set-Cookie` value that establishes a session.
    #[must_use]
    pub fn issue(self, token: &SecretToken, max_age: time::Duration) -> Cookie<'static> {
        Cookie::build((self.name, token.expose().to_owned()))
            // Unreadable from JavaScript, so an injected script has nothing to
            // steal. The previous console kept a JWT in `localStorage`.
            .http_only(true)
            .secure(self.secure)
            // `Lax` still sends the cookie on top-level navigation, so a link
            // into the console works, but withholds it on cross-site POSTs.
            .same_site(SameSite::Lax)
            .path("/")
            .max_age(max_age)
            .build()
    }

    /// Build the `Set-Cookie` value that clears a session.
    #[must_use]
    pub fn revoke(self) -> Cookie<'static> {
        Cookie::build((self.name, ""))
            .http_only(true)
            .secure(self.secure)
            .same_site(SameSite::Lax)
            .path("/")
            .max_age(time::Duration::ZERO)
            .build()
    }

    /// Read the session token a cookie jar carries, if any.
    #[must_use]
    pub fn read(self, jar: &CookieJar) -> Option<SecretToken> {
        jar.get(self.name)
            .map(|cookie| SecretToken::from_client(cookie.value()))
    }
}

/// Absolute base URLs for the links sent by mail.
///
/// Provided by the server from `server.public_url`, so a server function never
/// has to guess its own origin — the previous code hardcoded
/// `http://localhost:8080/v1` as the OIDC issuer and served that in its
/// discovery document wherever it was deployed.
#[derive(Debug, Clone)]
pub struct PublicUrls {
    /// Where a password-reset link points.
    pub reset: String,
    /// Where an email-verification link points.
    pub verify: String,
}

/// The session token presented by a request, if any.
#[must_use]
pub fn session_token(policy: CookiePolicy, parts: &Parts) -> Option<SecretToken> {
    policy.read(&CookieJar::from_headers(&parts.headers))
}

/// Attach a session cookie to the response a server function is building.
pub fn set_session_cookie(policy: CookiePolicy, issued: &Issued) {
    let max_age = issued.session.expires_at - time::OffsetDateTime::now_utc();
    append_cookie(&policy.issue(&issued.token, max_age));
}

/// Attach a cookie that clears the session.
pub fn clear_session_cookie(policy: CookiePolicy) {
    append_cookie(&policy.revoke());
}

fn append_cookie(cookie: &Cookie<'static>) {
    let Some(response) = use_context::<ResponseOptions>() else {
        // Only possible if a server function is invoked outside a request,
        // which would be a wiring bug rather than a runtime condition.
        tracing::error!("no ResponseOptions in context; cookie not set");
        return;
    };
    if let Ok(value) = cookie.to_string().parse() {
        response.append_header(SET_COOKIE, value);
    }
}

/// The client's address, as far as it can be trusted.
///
/// Taken from the transport connection only. `X-Forwarded-For` is deliberately
/// **not** consulted: it is caller-supplied, and the previous code trusted it
/// unconditionally to drive its risk scoring, which meant any client could
/// choose the address it was judged by. Reinstating it requires an explicit
/// trusted-proxy configuration.
#[must_use]
pub fn client_ip(parts: &Parts) -> Option<IpAddr> {
    parts
        .extensions
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip())
}

/// Resolve the live session behind the current server-function call.
///
/// Almost every caller wants [`require_actor`] instead. This exists for the
/// one thing an `Actor` deliberately does not carry: the session-bound CSRF
/// token, which the consent form has to embed so its `POST` to the protocol
/// endpoint can be told apart from one another origin submitted.
///
/// # Errors
///
/// Returns [`AppError::Unauthenticated`] when there is no live session, or an
/// internal error if the lookup fails.
pub async fn require_session(
    db: &authenc_identity::Db,
) -> Result<authenc_identity::session::Session, AppError> {
    use authenc_identity::session;

    let policy = leptos::prelude::expect_context::<CookiePolicy>();
    let parts = leptos::prelude::expect_context::<Parts>();

    let token = session_token(policy, &parts).ok_or(AppError::Unauthenticated)?;
    session::lookup(db, &token)
        .await?
        .ok_or(AppError::Unauthenticated)
}

/// Resolve the [`Actor`] behind the current server-function call.
///
/// Every administrative server function starts here. The actor's permissions
/// are read from the database on each call, so a role revoked a second ago is
/// already gone — nothing is cached in a token.
///
/// # Errors
///
/// Returns [`AppError::Unauthenticated`] when there is no live session, or an
/// internal error if a lookup fails.
pub async fn require_actor(db: &authenc_identity::Db) -> Result<Actor, AppError> {
    use authenc_identity::user;

    let session = require_session(db).await?;
    let user = user::by_id(db, session.user_id).await?;
    if !user.enabled {
        return Err(AppError::Unauthenticated);
    }

    Ok(Actor {
        roles: user::role_names(db, session.user_id).await?,
        permissions: user::permissions(db, session.user_id).await?,
        user_id: user.id,
        realm_id: user.realm_id,
        username: user.username,
    })
}

/// Convert a domain error into the failure a server function returns.
///
/// Two things happen here, and both matter:
///
/// * internal detail is dropped, because a server function's error travels to
///   the browser just as an HTTP body does;
/// * the HTTP status is set from the error, because Leptos otherwise reports
///   every server-function failure as 500 — which would make a wrong password
///   indistinguishable from a database outage to anything reading status
///   codes, including our own tests.
#[must_use]
pub fn to_server_fn_error(error: AppError) -> ServerFnError {
    if error.is_server_fault() {
        tracing::error!(?error, "server function failed");
    }

    if let Some(response) = use_context::<ResponseOptions>()
        && let Ok(status) = StatusCode::from_u16(error.status())
    {
        response.set_status(status);
    }

    ServerFnError::ServerError(error.public_detail())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_uses_a_plain_name_so_it_works_over_http() {
        let policy = CookiePolicy::development();
        assert_eq!(policy.name, "authenc_session");
        assert!(!policy.secure);
    }

    #[test]
    fn production_uses_the_host_prefix_and_secure() {
        let policy = CookiePolicy::production();
        assert_eq!(policy.name, "__Host-authenc_session");
        assert!(policy.secure, "__Host- is invalid without Secure");
    }

    #[test]
    fn the_session_cookie_is_never_readable_from_javascript() {
        for policy in [CookiePolicy::development(), CookiePolicy::production()] {
            let cookie = policy.issue(
                &SecretToken::from_client("some-token"),
                time::Duration::hours(1),
            );
            assert_eq!(cookie.http_only(), Some(true));
            assert_eq!(cookie.same_site(), Some(SameSite::Lax));
            assert_eq!(cookie.path(), Some("/"));
        }
    }

    #[test]
    fn revoking_expires_the_cookie_immediately() {
        let cookie = CookiePolicy::development().revoke();
        assert_eq!(cookie.value(), "");
        assert_eq!(cookie.max_age(), Some(time::Duration::ZERO));
    }

    #[test]
    fn a_token_round_trips_through_the_jar() {
        let policy = CookiePolicy::development();
        let jar = CookieJar::new().add(policy.issue(
            &SecretToken::from_client("abc123"),
            time::Duration::hours(1),
        ));
        assert_eq!(policy.read(&jar).unwrap().expose(), "abc123");
    }

    #[test]
    fn no_cookie_means_no_token() {
        assert!(
            CookiePolicy::development()
                .read(&CookieJar::new())
                .is_none()
        );
    }

    #[test]
    fn internal_error_detail_does_not_reach_the_browser() {
        let error = to_server_fn_error(AppError::internal(
            "connecting to postgres://user:hunter2@db:5432",
        ));
        assert!(!error.to_string().contains("hunter2"), "leaked: {error}");
    }

    #[test]
    fn validation_detail_does_reach_the_browser() {
        let error = to_server_fn_error(AppError::field("email", "must contain @"));
        assert!(error.to_string().contains("must contain @"));
    }
}
