//! The two HTTP requests a social sign-in takes.
//!
//! `GET .../start` sends the browser to the provider. `GET .../callback`
//! receives it back, redeems the code, and either opens a session or hands the
//! visitor to the second-factor page.
//!
//! # Why `state` is in a cookie as well as in the URL
//!
//! The server-side row alone does not stop login CSRF. An attacker can start a
//! sign-in with *their* upstream account, obtain a perfectly valid unspent
//! state, and hand the victim the resulting callback URL; the victim's browser
//! completes it and they are now working inside the attacker's account, where
//! anything they save belongs to somebody else. Binding the state to the
//! browser that started the sign-in is what breaks that, so the callback
//! demands the cookie and the query parameter agree.
//!
//! # Why every failure looks the same
//!
//! A refusal redirects to `/login?error=federation`, whatever went wrong. The
//! reason is in the audit log. A callback that reported "no such provider"
//! against one that said "that account is disabled" would answer questions
//! nobody has yet asked it.

use authenc_identity::{
    federation::{self, Provider},
    login::Outcome,
    session::Origin,
};
use authenc_oauth::social::{self, HttpTransport};
use axum::{
    Router,
    extract::{Path, Query, State},
    http::request::Parts,
    response::{IntoResponse, Redirect, Response},
    routing::get,
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::{auth::cookie_policy, state::AppState};

/// Where a refused sign-in sends the browser.
///
/// One destination for every failure, deliberately: see the module note.
const REFUSED: &str = "/login?error=federation";

/// The routes.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/realms/{realm}/federation/{alias}/start", get(start))
        .route("/realms/{realm}/federation/{alias}/callback", get(callback))
}

/// The absolute callback URL for a provider.
///
/// Built from `server.public_url` and never from a request header. A provider
/// compares this against what it has registered, and a `Host` an attacker
/// chose would either fail that comparison or, worse, pass it at a provider
/// that matches loosely.
fn callback_uri(origin: &str, realm: &str, alias: &str) -> String {
    format!("{origin}/realms/{realm}/federation/{alias}/callback")
}

/// Query parameters accepted when starting a sign-in.
#[derive(Debug, Deserialize)]
pub struct StartQuery {
    /// Where to send the browser afterwards. A path on this site; anything
    /// else is refused by the column's own constraint.
    pub return_to: Option<String>,
}

/// Begin a social sign-in.
async fn start(
    State(state): State<AppState>,
    Path((realm_name, alias)): Path<(String, String)>,
    Query(query): Query<StartQuery>,
    jar: CookieJar,
) -> Response {
    let policy = cookie_policy(&state.config);

    let Some(provider) = enabled_provider(&state, &realm_name, &alias).await else {
        return Redirect::to(REFUSED).into_response();
    };

    let redirect_uri = callback_uri(state.config.origin(), &realm_name, &alias);

    match social::begin(
        &state.db,
        &provider,
        &redirect_uri,
        query.return_to.as_deref(),
    )
    .await
    {
        Ok(started) => {
            let cookie = policy
                .federation()
                .issue(&started.state, social::STATE_LIFETIME);
            (jar.add(cookie), Redirect::to(&started.authorization_url)).into_response()
        }
        Err(error) => {
            // A rejected `return_to` is the interesting case, and it is a
            // visitor error rather than ours — but it still gets the one
            // generic destination, because the alternative is an endpoint that
            // tells a prober which paths this site considers its own.
            tracing::warn!(%alias, %error, "a social sign-in could not be started");
            Redirect::to(REFUSED).into_response()
        }
    }
}

/// Query parameters a provider sends back.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    /// The authorization code, when the visitor approved.
    pub code: Option<String>,
    /// The state this sign-in was started with.
    pub state: Option<String>,
    /// The provider's own error, when the visitor did not approve.
    pub error: Option<String>,
}

/// Finish a social sign-in.
#[allow(
    clippy::too_many_lines,
    reason = "one linear flow; splitting it would hide the order the checks run in"
)]
async fn callback(
    State(state): State<AppState>,
    Path((realm_name, alias)): Path<(String, String)>,
    Query(query): Query<CallbackQuery>,
    parts: Parts,
    jar: CookieJar,
) -> Response {
    let policy = cookie_policy(&state.config);
    let origin = request_origin(&parts);

    // Read the binding cookie *before* the revocation is added: a `CookieJar`
    // is read-your-writes, so revoking first makes every later read see the
    // emptied value and no callback can ever succeed. That is what the first
    // version of this function did, and every test still passed, because
    // "refuses everything" and "refuses the right things" look identical from
    // the outside.
    let from_cookie = policy.federation().read(&jar);

    // Whatever happens next, this sign-in is over: the cookie goes.
    let jar = jar.add(policy.federation().revoke());

    let refuse = |jar: CookieJar| (jar, Redirect::to(REFUSED)).into_response();

    // The visitor declined at the provider, or the provider refused. Not an
    // error worth a stack trace; they simply are not signing in.
    if let Some(error) = &query.error {
        tracing::info!(%alias, %error, "a social sign-in was declined at the provider");
        return refuse(jar);
    }

    let (Some(code), Some(presented)) = (&query.code, &query.state) else {
        return refuse(jar);
    };

    // The binding that defeats login CSRF. Compared before anything is
    // redeemed, so an unbound callback costs nothing but a cookie read.
    let Some(from_cookie) = from_cookie else {
        tracing::warn!(%alias, "a social callback arrived with no state cookie");
        return refuse(jar);
    };
    if from_cookie.expose() != presented {
        tracing::warn!(%alias, "a social callback's state did not match its cookie");
        return refuse(jar);
    }

    let Ok(pending) = social::claim_state(&state.db, &from_cookie).await else {
        return refuse(jar);
    };

    let Some(provider) = enabled_provider(&state, &realm_name, &alias).await else {
        return refuse(jar);
    };

    // The state was issued for a provider; the path names one. A mismatch
    // means the callback was moved between providers, which nothing legitimate
    // does.
    if pending.provider_id != provider.id {
        tracing::warn!(%alias, "a social callback used another provider's state");
        return refuse(jar);
    }

    let Ok(secret) = federation::client_secret(&state.db, &state.master_key, provider.id).await
    else {
        return refuse(jar);
    };

    let Ok(transport) = HttpTransport::new() else {
        return refuse(jar);
    };

    let claims = match social::complete(&transport, &provider, &secret, &pending, code).await {
        Ok(claims) => claims,
        Err(error) => {
            tracing::warn!(%alias, %error, "a social token exchange failed");
            return refuse(jar);
        }
    };

    let signed_in = match federation::sign_in(&state.db, &provider, &claims, origin).await {
        Ok(signed_in) => signed_in,
        Err(_) => return refuse(jar),
    };

    let destination = pending.return_to.as_deref().unwrap_or("/");

    match signed_in.outcome {
        Outcome::Complete(authenticated) => {
            let max_age =
                authenticated.session.session.expires_at - time::OffsetDateTime::now_utc();
            let cookie = policy.issue(&authenticated.session.token, max_age);
            (jar.add(cookie), Redirect::to(destination)).into_response()
        }
        // A second factor is enrolled, so nobody is signed in yet. The
        // challenge cookie takes the visitor to the same page a password login
        // would have reached.
        Outcome::SecondFactorRequired(challenged) => {
            let max_age = challenged.issued.pending.expires_at - time::OffsetDateTime::now_utc();
            let cookie = policy.challenge().issue(&challenged.issued.token, max_age);
            (jar.add(cookie), Redirect::to("/login")).into_response()
        }
    }
}

/// Resolve a realm and alias to a provider that is actually offered.
///
/// `None` covers "no such realm", "no such provider", and "that provider is
/// switched off" — one answer, because distinguishing them enumerates the
/// configuration for anybody who asks.
async fn enabled_provider(state: &AppState, realm_name: &str, alias: &str) -> Option<Provider> {
    let realm = authenc_identity::realm::by_name(&state.db, realm_name)
        .await
        .ok()?;
    if !realm.enabled {
        return None;
    }

    let provider = federation::by_alias(&state.db, realm.id, alias)
        .await
        .ok()?;
    provider.enabled.then_some(provider)
}

/// Where this request came from, for the attempt record and the audit log.
///
/// The address comes from the transport connection only, through the same
/// helper every other path uses. `X-Forwarded-For` is deliberately not
/// consulted: the previous code trusted it unconditionally, letting a client
/// choose the address it was judged by.
fn request_origin(parts: &Parts) -> Origin<'_> {
    Origin {
        user_agent: parts
            .headers
            .get(http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok()),
        ip_address: authenc_web::server_ctx::client_ip(parts),
    }
}

/// Providers a realm offers, for the login page's buttons.
///
/// Public and unauthenticated, because the login page is. It carries the
/// alias, the display name, and nothing else — a client id is public but
/// there is no reason to publish one before it is needed.
#[derive(Debug, serde::Serialize)]
pub struct Offered {
    /// The alias, which is the path segment.
    pub alias: String,
    /// What the button says.
    pub display_name: String,
    /// Which provider it is, so a console can show the right mark.
    pub kind: String,
}

/// Every enabled provider in a realm.
///
/// # Errors
///
/// Returns an empty list rather than an error for an unknown realm: the login
/// page must not become a way to discover which realms exist.
pub async fn offered(state: &AppState, realm_name: &str) -> Vec<Offered> {
    let Ok(realm) = authenc_identity::realm::by_name(&state.db, realm_name).await else {
        return Vec::new();
    };

    federation::list(&state.db, realm.id)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|provider| provider.enabled)
        .map(|provider| Offered {
            alias: provider.alias,
            display_name: provider.display_name,
            kind: provider.kind.as_str().to_owned(),
        })
        .collect()
}
