//! Session cookies, request authentication, and CSRF.

use authenc_contract::{AppError, Result, model::Actor};
use authenc_identity::{
    Db,
    session::{self, Session},
    user,
};
use authenc_web::server_ctx::CookiePolicy;
use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, Method, header, request::Parts},
};
use axum_extra::extract::cookie::CookieJar;

use crate::{config::Config, error::ApiError};

/// Header a client uses to present its CSRF token.
pub const CSRF_HEADER: &str = "x-csrf-token";

/// Derive the cookie policy from configuration.
#[must_use]
pub fn cookie_policy(config: &Config) -> CookiePolicy {
    if config.profile.is_production() {
        CookiePolicy::production()
    } else {
        CookiePolicy::development()
    }
}

/// Resolve the session a request carries, if it carries a live one.
///
/// # Errors
///
/// Returns an internal error if the lookup fails. An absent or expired session
/// is `Ok(None)`, not an error — that is simply an anonymous request.
pub async fn session_for(
    db: &Db,
    policy: CookiePolicy,
    jar: &CookieJar,
) -> Result<Option<Session>> {
    let Some(token) = policy.read(jar) else {
        return Ok(None);
    };
    session::lookup(db, &token).await
}

/// Build the [`Actor`] for a session.
///
/// Roles are resolved here, at the point of use, from the database. They are
/// deliberately not carried in a token: the previous system minted tokens with
/// `roles: None` and then checked `roles.contains("admin")`, so no token it
/// issued could ever satisfy an admin check.
///
/// # Errors
///
/// Returns [`AppError::NotFound`] if the session points at a user that no
/// longer exists, or an internal error if a query fails.
pub async fn actor_for(db: &Db, session: &Session) -> Result<Actor> {
    let user = user::by_id(db, session.user_id).await?;
    let roles = user::role_names(db, session.user_id).await?;

    Ok(Actor {
        user_id: user.id,
        realm_id: user.realm_id,
        username: user.username,
        roles,
    })
}

/// An authenticated caller, extracted from the session cookie.
///
/// Used by the HTTP surface. Server functions get the same thing through
/// [`crate::http`]'s context rather than through an extractor.
#[derive(Debug, Clone)]
pub struct CurrentUser(pub Actor);

impl<S> FromRequestParts<S> for CurrentUser
where
    S: Send + Sync,
    Db: axum::extract::FromRef<S>,
    std::sync::Arc<Config>: axum::extract::FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        use axum::extract::FromRef;

        let db = Db::from_ref(state);
        let config = std::sync::Arc::<Config>::from_ref(state);
        let policy = cookie_policy(&config);
        let jar = CookieJar::from_headers(&parts.headers);

        let session = session_for(&db, policy, &jar)
            .await
            .map_err(ApiError)?
            .ok_or(ApiError(AppError::Unauthenticated))?;

        // A state-changing request must also carry a matching CSRF token.
        verify_csrf(&parts.method, &parts.headers, &session).map_err(ApiError)?;

        let actor = actor_for(&db, &session).await.map_err(ApiError)?;
        Ok(Self(actor))
    }
}

/// Reject a state-changing request that does not present this session's CSRF
/// token.
///
/// Safe methods are exempt because they must not change anything in the first
/// place. The token is bound to the session, so one minted elsewhere does not
/// validate here — the previous implementation accepted any string of 32
/// characters or more, with no server-side state at all.
///
/// # Errors
///
/// Returns [`AppError::Forbidden`] if the token is absent or does not match.
pub fn verify_csrf(method: &Method, headers: &HeaderMap, session: &Session) -> Result<()> {
    if matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE
    ) {
        return Ok(());
    }

    let presented = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(AppError::Forbidden)?;

    if session.csrf_token_matches(presented) {
        Ok(())
    } else {
        Err(AppError::Forbidden)
    }
}

/// Whether a state-changing request came from our own origin.
///
/// Defence in depth alongside the CSRF token and the `SameSite=Lax` cookie:
/// `Sec-Fetch-Site` is set by the browser and cannot be forged by page script.
/// Requests without either header — non-browser clients — are allowed through
/// to the token check, which is the real gate.
#[must_use]
pub fn is_same_origin(headers: &HeaderMap, expected_origin: &str) -> bool {
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        return matches!(site, "same-origin" | "none");
    }
    match headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        Some(origin) => origin == expected_origin,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Profile;

    // Cookie-flag behaviour is tested where the policy lives, in
    // `authenc_web::server_ctx`. What belongs here is the mapping from
    // configuration to policy, and the origin check.

    #[test]
    fn only_production_gets_the_locked_down_cookie() {
        for profile in [Profile::Development, Profile::Test] {
            let config = Config {
                profile,
                ..Config::default()
            };
            assert_eq!(cookie_policy(&config).name, "authenc_session");
            assert!(!cookie_policy(&config).secure);
        }

        let config = Config {
            profile: Profile::Production,
            ..Config::default()
        };
        assert_eq!(cookie_policy(&config).name, "__Host-authenc_session");
        assert!(cookie_policy(&config).secure);
    }

    #[test]
    fn same_origin_detection_trusts_sec_fetch_site_over_origin() {
        let mut headers = HeaderMap::new();
        headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
        headers.insert(header::ORIGIN, "https://id.example.com".parse().unwrap());

        assert!(
            !is_same_origin(&headers, "https://id.example.com"),
            "Sec-Fetch-Site is set by the browser and page script cannot forge it",
        );
    }

    #[test]
    fn same_origin_falls_back_to_the_origin_header() {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://evil.example".parse().unwrap());
        assert!(!is_same_origin(&headers, "https://id.example.com"));

        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "https://id.example.com".parse().unwrap());
        assert!(is_same_origin(&headers, "https://id.example.com"));
    }

    #[test]
    fn a_request_with_neither_header_is_left_to_the_token_check() {
        assert!(is_same_origin(&HeaderMap::new(), "https://id.example.com"));
    }
}
