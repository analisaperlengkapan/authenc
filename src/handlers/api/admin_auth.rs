use authenc_crypto::utils::crypto::jwt::{self, Claims};
use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::CookieJar;

/// Authentication extractor for Admin Console routes.
///
/// Checks for the presence of a valid `authenc_admin_token` cookie.
/// If valid, provides access to the JWT claims and the raw token.
/// If invalid or missing, redirects the user to `/admin/login`.
pub struct AdminAuth {
    /// The decoded JWT claims from the token
    pub claims: Claims,
    /// The raw JWT token string (useful for API calls from frontend)
    pub token: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for AdminAuth
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|_| Redirect::to("/admin/login").into_response())?;

        if let Some(cookie) = jar.get("authenc_admin_token") {
            let token = cookie.value();
            if let Ok(claims) = jwt::verify_jwt(token) {
                return Ok(AdminAuth {
                    claims,
                    token: token.to_string(),
                });
            }
        }

        Err(Redirect::to("/admin/login").into_response())
    }
}
