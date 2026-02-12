use authenc_crypto::utils::crypto::jwt::{self, Claims};
use axum::http::request::Parts;
use axum::{
    extract::FromRequestParts,
    http::{StatusCode, header},
};

/// Authentication bearer token extractor for Axum
#[derive(Debug)]
pub struct AuthBearer(pub Claims);

impl<S> FromRequestParts<S> for AuthBearer
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(auth_header) = parts.headers.get(header::AUTHORIZATION)
            && let Ok(auth_str) = auth_header.to_str()
                && let Some(token) = auth_str.strip_prefix("Bearer ")
                    && let Ok(claims) = jwt::verify_jwt(token) {
                        return Ok(AuthBearer(claims));
                    }
        Err(StatusCode::UNAUTHORIZED)
    }
}
