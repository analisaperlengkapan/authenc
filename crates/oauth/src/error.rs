//! Protocol errors.
//!
//! OAuth does not use RFC 9457 problem documents. It has its own body —
//! `{"error": "...", "error_description": "..."}` — and a client library will
//! branch on that `error` code, so returning the wrong one is a protocol bug
//! even when the status is right. That is why this is a separate type from
//! [`AppError`] rather than a second status table bolted onto it.
//!
//! Two rules encoded here that are easy to get wrong:
//!
//! * `invalid_client` is **401**, not 400 (RFC 6749 §5.2), and it is the only
//!   token-endpoint error that is.
//! * an error must **not** be redirected back to the client when the client or
//!   the redirect URI is itself what failed validation (RFC 6749 §4.1.2.1).
//!   Redirecting there turns the authorization endpoint into an open redirect,
//!   which is exactly what the previous implementation did — it echoed back
//!   whatever `redirect_uri` the caller supplied, unvalidated.

use authenc_contract::AppError;
use serde::{Deserialize, Serialize};

/// The `error` codes this server emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthErrorCode {
    /// Malformed request: a missing, repeated, or unparseable parameter.
    InvalidRequest,
    /// Client authentication failed, or the client is unknown.
    InvalidClient,
    /// The grant — code, refresh token, or PKCE verifier — did not check out.
    InvalidGrant,
    /// The client is known but is not allowed to use this grant or flow.
    UnauthorizedClient,
    /// The `grant_type` is not one this server implements.
    UnsupportedGrantType,
    /// The `response_type` is not one this server implements.
    UnsupportedResponseType,
    /// The requested scope is unknown or wider than the client may ask for.
    InvalidScope,
    /// The resource owner refused.
    AccessDenied,
    /// Something on our side failed.
    ServerError,
    /// A dependency is down; retrying later may work.
    TemporarilyUnavailable,
    /// The presented access token is expired, revoked, or malformed.
    InvalidToken,
    /// The redirect URI is not on the client's allow-list. Never redirected.
    InvalidRedirectUri,
    /// Registration metadata was rejected (RFC 7591 §3.2.2).
    InvalidClientMetadata,
    /// Interactive sign-in is needed but `prompt=none` forbade it.
    LoginRequired,
    /// Consent is needed but `prompt=none` forbade asking for it.
    ConsentRequired,
}

impl OAuthErrorCode {
    /// The wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InvalidToken => "invalid_token",
            Self::InvalidRedirectUri => "invalid_redirect_uri",
            Self::InvalidClientMetadata => "invalid_client_metadata",
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
        }
    }

    /// The HTTP status this code is returned with.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::InvalidClient | Self::InvalidToken => 401,
            Self::AccessDenied => 403,
            Self::ServerError => 500,
            Self::TemporarilyUnavailable => 503,
            _ => 400,
        }
    }

    /// Whether this failure may be reported by redirecting to the client.
    ///
    /// It may not when the client identity or the redirect target is what
    /// failed — there is then no address we have any reason to trust.
    #[must_use]
    pub const fn is_redirectable(self) -> bool {
        !matches!(
            self,
            Self::InvalidClient | Self::InvalidRedirectUri | Self::InvalidClientMetadata
        )
    }
}

/// A protocol error, ready to be serialised into a response body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthError {
    /// The machine-readable code a client branches on.
    #[serde(rename = "error")]
    pub code: OAuthErrorCode,
    /// Human-readable detail. Safe to show: it never carries internal state.
    #[serde(rename = "error_description")]
    pub description: String,
}

impl OAuthError {
    /// Build an error with an explicit code.
    pub fn new(code: OAuthErrorCode, description: impl Into<String>) -> Self {
        Self {
            code,
            description: description.into(),
        }
    }

    /// The status this error is returned with.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.code.status()
    }

    /// Whether it may be reported by redirecting to the client.
    #[must_use]
    pub const fn is_redirectable(&self) -> bool {
        self.code.is_redirectable()
    }

    /// A malformed request.
    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidRequest, description)
    }

    /// Unknown client, or client authentication failed.
    pub fn invalid_client(description: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidClient, description)
    }

    /// A code, refresh token, or verifier that did not check out.
    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidGrant, description)
    }

    /// A scope that is unknown or wider than the client may request.
    pub fn invalid_scope(description: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidScope, description)
    }

    /// A redirect URI that is not on the client's allow-list.
    pub fn invalid_redirect_uri(description: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidRedirectUri, description)
    }

    /// Registration metadata this server will not accept.
    pub fn invalid_client_metadata(description: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidClientMetadata, description)
    }
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.description)
    }
}

impl std::error::Error for OAuthError {}

/// Translate an internal error into a protocol one.
///
/// The mapping deliberately collapses everything unexpected to `server_error`
/// with a fixed description. An `AppError::Internal` carries context that
/// routinely includes SQL and connection strings, and a token endpoint answers
/// unauthenticated callers.
impl From<AppError> for OAuthError {
    fn from(error: AppError) -> Self {
        match error.status() {
            400 => Self::invalid_request(error.public_detail()),
            401 => Self::invalid_client("client authentication failed"),
            403 => Self::new(OAuthErrorCode::AccessDenied, error.public_detail()),
            404 => Self::invalid_grant("no such grant"),
            503 => Self::new(
                OAuthErrorCode::TemporarilyUnavailable,
                "a dependency is unavailable; try again",
            ),
            _ => {
                tracing::error!(?error, "oauth request failed");
                Self::new(OAuthErrorCode::ServerError, "an internal error occurred")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_client_is_401_and_everything_else_at_the_token_endpoint_is_400() {
        // RFC 6749 §5.2 singles this one out; getting it wrong makes a client
        // library retry a bad secret forever instead of failing loudly.
        assert_eq!(OAuthErrorCode::InvalidClient.status(), 401);
        assert_eq!(OAuthErrorCode::InvalidGrant.status(), 400);
        assert_eq!(OAuthErrorCode::InvalidRequest.status(), 400);
        assert_eq!(OAuthErrorCode::UnsupportedGrantType.status(), 400);
    }

    #[test]
    fn a_bad_client_or_redirect_uri_is_never_redirected_back() {
        // Redirecting these is how an authorization endpoint becomes an open
        // redirect.
        assert!(!OAuthErrorCode::InvalidClient.is_redirectable());
        assert!(!OAuthErrorCode::InvalidRedirectUri.is_redirectable());

        // Everything else is reported to the client, per RFC 6749 §4.1.2.1.
        assert!(OAuthErrorCode::AccessDenied.is_redirectable());
        assert!(OAuthErrorCode::InvalidScope.is_redirectable());
        assert!(OAuthErrorCode::UnsupportedResponseType.is_redirectable());
    }

    #[test]
    fn the_body_uses_the_field_names_the_rfc_specifies() {
        let json = serde_json::to_value(OAuthError::invalid_grant("code expired")).unwrap();
        assert_eq!(json["error"], "invalid_grant");
        assert_eq!(json["error_description"], "code expired");
    }

    #[test]
    fn internal_detail_never_reaches_the_client() {
        let error = OAuthError::from(AppError::internal(
            "connecting to postgres://user:hunter2@db:5432/authenc",
        ));
        assert_eq!(error.code, OAuthErrorCode::ServerError);
        assert!(!error.description.contains("hunter2"), "{error}");
    }

    #[test]
    fn a_validation_failure_keeps_its_detail() {
        let error = OAuthError::from(AppError::validation("redirect_uri must be absolute"));
        assert_eq!(error.code, OAuthErrorCode::InvalidRequest);
        assert!(error.description.contains("absolute"));
    }
}
