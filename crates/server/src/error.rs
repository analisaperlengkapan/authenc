//! Turning an [`AppError`] into an HTTP response.
//!
//! One conversion, in one place, so no handler can invent its own error shape.

use authenc_contract::AppError;
use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

/// Newtype so we can implement [`IntoResponse`] for the shared error type.
#[derive(Debug)]
pub struct ApiError(pub AppError);

impl From<AppError> for ApiError {
    fn from(error: AppError) -> Self {
        Self(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let error = self.0;

        // Log the full detail here and only here; what goes on the wire is the
        // redacted problem document. This is the boundary where an internal
        // message containing a connection string stops.
        if error.is_server_fault() {
            tracing::error!(error = ?error, "request failed");
        } else {
            tracing::debug!(error = %error, "request rejected");
        }

        let problem = error.to_problem();
        let status =
            StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        (
            status,
            [(header::CONTENT_TYPE, "application/problem+json")],
            Json(problem),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn internal_errors_do_not_leak_their_detail() {
        let error = ApiError(AppError::internal(
            "connecting to postgres://user:hunter2@db:5432/authenc",
        ));
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(!body.contains("hunter2"), "leaked: {body}");
        assert!(body.contains("An internal error occurred."));
    }

    #[tokio::test]
    async fn validation_errors_keep_their_detail_and_field() {
        let error = ApiError(AppError::field("email", "must contain @"));
        let response = error.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json"),
        );

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("must contain @"), "got: {body}");
        assert!(body.contains("\"field\":\"email\""), "got: {body}");
    }

    #[tokio::test]
    async fn status_codes_follow_the_single_mapping() {
        for (error, expected) in [
            (AppError::Unauthenticated, StatusCode::UNAUTHORIZED),
            (AppError::Forbidden, StatusCode::FORBIDDEN),
            (AppError::NotFound("user"), StatusCode::NOT_FOUND),
            (AppError::conflict("taken"), StatusCode::CONFLICT),
            (AppError::RateLimited, StatusCode::TOO_MANY_REQUESTS),
        ] {
            let response = ApiError(error).into_response();
            assert_eq!(response.status(), expected);
        }
    }
}
