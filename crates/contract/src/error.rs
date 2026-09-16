//! The single error type shared by every layer, and its one canonical mapping
//! to HTTP status codes.
//!
//! The previous codebase carried two hand-maintained copies of that mapping
//! which had already drifted apart (`InvalidCredentials` mapped to 400 in one
//! and 401 in the other). There is exactly one table here, and
//! [`AppError::status`] is the only way to get a status code.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Everything that can go wrong, from validation through to infrastructure.
///
/// Variants are grouped by how they must be *reported*: the `Internal` family
/// never reaches the client with its detail intact (see [`AppError::public_detail`]),
/// because those messages routinely contain connection strings, SQL, and
/// internal hostnames.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Input failed validation. Safe to show the caller.
    #[error("{0}")]
    Validation(String),

    /// A field-level validation failure, carrying the offending field.
    #[error("{field}: {message}")]
    Field {
        /// Name of the field that failed.
        field: String,
        /// Human-readable reason.
        message: String,
    },

    /// No credentials, or credentials that did not verify.
    #[error("authentication required")]
    Unauthenticated,

    /// Authenticated, but not allowed to perform this action.
    #[error("permission denied")]
    Forbidden,

    /// The addressed resource does not exist (or is not visible to the caller).
    #[error("{0} not found")]
    NotFound(&'static str),

    /// The request conflicts with current state, e.g. a duplicate username.
    #[error("{0}")]
    Conflict(String),

    /// The caller exceeded a rate limit.
    #[error("too many requests")]
    RateLimited,

    /// A dependency this endpoint cannot work without is down. Distinct from
    /// [`Self::Internal`]: it means "try again", not "something is broken",
    /// and it is what a readiness probe must return so an orchestrator takes
    /// the instance out of rotation instead of restarting it.
    #[error("{0} is unavailable")]
    Unavailable(&'static str),

    /// A dependency failed: database, cache, mail, an upstream provider.
    #[error("{context}")]
    Internal {
        /// What we were doing. Logged, never returned to the client.
        context: String,
        /// The underlying cause, if any.
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl AppError {
    /// Build a validation error.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation(message.into())
    }

    /// Build a field-level validation error.
    pub fn field(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Field {
            field: field.into(),
            message: message.into(),
        }
    }

    /// Build a conflict error.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict(message.into())
    }

    /// Build an internal error with context but no source.
    pub fn internal(context: impl Into<String>) -> Self {
        Self::Internal {
            context: context.into(),
            source: None,
        }
    }

    /// Build an internal error wrapping an underlying cause.
    pub fn internal_from(
        context: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Internal {
            context: context.into(),
            source: Some(Box::new(source)),
        }
    }

    /// The HTTP status this error maps to. **The only such mapping.**
    pub fn status(&self) -> u16 {
        match self {
            Self::Validation(_) | Self::Field { .. } => 400,
            Self::Unauthenticated => 401,
            Self::Forbidden => 403,
            Self::NotFound(_) => 404,
            Self::Conflict(_) => 409,
            Self::RateLimited => 429,
            Self::Internal { .. } => 500,
            Self::Unavailable(_) => 503,
        }
    }

    /// A stable machine-readable code, suitable for clients to branch on.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) | Self::Field { .. } => "invalid_request",
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::NotFound(_) => "not_found",
            Self::Conflict(_) => "conflict",
            Self::RateLimited => "rate_limited",
            Self::Internal { .. } => "internal_error",
            Self::Unavailable(_) => "unavailable",
        }
    }

    /// The detail that is safe to send to the client.
    ///
    /// Internal failures collapse to a fixed string — their real message is for
    /// the log, not the wire.
    pub fn public_detail(&self) -> String {
        match self {
            Self::Internal { .. } => "An internal error occurred.".to_owned(),
            other => other.to_string(),
        }
    }

    /// Whether this error should be logged at ERROR level.
    ///
    /// A failed login is not an application error; logging every one at ERROR
    /// (as the previous code did) buries the failures that matter.
    pub fn is_server_fault(&self) -> bool {
        matches!(self, Self::Internal { .. })
    }

    /// Render as an RFC 9457 problem document.
    pub fn to_problem(&self) -> Problem {
        Problem {
            r#type: format!("https://authenc.dev/problems/{}", self.code()),
            title: self.code().to_owned(),
            status: self.status(),
            detail: self.public_detail(),
            field: match self {
                Self::Field { field, .. } => Some(field.clone()),
                _ => None,
            },
        }
    }
}

/// An [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem document.
///
/// Served as `application/problem+json`, and deserialisable in the browser so
/// the Leptos side can render a typed error rather than a stringly-typed one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Problem {
    /// URI identifying the problem type.
    pub r#type: String,
    /// Short, stable summary — equal to [`AppError::code`].
    pub title: String,
    /// HTTP status code.
    pub status: u16,
    /// Human-readable explanation, already stripped of internal detail.
    pub detail: String,
    /// The offending field, for field-level validation failures.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {}", self.title, self.status, self.detail)
    }
}

/// Convenient result alias.
pub type Result<T, E = AppError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_detail_never_reaches_the_client() {
        let err = AppError::internal("connecting to postgres://user:hunter2@db:5432");
        assert_eq!(err.public_detail(), "An internal error occurred.");
        assert!(!err.to_problem().detail.contains("hunter2"));
    }

    #[test]
    fn validation_detail_does_reach_the_client() {
        let err = AppError::field("email", "must contain @");
        assert_eq!(err.status(), 400);
        assert_eq!(err.to_problem().field.as_deref(), Some("email"));
        assert!(err.public_detail().contains("must contain @"));
    }

    #[test]
    fn only_internal_errors_are_server_faults() {
        assert!(AppError::internal("boom").is_server_fault());
        assert!(!AppError::Unauthenticated.is_server_fault());
        assert!(!AppError::Forbidden.is_server_fault());
    }

    #[test]
    fn credentials_failure_is_401_not_400() {
        // The old codebase mapped this to 400 in one table and 401 in another.
        assert_eq!(AppError::Unauthenticated.status(), 401);
    }

    #[test]
    fn unavailable_is_503_and_keeps_its_detail() {
        // A readiness failure must be distinguishable from a crash: 503 tells
        // an orchestrator to stop routing traffic, 500 tells it nothing.
        let err = AppError::Unavailable("database");
        assert_eq!(err.status(), 503);
        assert!(!err.is_server_fault());
        assert!(err.public_detail().contains("database"));
    }

    #[test]
    fn conflict_is_409_not_400() {
        // The old `conflict()` helper returned a ValidationError, i.e. HTTP 400.
        assert_eq!(AppError::conflict("username taken").status(), 409);
    }
}
