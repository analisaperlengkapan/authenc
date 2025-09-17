use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Type alias for Results in this crate  
pub type Result<T> = std::result::Result<T, AuthencError>;

/// Legacy alias for backward compatibility
pub type AuthenceResult<T> = Result<T>; // backward compat

/// Comprehensive error types for the Authence application
#[derive(Error, Debug)]
pub enum AuthencError {
    // Authentication and authorization errors
    /// Authentication failed due to invalid credentials or session
    #[error("Authentication failed")]
    AuthenticationFailed,

    /// Access denied due to insufficient permissions
    #[error("Access denied: insufficient permissions")]
    AccessDenied,

    /// Invalid credentials provided during authentication
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// JWT token has expired and needs refresh
    #[error("Token expired")]
    TokenExpired,

    /// JWT token is malformed or invalid
    #[error("Invalid token")]
    InvalidToken,

    /// Account locked due to too many failed authentication attempts
    #[error("Account locked due to too many failed attempts")]
    AccountLocked,

    /// Unauthorized access attempt with custom message
    #[error("Unauthorized: {message}")]
    Unauthorized { 
        /// The custom error message describing the unauthorized access
        message: String 
    },

    /// Forbidden operation with custom message
    #[error("Forbidden: {message}")]
    Forbidden { 
        /// The custom error message describing the forbidden operation
        message: String 
    },

    // Validation errors
    /// Input validation failed with custom message
    #[error("Invalid input: {message}")]
    ValidationError { 
        /// The custom error message describing the validation failure
        message: String 
    },

    /// Required field is missing from input
    #[error("Required field missing: {field}")]
    MissingField { 
        /// The name of the missing required field
        field: String 
    },

    /// Field has invalid format
    #[error("Invalid format: {field}")]
    InvalidFormat { 
        /// The name of the field with invalid format
        field: String 
    },

    // Resource errors
    /// User account not found in the system
    #[error("User not found")]
    UserNotFound,

    /// Requested resource does not exist
    #[error("Resource not found: {resource}")]
    ResourceNotFound { 
        /// The identifier or name of the resource that was not found
        resource: String 
    },

    /// Resource already exists and cannot be created again
    #[error("Resource already exists: {resource}")]
    ResourceExists { 
        /// The identifier or name of the resource that already exists
        resource: String 
    },

    /// Operation not permitted due to resource state conflict
    #[error("Operation not permitted on resource: {resource}")]
    ResourceConflict { 
        /// The identifier or name of the resource with the state conflict
        resource: String 
    },

    // System errors
    /// Database operation failed with custom message
    #[error("Database error: {message}")]
    DatabaseError { 
        /// The detailed error message from the database operation
        message: String 
    },

    /// Configuration is invalid or missing
    #[error("Configuration error: {message}")]
    ConfigurationError { 
        /// The detailed error message describing the configuration issue
        message: String 
    },

    /// External service dependency failed
    #[error("External service error: {service}")]
    ExternalServiceError { 
        /// The name or identifier of the external service that failed
        service: String 
    },

    /// Rate limit exceeded for the operation
    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    /// Service is temporarily unavailable
    #[error("Service temporarily unavailable")]
    ServiceUnavailable,

    // Internal errors
    /// Internal server error with custom message
    #[error("Internal server error: {message}")]
    InternalError { 
        /// The detailed error message describing the internal server error
        message: String 
    },

    /// Data serialization/deserialization failed
    #[error("Serialization error: {message}")]
    SerializationError { 
        /// The detailed error message from the serialization/deserialization operation
        message: String 
    },

    /// Cryptographic operation failed
    #[error("Cryptographic operation failed")]
    CryptographicError,

    /// Network communication failed
    #[error("Network error: {message}")]
    NetworkError { 
        /// The detailed error message describing the network communication failure
        message: String 
    },
}

impl AuthencError {
    /// Create a validation error with custom message
    pub fn validation<T: Into<String>>(message: T) -> Self {
        Self::ValidationError {
            message: message.into(),
        }
    }

    /// Create a missing field error
    pub fn missing_field<T: Into<String>>(field: T) -> Self {
        Self::MissingField {
            field: field.into(),
        }
    }

    /// Create a resource not found error
    pub fn resource_not_found<T: Into<String>>(resource: T) -> Self {
        Self::ResourceNotFound {
            resource: resource.into(),
        }
    }

    /// Create a database error
    pub fn database<T: Into<String>>(message: T) -> Self {
        Self::DatabaseError {
            message: message.into(),
        }
    }

    /// Create an internal error
    pub fn internal<T: Into<String>>(message: T) -> Self {
        Self::InternalError {
            message: message.into(),
        }
    }

    /// Create an unauthorized error for authentication failures
    ///
    /// This constructor creates an `AuthencError::Unauthorized` variant to indicate
    /// that the request lacks valid authentication credentials or the provided
    /// credentials are invalid/expired.
    ///
    /// # Arguments
    /// * `message` - A descriptive message explaining the authentication failure
    ///
    /// # Returns
    /// An `AuthencError::Unauthorized` instance with the provided message
    ///
    /// # Example
    /// ```rust
    /// use authenc::error::AuthencError;
    ///
    /// let error = AuthencError::unauthorized("Invalid or expired authentication token");
    /// ```
    pub fn unauthorized<T: Into<String>>(message: T) -> Self {
        Self::Unauthorized {
            message: message.into(),
        }
    }

    /// Create a forbidden error for access denied scenarios
    ///
    /// This constructor creates an `AuthencError::Forbidden` variant to indicate
    /// that the authenticated user does not have sufficient permissions to access
    /// the requested resource, even though they are authenticated.
    ///
    /// # Arguments
    /// * `message` - A descriptive message explaining why access was denied
    ///
    /// # Returns
    /// An `AuthencError::Forbidden` instance with the provided message
    ///
    /// # Example
    /// ```rust
    /// use authenc::error::AuthencError;
    ///
    /// let error = AuthencError::forbidden("User lacks required role for this operation");
    /// ```
    pub fn forbidden<T: Into<String>>(message: T) -> Self {
        Self::Forbidden {
            message: message.into(),
        }
    }

    /// Check if the error should be logged as an error (vs warning)
    pub fn should_log_as_error(&self) -> bool {
        matches!(
            self,
            AuthencError::DatabaseError { .. }
                | AuthencError::ConfigurationError { .. }
                | AuthencError::ExternalServiceError { .. }
                | AuthencError::InternalError { .. }
                | AuthencError::CryptographicError
                | AuthencError::ServiceUnavailable
                | AuthencError::Unauthorized { .. }
                | AuthencError::Forbidden { .. }
        )
    }

    /// Get the error code for structured logging and monitoring
    pub fn error_code(&self) -> &'static str {
        match self {
            AuthencError::AuthenticationFailed => "AUTH_FAILED",
            AuthencError::AccessDenied => "ACCESS_DENIED",
            AuthencError::InvalidCredentials => "INVALID_CREDENTIALS",
            AuthencError::TokenExpired => "TOKEN_EXPIRED",
            AuthencError::InvalidToken => "INVALID_TOKEN",
            AuthencError::AccountLocked => "ACCOUNT_LOCKED",
            AuthencError::Unauthorized { .. } => "UNAUTHORIZED",
            AuthencError::Forbidden { .. } => "FORBIDDEN",
            AuthencError::ValidationError { .. } => "VALIDATION_ERROR",
            AuthencError::MissingField { .. } => "MISSING_FIELD",
            AuthencError::InvalidFormat { .. } => "INVALID_FORMAT",
            AuthencError::UserNotFound => "USER_NOT_FOUND",
            AuthencError::ResourceNotFound { .. } => "RESOURCE_NOT_FOUND",
            AuthencError::ResourceExists { .. } => "RESOURCE_EXISTS",
            AuthencError::ResourceConflict { .. } => "RESOURCE_CONFLICT",
            AuthencError::DatabaseError { .. } => "DATABASE_ERROR",
            AuthencError::ConfigurationError { .. } => "CONFIG_ERROR",
            AuthencError::ExternalServiceError { .. } => "EXTERNAL_SERVICE_ERROR",
            AuthencError::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            AuthencError::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            AuthencError::InternalError { .. } => "INTERNAL_ERROR",
            AuthencError::CryptographicError => "CRYPTO_ERROR",
            AuthencError::SerializationError { .. } => "SERIALIZATION_ERROR",
            AuthencError::NetworkError { .. } => "NETWORK_ERROR",
        }
    }
}

impl IntoResponse for AuthencError {
    fn into_response(self) -> Response {
        let status = self.status_code();

        // For internal errors, don't expose sensitive information
        let error_message = match &self {
            AuthencError::DatabaseError { .. }
            | AuthencError::ConfigurationError { .. }
            | AuthencError::InternalError { .. }
            | AuthencError::CryptographicError
            | AuthencError::SerializationError { .. }
            | AuthencError::NetworkError { .. } => {
                tracing::error!("Internal error occurred: {}", self);
                "An internal error occurred. Please try again later.".to_string()
            }
            _ => self.to_string(),
        };

        let response_body = json!({
            "error": {
                "code": self.error_code(),
                "message": error_message,
                "status": status.as_u16()
            }
        });

        (status, Json(response_body)).into_response()
    }
}

impl AuthencError {
    fn status_code(&self) -> StatusCode {
        match self {
            // 400 Bad Request
            AuthencError::ValidationError { .. }
            | AuthencError::MissingField { .. }
            | AuthencError::InvalidFormat { .. }
            | AuthencError::InvalidCredentials => StatusCode::BAD_REQUEST,

            // 401 Unauthorized
            AuthencError::AuthenticationFailed
            | AuthencError::TokenExpired
            | AuthencError::InvalidToken => StatusCode::UNAUTHORIZED,

            // 403 Forbidden
            AuthencError::AccessDenied
            | AuthencError::AccountLocked
            | AuthencError::Forbidden { .. } => StatusCode::FORBIDDEN,

            // 401 Unauthorized (additional)
            AuthencError::Unauthorized { .. } => StatusCode::UNAUTHORIZED,

            // 404 Not Found
            AuthencError::UserNotFound | AuthencError::ResourceNotFound { .. } => {
                StatusCode::NOT_FOUND
            }

            // 409 Conflict
            AuthencError::ResourceExists { .. } | AuthencError::ResourceConflict { .. } => {
                StatusCode::CONFLICT
            }

            // 429 Too Many Requests
            AuthencError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,

            // 503 Service Unavailable
            AuthencError::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,

            // 500 Internal Server Error
            AuthencError::DatabaseError { .. }
            | AuthencError::ConfigurationError { .. }
            | AuthencError::ExternalServiceError { .. }
            | AuthencError::InternalError { .. }
            | AuthencError::CryptographicError
            | AuthencError::SerializationError { .. }
            | AuthencError::NetworkError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

/// Convert common error types to AuthencError
impl From<anyhow::Error> for AuthencError {
    fn from(err: anyhow::Error) -> Self {
        AuthencError::internal(err.to_string())
    }
}

impl From<serde_json::Error> for AuthencError {
    fn from(err: serde_json::Error) -> Self {
        AuthencError::SerializationError {
            message: err.to_string(),
        }
    }
}

impl From<tokio_postgres::Error> for AuthencError {
    fn from(err: tokio_postgres::Error) -> Self {
        AuthencError::database(err.to_string())
    }
}

impl From<deadpool_postgres::PoolError> for AuthencError {
    fn from(err: deadpool_postgres::PoolError) -> Self {
        AuthencError::database(err.to_string())
    }
}

impl From<argon2::password_hash::Error> for AuthencError {
    fn from(_err: argon2::password_hash::Error) -> Self {
        AuthencError::CryptographicError
    }
}

impl From<std::num::ParseIntError> for AuthencError {
    fn from(err: std::num::ParseIntError) -> Self {
        AuthencError::ConfigurationError {
            message: format!("Failed to parse integer: {}", err),
        }
    }
}

impl From<std::str::ParseBoolError> for AuthencError {
    fn from(err: std::str::ParseBoolError) -> Self {
        AuthencError::ConfigurationError {
            message: format!("Failed to parse boolean: {}", err),
        }
    }
}

impl From<std::io::Error> for AuthencError {
    fn from(err: std::io::Error) -> Self {
        AuthencError::NetworkError {
            message: format!("IO error: {}", err),
        }
    }
}
