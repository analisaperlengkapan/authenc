use thiserror::Error;
use actix_web::{HttpResponse, ResponseError};
use serde_json::json;

/// Type alias for Results in this crate  
pub type Result<T> = std::result::Result<T, AuthencError>;

/// Legacy alias for backward compatibility
pub type AuthenceResult<T> = Result<T>; // backward compat

/// Comprehensive error types for the Authence application
#[derive(Error, Debug)]
pub enum AuthencError {
    // Authentication and authorization errors
    #[error("Authentication failed")]
    AuthenticationFailed,
    
    #[error("Access denied: insufficient permissions")]
    AccessDenied,
    
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("Token expired")]
    TokenExpired,
    
    #[error("Invalid token")]
    InvalidToken,
    
    #[error("Account locked due to too many failed attempts")]
    AccountLocked,
    
    // Validation errors
    #[error("Invalid input: {message}")]
    ValidationError { message: String },
    
    #[error("Required field missing: {field}")]
    MissingField { field: String },
    
    #[error("Invalid format: {field}")]
    InvalidFormat { field: String },
    
    // Resource errors
    #[error("User not found")]
    UserNotFound,
    
    #[error("Resource not found: {resource}")]
    ResourceNotFound { resource: String },
    
    #[error("Resource already exists: {resource}")]
    ResourceExists { resource: String },
    
    #[error("Operation not permitted on resource: {resource}")]
    ResourceConflict { resource: String },
    
    // System errors
    #[error("Database error: {message}")]
    DatabaseError { message: String },
    
    #[error("Configuration error: {message}")]
    ConfigurationError { message: String },
    
    #[error("External service error: {service}")]
    ExternalServiceError { service: String },
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Service temporarily unavailable")]
    ServiceUnavailable,
    
    // Internal errors
    #[error("Internal server error: {message}")]
    InternalError { message: String },
    
    #[error("Cryptographic operation failed")]
    CryptographicError,
    
    #[error("Serialization error: {message}")]
    SerializationError { message: String },
    
    #[error("Network error: {message}")]
    NetworkError { message: String },
}

impl AuthencError {
    /// Create a validation error with custom message
    pub fn validation<T: Into<String>>(message: T) -> Self {
        Self::ValidationError { message: message.into() }
    }
    
    /// Create a missing field error
    pub fn missing_field<T: Into<String>>(field: T) -> Self {
        Self::MissingField { field: field.into() }
    }
    
    /// Create a resource not found error
    pub fn resource_not_found<T: Into<String>>(resource: T) -> Self {
        Self::ResourceNotFound { resource: resource.into() }
    }
    
    /// Create a database error
    pub fn database<T: Into<String>>(message: T) -> Self {
        Self::DatabaseError { message: message.into() }
    }
    
    /// Create an internal error
    pub fn internal<T: Into<String>>(message: T) -> Self {
        Self::InternalError { message: message.into() }
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

impl ResponseError for AuthencError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            // 400 Bad Request
            AuthencError::ValidationError { .. }
            | AuthencError::MissingField { .. }
            | AuthencError::InvalidFormat { .. }
            | AuthencError::InvalidCredentials => actix_web::http::StatusCode::BAD_REQUEST,
            
            // 401 Unauthorized
            AuthencError::AuthenticationFailed
            | AuthencError::TokenExpired
            | AuthencError::InvalidToken => actix_web::http::StatusCode::UNAUTHORIZED,
            
            // 403 Forbidden
            AuthencError::AccessDenied
            | AuthencError::AccountLocked => actix_web::http::StatusCode::FORBIDDEN,
            
            // 404 Not Found
            AuthencError::UserNotFound
            | AuthencError::ResourceNotFound { .. } => actix_web::http::StatusCode::NOT_FOUND,
            
            // 409 Conflict
            AuthencError::ResourceExists { .. }
            | AuthencError::ResourceConflict { .. } => actix_web::http::StatusCode::CONFLICT,
            
            // 429 Too Many Requests
            AuthencError::RateLimitExceeded => actix_web::http::StatusCode::TOO_MANY_REQUESTS,
            
            // 503 Service Unavailable
            AuthencError::ServiceUnavailable => actix_web::http::StatusCode::SERVICE_UNAVAILABLE,
            
            // 500 Internal Server Error
            AuthencError::DatabaseError { .. }
            | AuthencError::ConfigurationError { .. }
            | AuthencError::ExternalServiceError { .. }
            | AuthencError::InternalError { .. }
            | AuthencError::CryptographicError
            | AuthencError::SerializationError { .. }
            | AuthencError::NetworkError { .. } => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    
    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        
        // For internal errors, don't expose sensitive information
        let error_message = match self {
            AuthencError::DatabaseError { .. }
                | AuthencError::ConfigurationError { .. }
                | AuthencError::InternalError { .. }
                | AuthencError::CryptographicError
                | AuthencError::SerializationError { .. }
                | AuthencError::NetworkError { .. } => {
                log::error!("Internal error occurred: {}", self);
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
        
        HttpResponse::build(status).json(response_body)
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
    AuthencError::SerializationError { message: err.to_string() }
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
            message: format!("Failed to parse integer: {}", err)
        }
    }
}

impl From<std::str::ParseBoolError> for AuthencError {
    fn from(err: std::str::ParseBoolError) -> Self {
    AuthencError::ConfigurationError { 
            message: format!("Failed to parse boolean: {}", err)
        }
    }
}
