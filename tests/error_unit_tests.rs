use authenc::error::{AuthencError, Result};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::Value;
use std::io;

// Helper function to extract status code from response
fn extract_status_code(error: AuthencError) -> StatusCode {
    let response = error.into_response();
    response.status()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_messages() {
        // Test basic error display messages
        assert_eq!(
            format!("{}", AuthencError::AuthenticationFailed),
            "Authentication failed"
        );
        assert_eq!(
            format!("{}", AuthencError::AccessDenied),
            "Access denied: insufficient permissions"
        );
        assert_eq!(
            format!("{}", AuthencError::InvalidCredentials),
            "Invalid credentials"
        );
        assert_eq!(format!("{}", AuthencError::TokenExpired), "Token expired");
        assert_eq!(format!("{}", AuthencError::InvalidToken), "Invalid token");
        assert_eq!(
            format!("{}", AuthencError::AccountLocked),
            "Account locked due to too many failed attempts"
        );
        assert_eq!(format!("{}", AuthencError::UserNotFound), "User not found");
        assert_eq!(
            format!("{}", AuthencError::RateLimitExceeded),
            "Rate limit exceeded"
        );
        assert_eq!(
            format!("{}", AuthencError::ServiceUnavailable),
            "Service temporarily unavailable"
        );
        assert_eq!(
            format!("{}", AuthencError::CryptographicError),
            "Cryptographic operation failed"
        );
    }

    #[test]
    fn test_error_display_with_custom_messages() {
        // Test errors with custom messages
        let unauthorized = AuthencError::unauthorized("Custom auth message");
        assert_eq!(
            format!("{}", unauthorized),
            "Unauthorized: Custom auth message"
        );

        let forbidden = AuthencError::forbidden("Custom forbidden message");
        assert_eq!(
            format!("{}", forbidden),
            "Forbidden: Custom forbidden message"
        );

        let validation = AuthencError::validation("Custom validation message");
        assert_eq!(
            format!("{}", validation),
            "Invalid input: Custom validation message"
        );

        let missing_field = AuthencError::missing_field("username");
        assert_eq!(
            format!("{}", missing_field),
            "Required field missing: username"
        );

        let invalid_format = AuthencError::InvalidFormat {
            field: "email".to_string(),
        };
        assert_eq!(format!("{}", invalid_format), "Invalid format: email");

        let resource_not_found = AuthencError::resource_not_found("user-123");
        assert_eq!(
            format!("{}", resource_not_found),
            "Resource not found: user-123"
        );

        let resource_exists = AuthencError::ResourceExists {
            resource: "user@example.com".to_string(),
        };
        assert_eq!(
            format!("{}", resource_exists),
            "Resource already exists: user@example.com"
        );

        let resource_conflict = AuthencError::ResourceConflict {
            resource: "session-456".to_string(),
        };
        assert_eq!(
            format!("{}", resource_conflict),
            "Operation not permitted on resource: session-456"
        );

        let db_error = AuthencError::database("Connection failed");
        assert_eq!(format!("{}", db_error), "Database error: Connection failed");

        let config_error = AuthencError::ConfigurationError {
            message: "Missing config".to_string(),
        };
        assert_eq!(
            format!("{}", config_error),
            "Configuration error: Missing config"
        );

        let external_error = AuthencError::ExternalServiceError {
            service: "keycloak".to_string(),
        };
        assert_eq!(
            format!("{}", external_error),
            "External service error: keycloak"
        );

        let internal_error = AuthencError::internal("Something went wrong");
        assert_eq!(
            format!("{}", internal_error),
            "Internal server error: Something went wrong"
        );

        let serialization_error = AuthencError::SerializationError {
            message: "Invalid JSON".to_string(),
        };
        assert_eq!(
            format!("{}", serialization_error),
            "Serialization error: Invalid JSON"
        );

        let network_error = AuthencError::NetworkError {
            message: "Connection timeout".to_string(),
        };
        assert_eq!(
            format!("{}", network_error),
            "Network error: Connection timeout"
        );
    }

    #[test]
    fn test_error_codes() {
        // Test error codes for all variants
        assert_eq!(
            AuthencError::AuthenticationFailed.error_code(),
            "AUTH_FAILED"
        );
        assert_eq!(AuthencError::AccessDenied.error_code(), "ACCESS_DENIED");
        assert_eq!(
            AuthencError::InvalidCredentials.error_code(),
            "INVALID_CREDENTIALS"
        );
        assert_eq!(AuthencError::TokenExpired.error_code(), "TOKEN_EXPIRED");
        assert_eq!(AuthencError::InvalidToken.error_code(), "INVALID_TOKEN");
        assert_eq!(AuthencError::AccountLocked.error_code(), "ACCOUNT_LOCKED");
        assert_eq!(
            AuthencError::Unauthorized {
                message: "".to_string()
            }
            .error_code(),
            "UNAUTHORIZED"
        );
        assert_eq!(
            AuthencError::Forbidden {
                message: "".to_string()
            }
            .error_code(),
            "FORBIDDEN"
        );
        assert_eq!(
            AuthencError::ValidationError {
                message: "".to_string()
            }
            .error_code(),
            "VALIDATION_ERROR"
        );
        assert_eq!(
            AuthencError::MissingField {
                field: "".to_string()
            }
            .error_code(),
            "MISSING_FIELD"
        );
        assert_eq!(
            AuthencError::InvalidFormat {
                field: "".to_string()
            }
            .error_code(),
            "INVALID_FORMAT"
        );
        assert_eq!(AuthencError::UserNotFound.error_code(), "USER_NOT_FOUND");
        assert_eq!(
            AuthencError::ResourceNotFound {
                resource: "".to_string()
            }
            .error_code(),
            "RESOURCE_NOT_FOUND"
        );
        assert_eq!(
            AuthencError::ResourceExists {
                resource: "".to_string()
            }
            .error_code(),
            "RESOURCE_EXISTS"
        );
        assert_eq!(
            AuthencError::ResourceConflict {
                resource: "".to_string()
            }
            .error_code(),
            "RESOURCE_CONFLICT"
        );
        assert_eq!(
            AuthencError::DatabaseError {
                message: "".to_string()
            }
            .error_code(),
            "DATABASE_ERROR"
        );
        assert_eq!(
            AuthencError::ConfigurationError {
                message: "".to_string()
            }
            .error_code(),
            "CONFIG_ERROR"
        );
        assert_eq!(
            AuthencError::ExternalServiceError {
                service: "".to_string()
            }
            .error_code(),
            "EXTERNAL_SERVICE_ERROR"
        );
        assert_eq!(
            AuthencError::RateLimitExceeded.error_code(),
            "RATE_LIMIT_EXCEEDED"
        );
        assert_eq!(
            AuthencError::ServiceUnavailable.error_code(),
            "SERVICE_UNAVAILABLE"
        );
        assert_eq!(
            AuthencError::InternalError {
                message: "".to_string()
            }
            .error_code(),
            "INTERNAL_ERROR"
        );
        assert_eq!(
            AuthencError::CryptographicError.error_code(),
            "CRYPTO_ERROR"
        );
        assert_eq!(
            AuthencError::SerializationError {
                message: "".to_string()
            }
            .error_code(),
            "SERIALIZATION_ERROR"
        );
        assert_eq!(
            AuthencError::NetworkError {
                message: "".to_string()
            }
            .error_code(),
            "NETWORK_ERROR"
        );
    }

    #[test]
    fn test_should_log_as_error() {
        // Test which errors should be logged as errors vs warnings
        assert!(
            AuthencError::DatabaseError {
                message: "".to_string()
            }
            .should_log_as_error()
        );
        assert!(
            AuthencError::ConfigurationError {
                message: "".to_string()
            }
            .should_log_as_error()
        );
        assert!(
            AuthencError::ExternalServiceError {
                service: "".to_string()
            }
            .should_log_as_error()
        );
        assert!(
            AuthencError::InternalError {
                message: "".to_string()
            }
            .should_log_as_error()
        );
        assert!(AuthencError::CryptographicError.should_log_as_error());
        assert!(AuthencError::ServiceUnavailable.should_log_as_error());
        assert!(
            AuthencError::Unauthorized {
                message: "".to_string()
            }
            .should_log_as_error()
        );
        assert!(
            AuthencError::Forbidden {
                message: "".to_string()
            }
            .should_log_as_error()
        );

        // These should NOT be logged as errors (logged as warnings)
        assert!(!AuthencError::AuthenticationFailed.should_log_as_error());
        assert!(!AuthencError::AccessDenied.should_log_as_error());
        assert!(!AuthencError::InvalidCredentials.should_log_as_error());
        assert!(!AuthencError::TokenExpired.should_log_as_error());
        assert!(!AuthencError::InvalidToken.should_log_as_error());
        assert!(!AuthencError::AccountLocked.should_log_as_error());
        assert!(
            !AuthencError::ValidationError {
                message: "".to_string()
            }
            .should_log_as_error()
        );
        assert!(
            !AuthencError::MissingField {
                field: "".to_string()
            }
            .should_log_as_error()
        );
        assert!(
            !AuthencError::InvalidFormat {
                field: "".to_string()
            }
            .should_log_as_error()
        );
        assert!(!AuthencError::UserNotFound.should_log_as_error());
        assert!(
            !AuthencError::ResourceNotFound {
                resource: "".to_string()
            }
            .should_log_as_error()
        );
        assert!(
            !AuthencError::ResourceExists {
                resource: "".to_string()
            }
            .should_log_as_error()
        );
        assert!(
            !AuthencError::ResourceConflict {
                resource: "".to_string()
            }
            .should_log_as_error()
        );
        assert!(!AuthencError::RateLimitExceeded.should_log_as_error());
        assert!(
            !AuthencError::SerializationError {
                message: "".to_string()
            }
            .should_log_as_error()
        );
        assert!(
            !AuthencError::NetworkError {
                message: "".to_string()
            }
            .should_log_as_error()
        );
    }

    #[test]
    fn test_status_codes() {
        // Test HTTP status code mapping
        // 400 Bad Request
        assert_eq!(
            AuthencError::ValidationError {
                message: "".to_string()
            }
            .status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AuthencError::MissingField {
                field: "".to_string()
            }
            .status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AuthencError::InvalidFormat {
                field: "".to_string()
            }
            .status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AuthencError::InvalidCredentials.status_code(),
            StatusCode::BAD_REQUEST
        );

        // 401 Unauthorized
        assert_eq!(
            AuthencError::AuthenticationFailed.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AuthencError::TokenExpired.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AuthencError::InvalidToken.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AuthencError::Unauthorized {
                message: "".to_string()
            }
            .status_code(),
            StatusCode::UNAUTHORIZED
        );

        // 403 Forbidden
        assert_eq!(
            AuthencError::AccessDenied.status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AuthencError::AccountLocked.status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AuthencError::Forbidden {
                message: "".to_string()
            }
            .status_code(),
            StatusCode::FORBIDDEN
        );

        // 404 Not Found
        assert_eq!(
            AuthencError::UserNotFound.status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AuthencError::ResourceNotFound {
                resource: "".to_string()
            }
            .status_code(),
            StatusCode::NOT_FOUND
        );

        // 409 Conflict
        assert_eq!(
            AuthencError::ResourceExists {
                resource: "".to_string()
            }
            .status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AuthencError::ResourceConflict {
                resource: "".to_string()
            }
            .status_code(),
            StatusCode::CONFLICT
        );

        // 429 Too Many Requests
        assert_eq!(
            AuthencError::RateLimitExceeded.status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );

        // 503 Service Unavailable
        assert_eq!(
            AuthencError::ServiceUnavailable.status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        // 500 Internal Server Error
        assert_eq!(
            AuthencError::DatabaseError {
                message: "".to_string()
            }
            .status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AuthencError::ConfigurationError {
                message: "".to_string()
            }
            .status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AuthencError::ExternalServiceError {
                service: "".to_string()
            }
            .status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AuthencError::InternalError {
                message: "".to_string()
            }
            .status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AuthencError::CryptographicError.status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AuthencError::SerializationError {
                message: "".to_string()
            }
            .status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AuthencError::NetworkError {
                message: "".to_string()
            }
            .status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_into_response_user_facing_errors() {
        // Test IntoResponse for user-facing errors (should return correct status codes)
        assert_eq!(
            extract_status_code(AuthencError::AuthenticationFailed),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            extract_status_code(AuthencError::ValidationError {
                message: "Invalid email".to_string()
            }),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            extract_status_code(AuthencError::UserNotFound),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn test_into_response_internal_errors() {
        // Test IntoResponse for internal errors (should return 500 status)
        assert_eq!(
            extract_status_code(AuthencError::DatabaseError {
                message: "Connection failed".to_string()
            }),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            extract_status_code(AuthencError::InternalError {
                message: "Secret info".to_string()
            }),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            extract_status_code(AuthencError::CryptographicError),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_from_implementations() {
        // Test From implementations for common error types
        let anyhow_err = anyhow::anyhow!("Test error");
        let authenc_err: AuthencError = anyhow_err.into();
        assert!(matches!(authenc_err, AuthencError::InternalError { .. }));

        let json_err = serde_json::from_str::<Value>("invalid json").unwrap_err();
        let authenc_err: AuthencError = json_err.into();
        assert!(matches!(
            authenc_err,
            AuthencError::SerializationError { .. }
        ));

        let io_err = io::Error::new(io::ErrorKind::NotFound, "File not found");
        let authenc_err: AuthencError = io_err.into();
        assert!(matches!(authenc_err, AuthencError::NetworkError { .. }));

        let uuid_err = uuid::Uuid::parse_str("invalid-uuid").unwrap_err();
        let authenc_err: AuthencError = uuid_err.into();
        assert!(matches!(authenc_err, AuthencError::ValidationError { .. }));

        let parse_int_err = "not_a_number".parse::<i32>().unwrap_err();
        let authenc_err: AuthencError = parse_int_err.into();
        assert!(matches!(
            authenc_err,
            AuthencError::ConfigurationError { .. }
        ));

        let parse_bool_err = "not_a_bool".parse::<bool>().unwrap_err();
        let authenc_err: AuthencError = parse_bool_err.into();
        assert!(matches!(
            authenc_err,
            AuthencError::ConfigurationError { .. }
        ));
    }

    #[test]
    fn test_constructor_methods() {
        // Test all constructor methods
        let validation = AuthencError::validation("test message");
        assert!(
            matches!(validation, AuthencError::ValidationError { message } if message == "test message")
        );

        let missing_field = AuthencError::missing_field("username");
        assert!(
            matches!(missing_field, AuthencError::MissingField { field } if field == "username")
        );

        let resource_not_found = AuthencError::resource_not_found("user-123");
        assert!(
            matches!(resource_not_found, AuthencError::ResourceNotFound { resource } if resource == "user-123")
        );

        let database = AuthencError::database("connection failed");
        assert!(
            matches!(database, AuthencError::DatabaseError { message } if message == "connection failed")
        );

        let internal = AuthencError::internal("internal error");
        assert!(
            matches!(internal, AuthencError::InternalError { message } if message == "internal error")
        );

        let unauthorized = AuthencError::unauthorized("not authenticated");
        assert!(
            matches!(unauthorized, AuthencError::Unauthorized { message } if message == "not authenticated")
        );

        let forbidden = AuthencError::forbidden("access denied");
        assert!(
            matches!(forbidden, AuthencError::Forbidden { message } if message == "access denied")
        );
    }

    #[test]
    fn test_result_type_alias() {
        // Test that Result type alias works
        let result: Result<i32> = Ok(42);
        assert_eq!(result.unwrap(), 42);

        let result: Result<i32> = Err(AuthencError::ValidationError {
            message: "test".to_string(),
        });
        assert!(result.is_err());
    }
}
