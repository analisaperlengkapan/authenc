use axum::{
    Router,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{delete, get, post, put},
};
use std::sync::Arc;

use crate::app::AppState;
use crate::error::AuthencError;
use authenc_models::models::client_registration::{
    ClientRegistrationError, ClientRegistrationRequest, ClientRegistrationResponse,
    ClientUpdateRequest, SoftwareStatement,
};
use authenc_services::services::client_registration::{
    ClientRegistrationService, DefaultClientRegistrationService,
};
use jsonwebtoken::dangerous::insecure_decode;


/// Create client registration routes (RFC 7591/7592)
pub fn create_client_registration_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/register", post(register_client))
        .route("/register/{client_id}", get(get_client_configuration))
        .route("/register/{client_id}", put(update_client_configuration))
        .route("/register/{client_id}", delete(delete_client_registration))
}

/// Register a new OAuth 2.0 client (RFC 7591)
async fn register_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<ClientRegistrationRequest>,
) -> Result<
    (StatusCode, Json<ClientRegistrationResponse>),
    (StatusCode, Json<ClientRegistrationError>),
> {
    // Create client registration service
    let registration_service = DefaultClientRegistrationService::new(
        state.oidc_client_store.clone(),
        true,  // enable_dynamic_registration
        false, // require_software_statement
        Some(state.config.security.jwt_secret.as_bytes().to_vec()), // Validation secret
    );

    // Check for software statement in Authorization header
    // In this implementation, we extract the token but don't parse it yet, passing it to the service
    let software_statement = extract_registration_token(&headers);

    // Register client
    match registration_service
        .register_client(request, software_statement)
        .await
    {
        Ok(response) => Ok((StatusCode::CREATED, Json(response))),
        Err(err) => {
            let error_response = match err {
                AuthencError::ValidationError { message } => ClientRegistrationError {
                    error: "invalid_client_metadata".to_string(),
                    error_description: Some(message),
                },
                AuthencError::ConfigurationError { message } => ClientRegistrationError {
                    error: "invalid_request".to_string(),
                    error_description: Some(message),
                },
                _ => ClientRegistrationError {
                    error: "invalid_request".to_string(),
                    error_description: Some("Client registration failed".to_string()),
                },
            };
            Err((StatusCode::BAD_REQUEST, Json(error_response)))
        }
    }
}

/// Get client configuration (RFC 7592)
async fn get_client_configuration(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<ClientRegistrationResponse>, (StatusCode, Json<ClientRegistrationError>)> {
    // Extract registration access token from Authorization header
    let registration_token = match extract_registration_token(&headers) {
        Some(token) => token,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ClientRegistrationError {
                    error: "invalid_token".to_string(),
                    error_description: Some(
                        "Missing or invalid registration access token".to_string(),
                    ),
                }),
            ));
        }
    };

    // Create client registration service
    let registration_service = DefaultClientRegistrationService::new(
        state.oidc_client_store.clone(),
        true,  // enable_dynamic_registration
        false, // require_software_statement
        Some(state.config.security.jwt_secret.as_bytes().to_vec()),
    );

    // Get client configuration
    match registration_service
        .get_client_configuration(&client_id, &registration_token)
        .await
    {
        Ok(response) => Ok(Json(response)),
        Err(err) => {
            let error_response = match err {
                AuthencError::AuthenticationFailed => ClientRegistrationError {
                    error: "invalid_token".to_string(),
                    error_description: Some("Invalid registration access token".to_string()),
                },
                AuthencError::ResourceNotFound { .. } => ClientRegistrationError {
                    error: "invalid_client_id".to_string(),
                    error_description: Some("Client not found".to_string()),
                },
                _ => ClientRegistrationError {
                    error: "invalid_request".to_string(),
                    error_description: Some("Failed to get client configuration".to_string()),
                },
            };
            Err((StatusCode::BAD_REQUEST, Json(error_response)))
        }
    }
}

/// Update client configuration (RFC 7592)
async fn update_client_configuration(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ClientUpdateRequest>,
) -> Result<Json<ClientRegistrationResponse>, (StatusCode, Json<ClientRegistrationError>)> {
    // Extract registration access token from Authorization header
    let registration_token = match extract_registration_token(&headers) {
        Some(token) => token,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ClientRegistrationError {
                    error: "invalid_token".to_string(),
                    error_description: Some(
                        "Missing or invalid registration access token".to_string(),
                    ),
                }),
            ));
        }
    };

    // Create client registration service
    let registration_service = DefaultClientRegistrationService::new(
        state.oidc_client_store.clone(),
        true,  // enable_dynamic_registration
        false, // require_software_statement
        Some(state.config.security.jwt_secret.as_bytes().to_vec()),
    );

    // Update client configuration
    match registration_service
        .update_client_configuration(&client_id, &registration_token, request)
        .await
    {
        Ok(response) => Ok(Json(response)),
        Err(err) => {
            let error_response = match err {
                AuthencError::AuthenticationFailed => ClientRegistrationError {
                    error: "invalid_token".to_string(),
                    error_description: Some("Invalid registration access token".to_string()),
                },
                AuthencError::ValidationError { message } => ClientRegistrationError {
                    error: "invalid_client_metadata".to_string(),
                    error_description: Some(message),
                },
                AuthencError::ResourceNotFound { .. } => ClientRegistrationError {
                    error: "invalid_client_id".to_string(),
                    error_description: Some("Client not found".to_string()),
                },
                _ => ClientRegistrationError {
                    error: "invalid_request".to_string(),
                    error_description: Some("Failed to update client configuration".to_string()),
                },
            };
            Err((StatusCode::BAD_REQUEST, Json(error_response)))
        }
    }
}

/// Delete client registration (RFC 7592)
async fn delete_client_registration(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, Json<ClientRegistrationError>)> {
    // Extract registration access token from Authorization header
    let registration_token = match extract_registration_token(&headers) {
        Some(token) => token,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ClientRegistrationError {
                    error: "invalid_token".to_string(),
                    error_description: Some(
                        "Missing or invalid registration access token".to_string(),
                    ),
                }),
            ));
        }
    };

    // Create client registration service
    let registration_service = DefaultClientRegistrationService::new(
        state.oidc_client_store.clone(),
        true,  // enable_dynamic_registration
        false, // require_software_statement
        Some(state.config.security.jwt_secret.as_bytes().to_vec()),
    );

    // Delete client registration
    match registration_service
        .delete_client_registration(&client_id, &registration_token)
        .await
    {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(err) => {
            let error_response = match err {
                AuthencError::AuthenticationFailed => ClientRegistrationError {
                    error: "invalid_token".to_string(),
                    error_description: Some("Invalid registration access token".to_string()),
                },
                AuthencError::ResourceNotFound { .. } => ClientRegistrationError {
                    error: "invalid_client_id".to_string(),
                    error_description: Some("Client not found".to_string()),
                },
                _ => ClientRegistrationError {
                    error: "invalid_request".to_string(),
                    error_description: Some("Failed to delete client registration".to_string()),
                },
            };
            Err((StatusCode::BAD_REQUEST, Json(error_response)))
        }
    }
}

/// Extract registration access token from Authorization header
fn extract_registration_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|auth| auth.to_str().ok())
        .and_then(|auth| {
            if auth.len() >= 7 && auth.as_bytes()[..7].eq_ignore_ascii_case(b"bearer ") {
                Some(auth[7..].to_string())
            } else {
                None
            }
        })
}

/// Parse software statement from JWT string
/// Note: This only decodes the payload, validation is done by the service
#[allow(dead_code)]
fn parse_software_statement(token: &str) -> Option<SoftwareStatement> {
    let decoded = insecure_decode::<SoftwareStatement>(token).ok()?;
    Some(decoded.claims)
}


#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use jsonwebtoken::{encode, EncodingKey, Header};

    #[test]
    fn test_extract_registration_token() {
        // Test with valid Bearer token
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer some.jwt.token"),
        );
        assert_eq!(
            extract_registration_token(&headers),
            Some("some.jwt.token".to_string())
        );

        // Test with invalid prefix
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Basic some.jwt.token"),
        );
        assert_eq!(extract_registration_token(&headers), None);

        // Test with no authorization header
        let headers = HeaderMap::new();
        assert_eq!(extract_registration_token(&headers), None);

        // Test with just "Bearer "
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer "));
        assert_eq!(extract_registration_token(&headers), Some("".to_string()));

        // Test with lowercase "bearer "
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("bearer some.jwt.token"));
        assert_eq!(extract_registration_token(&headers), Some("some.jwt.token".to_string()));

        // Test with mixed case "BeArEr "
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("BeArEr some.jwt.token"));
        assert_eq!(extract_registration_token(&headers), Some("some.jwt.token".to_string()));
    }

    #[test]
    fn test_parse_software_statement() {
        use serde_json::json;

        // Create a mock JWT payload
        let payload = SoftwareStatement {
            software_id: Some("test_software".to_string()),
            software_version: Some("1.0".to_string()),
            client_metadata: std::collections::HashMap::from([
                ("client_name".to_string(), json!("Test Client"))
            ]),
        };

        // Create a proper JWT using jsonwebtoken
        let key = EncodingKey::from_secret(b"secret");
        let token = encode(&Header::default(), &payload, &key).expect("Failed to encode token");

        // Test parsing
        let stmt = parse_software_statement(&token).expect("Failed to parse software statement");
        assert_eq!(stmt.software_id, Some("test_software".to_string()));
        assert_eq!(stmt.software_version, Some("1.0".to_string()));
        assert_eq!(stmt.client_metadata.get("client_name"), Some(&json!("Test Client")));

        // Test invalid token format
        assert!(parse_software_statement("invalid").is_none());
        // jsonwebtoken parsing might return specific errors, but our function returns Option::None
    }
}
