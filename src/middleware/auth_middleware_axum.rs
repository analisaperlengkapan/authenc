use axum::{
    body::Body,
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::Response,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::error;

use crate::error::AuthencError;

// Local result type for middleware that can return Response errors

/// The key used to store the authenticated user in request extensions
pub const AUTH_USER_KEY: &str = "authenc.auth_user";

/// Claims extracted from the JWT token
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthUser {
    /// Unique identifier of the authenticated user
    pub id: String,
    /// Email address of the authenticated user
    pub email: String,
    /// List of roles assigned to the authenticated user
    pub roles: Vec<String>,
}

/// State for auth middleware
#[derive(Clone)]
pub struct AuthState {
    /// Secret key used for JWT token validation
    /// Note: This is currently unused by the Ed25519 verification logic which uses a global keypair,
    /// but kept for compatibility or future symmetric key support.
    pub jwt_secret: String,
}

/// Middleware function that validates JWT tokens from the Authorization header
pub async fn auth_middleware(
    State(state): State<Arc<AuthState>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    // Skip authentication for public endpoints
    if is_public_endpoint(request.uri().path()) {
        return Ok(next.run(request).await);
    }

    // Get the token from the Authorization header
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Validate the token
    let user = validate_token(token, &state.jwt_secret).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // Insert the user into the request extensions
    request.extensions_mut().insert(user);

    Ok(next.run(request).await)
}

/// Extract and validate the JWT token
fn validate_token(token: &str, _secret: &str) -> Result<AuthUser, AuthencError> {
    // Use Ed25519 JWT verification
    // Note: verify_jwt uses the global ED25519_KEYPAIR, ignoring the passed _secret
    let claims = crate::utils::crypto::jwt::verify_jwt(token).map_err(|e| {
        error!("JWT validation failed: {}", e);
        AuthencError::unauthorized("Invalid token")
    })?;

    // Extract email and roles from JWT claims, with fallback values
    let email = claims.email.unwrap_or_else(|| {
        // If email is not in the token, use a placeholder
        // This can happen for tokens generated before the enhancement
        format!("{}@unknown.local", claims.sub)
    });
    
    let roles = claims.roles.unwrap_or_else(|| {
        // Default role if not specified in token
        vec!["user".to_string()]
    });

    Ok(AuthUser {
        id: claims.sub,
        email,
        roles,
    })
}

/// Extension trait to get the authenticated user from a request
pub trait AuthUserExt {
    /// Get the authenticated user if available
    fn auth_user(&self) -> Option<&AuthUser>;
}

impl<B> AuthUserExt for Request<B> {
    fn auth_user(&self) -> Option<&AuthUser> {
        self.extensions().get::<AuthUser>()
    }
}

/// Extension trait to require authentication for a handler
pub trait RequireAuth {
    /// Require the request to be authenticated
    fn require_auth(self) -> Result<AuthUser, AuthencError>;
}

impl<B> RequireAuth for &Request<B> {
    fn require_auth(self) -> Result<AuthUser, AuthencError> {
        self.extensions()
            .get::<AuthUser>()
            .cloned() // Clone instead of unsafe lifetime extension
            .ok_or_else(|| AuthencError::unauthorized("Authentication required"))
    }
}

/// Check if the endpoint is public and doesn't require authentication
fn is_public_endpoint(path: &str) -> bool {
    // Add public endpoints here
    matches!(
        path,
        "/health" | "/health/" | "/health/ready" | "/health/live"
    )
}

/// Create an auth middleware layer
pub fn auth_layer(secret: &str) -> impl tower::Layer<axum::Router> + Clone + Send + 'static {
    let state = Arc::new(AuthState {
        jwt_secret: secret.to_string(),
    });

    middleware::from_fn_with_state::<_, _, axum::body::Body>(state, auth_middleware)
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use tower::ServiceExt; // Required for oneshot

    use super::*;

    #[tokio::test]
    async fn test_auth_middleware() {
        // Comprehensive test for the middleware
        let state = Arc::new(AuthState {
            jwt_secret: "unused-secret".to_string(), // Secret is unused by Ed25519 verification
        });

        let app = Router::new()
            .route("/protected", get(|| async { "Protected content" }))
            .layer(axum::middleware::from_fn_with_state(state.clone(), auth_middleware));

        // 1. Test missing token
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // 2. Test invalid token
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("authorization", "Bearer invalid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // 3. Test valid token
        use crate::utils::crypto::jwt::generate_jwt;
        // generate_jwt uses the same global ED25519_KEYPAIR as verify_jwt
        let token = generate_jwt("test-user-id").expect("Failed to generate token");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_public_endpoints_no_auth_required() {
        let state = Arc::new(AuthState {
            jwt_secret: "unused-secret".to_string(),
        });

        let app = Router::new()
            .route("/health", get(|| async { "OK" }))
            .route("/health/ready", get(|| async { "Ready" }))
            .route("/health/live", get(|| async { "Live" }))
            .layer(axum::middleware::from_fn_with_state(state, auth_middleware));

        // Test health endpoint
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test health/ready endpoint
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test health/live endpoint
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_protected_endpoints_require_auth() {
        let state = Arc::new(AuthState {
            jwt_secret: "unused-secret".to_string(),
        });

        let app = Router::new()
            .route("/protected", get(|| async { "Protected content" }))
            .layer(axum::middleware::from_fn_with_state(state, auth_middleware));

        // Request without authorization header should fail
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Request with malformed authorization header should fail
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("authorization", "Invalid token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Request with non-Bearer authorization header should fail
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("authorization", "Basic dXNlcjpwYXNz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_user_extension() {
        use crate::utils::crypto::jwt::generate_jwt;

        let state = Arc::new(AuthState {
            jwt_secret: "unused-secret".to_string(),
        });

        let app = Router::new()
            .route(
                "/user",
                get(|req: Request<Body>| async move {
                    match req.auth_user() {
                        Some(user) => format!("User: {} ({})", user.email, user.id),
                        None => "No user".to_string(),
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(state, auth_middleware));

        // Generate a valid JWT token
        let token = generate_jwt("test-user-id").expect("Failed to generate token");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/user")
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body();
        let bytes = http_body_util::BodyExt::collect(body)
            .await
            .unwrap()
            .to_bytes();
        let body_str = String::from_utf8(bytes.to_vec()).unwrap();
        // Email is derived from user_id when not in token: "{user_id}@unknown.local"
        assert!(body_str.contains("test-user-id@unknown.local"));
        assert!(body_str.contains("test-user-id"));
    }

    #[tokio::test]
    async fn test_require_auth_extension() {
        use crate::utils::crypto::jwt::generate_jwt;

        let state = Arc::new(AuthState {
            jwt_secret: "unused-secret".to_string(),
        });

        let app = Router::new()
            .route(
                "/secure",
                get(|req: Request<Body>| async move {
                    match req.require_auth() {
                        Ok(user) => format!("Authenticated: {}", user.id),
                        Err(_) => "Authentication failed".to_string(),
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(state, auth_middleware));

        // Test without authentication
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/secure")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Test with valid authentication
        let token = generate_jwt("test-user-id").expect("Failed to generate token");

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/secure")
                    .header("authorization", format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body();
        let bytes = http_body_util::BodyExt::collect(body)
            .await
            .unwrap()
            .to_bytes();
        let body_str = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(body_str.contains("Authenticated: test-user-id"));
    }

    #[tokio::test]
    async fn test_invalid_jwt_token() {
        let state = Arc::new(AuthState {
            jwt_secret: "unused-secret".to_string(),
        });

        let app = Router::new()
            .route("/protected", get(|| async { "Protected" }))
            .layer(axum::middleware::from_fn_with_state(state, auth_middleware));

        // Test with invalid JWT token
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("authorization", "Bearer invalid.jwt.token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_state_creation() {
        let state = AuthState {
            jwt_secret: "my-secret-key".to_string(),
        };

        assert_eq!(state.jwt_secret, "my-secret-key");
    }

    #[tokio::test]
    async fn test_auth_user_struct() {
        let user = AuthUser {
            id: "user123".to_string(),
            email: "user@example.com".to_string(),
            roles: vec!["user".to_string(), "admin".to_string()],
        };

        assert_eq!(user.id, "user123");
        assert_eq!(user.email, "user@example.com");
        assert_eq!(user.roles.len(), 2);
        assert!(user.roles.contains(&"user".to_string()));
        assert!(user.roles.contains(&"admin".to_string()));
    }

    #[tokio::test]
    async fn test_is_public_endpoint() {
        assert!(is_public_endpoint("/health"));
        assert!(is_public_endpoint("/health/"));
        assert!(is_public_endpoint("/health/ready"));
        assert!(is_public_endpoint("/health/live"));

        assert!(!is_public_endpoint("/api/users"));
        assert!(!is_public_endpoint("/auth/login"));
        assert!(!is_public_endpoint("/protected"));
        assert!(!is_public_endpoint("/"));
    }

    #[tokio::test]
    async fn test_expired_token() {
        use crate::crypto::ed25519_keys::sign_ed25519;
        use crate::utils::crypto::jwt::Claims;
        use base64ct::{Base64UrlUnpadded, Encoding};
        use std::time::{SystemTime, UNIX_EPOCH};

        let state = Arc::new(AuthState {
            jwt_secret: "unused-secret".to_string(),
        });

        let app = Router::new()
            .route("/protected", get(|| async { "Protected" }))
            .layer(axum::middleware::from_fn_with_state(state, auth_middleware));

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        // Helper to create token manually
        let create_token = |claims: &Claims| -> String {
            let header = r#"{"alg":"EdDSA","typ":"JWT"}"#;
            let header_b64 = Base64UrlUnpadded::encode_string(header.as_bytes());
            let payload_json = serde_json::to_string(claims).unwrap();
            let payload_b64 = Base64UrlUnpadded::encode_string(payload_json.as_bytes());
            let message = format!("{}.{}", header_b64, payload_b64);
            let signature = sign_ed25519(message.as_bytes());
            let signature_b64 = Base64UrlUnpadded::encode_string(&signature.to_bytes());
            format!("{}.{}.{}", header_b64, payload_b64, signature_b64)
        };

        // 1. Verify that a valid token manually constructed works (sanity check for test harness)
        let valid_claims = Claims {
            sub: "test-user".to_string(),
            exp: now + 3600, // Expires in 1 hour
            email: None,
            roles: None,
        };
        let valid_token = create_token(&valid_claims);

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("authorization", format!("Bearer {}", valid_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK, "Manually constructed valid token should pass");

        // 2. Test expired token
        let expired_claims = Claims {
            sub: "test-user".to_string(),
            exp: now - 3600, // Expired 1 hour ago
            email: None,
            roles: None,
        };
        let expired_token = create_token(&expired_claims);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/protected")
                    .header("authorization", format!("Bearer {}", expired_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "Expired token should be rejected");
    }
}
