use axum::{
    body::Body,
    extract::{Request, State},
    http::{Response, StatusCode},
    middleware::Next,
};
use base64::{engine::general_purpose, Engine as _};
use rand::{thread_rng, Rng};
use std::sync::Arc;
use tracing::{debug, warn};

/// Configuration for CSRF protection
#[derive(Clone, Debug)]
pub struct CsrfConfig {
    /// Whether CSRF protection is enabled
    pub enabled: bool,
    /// Name of the CSRF token header
    pub header_name: String,
    /// Name of the CSRF token cookie
    pub cookie_name: String,
    /// CSRF token length in bytes
    pub token_length: usize,
    /// Paths to exclude from CSRF protection
    pub excluded_paths: Vec<String>,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            header_name: "X-CSRF-Token".to_string(),
            cookie_name: "csrf_token".to_string(),
            token_length: 32,
            excluded_paths: vec![
                "/health".to_string(),
                "/health/ready".to_string(),
                "/health/live".to_string(),
                "/metrics".to_string(),
            ],
        }
    }
}

/// CSRF protection state
#[derive(Clone)]
pub struct CsrfState {
    config: CsrfConfig,
}

impl CsrfState {
    /// Create a new CSRF state with the given configuration
    pub fn new(config: CsrfConfig) -> Self {
        Self { config }
    }

    /// Generate a new CSRF token
    pub fn generate_token(&self) -> String {
        let mut rng = thread_rng();
        let mut token_bytes = vec![0u8; self.config.token_length];
        rng.fill(&mut token_bytes[..]);
        general_purpose::URL_SAFE_NO_PAD.encode(&token_bytes)
    }

    /// Validate CSRF token
    pub fn validate_token(&self, token: &str) -> bool {
        // Basic validation - in production, you might want to store tokens
        // in a cache with expiration times
        !token.is_empty() && token.len() >= 32
    }
}

/// Middleware that provides CSRF protection
pub async fn csrf_protection_middleware(
    State(state): State<Arc<CsrfState>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    if !state.config.enabled {
        return Ok(next.run(request).await);
    }

    let path = request.uri().path();

    // Skip CSRF protection for excluded paths
    if state
        .config
        .excluded_paths
        .iter()
        .any(|excluded| path.starts_with(excluded))
    {
        return Ok(next.run(request).await);
    }

    // Skip CSRF protection for GET, HEAD, OPTIONS requests
    if matches!(
        request.method(),
        &axum::http::Method::GET | &axum::http::Method::HEAD | &axum::http::Method::OPTIONS
    ) {
        return Ok(next.run(request).await);
    }

    // Extract CSRF token from header
    let csrf_token = request
        .headers()
        .get(&state.config.header_name)
        .and_then(|h| h.to_str().ok());

    let csrf_token = match csrf_token {
        Some(token) => token,
        None => {
            warn!("CSRF token missing in request to {}", path);
            return Err(StatusCode::FORBIDDEN);
        }
    };

    // Validate the token
    if !state.validate_token(csrf_token) {
        warn!("Invalid CSRF token in request to {}", path);
        return Err(StatusCode::FORBIDDEN);
    }

    debug!("CSRF token validated for request to {}", path);
    Ok(next.run(request).await)
}

/// Generate a CSRF token response header
pub fn generate_csrf_token_response(state: &CsrfState) -> (String, String) {
    let token = state.generate_token();
    (state.config.header_name.clone(), token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::Request,
        http::{Method, StatusCode},
        middleware::from_fn,
        routing::{get, post},
        Router,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_csrf_protection_enabled() {
        let state = Arc::new(CsrfState::new(CsrfConfig::default()));
        let app = Router::new()
            .route("/test", post(|| async { "OK" }))
            .layer(from_fn(move |req, next| {
                let state = state.clone();
                csrf_protection_middleware(State(state), req, next)
            }));

        // Request without CSRF token should fail
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_csrf_protection_disabled() {
        let config = CsrfConfig {
            enabled: false,
            ..Default::default()
        };
        let state = Arc::new(CsrfState::new(config));
        let app = Router::new()
            .route("/test", post(|| async { "OK" }))
            .layer(from_fn(move |req, next| {
                let state = state.clone();
                csrf_protection_middleware(State(state), req, next)
            }));

        // Request without CSRF token should succeed when disabled
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_csrf_excluded_paths() {
        let state = Arc::new(CsrfState::new(CsrfConfig::default()));
        let app = Router::new()
            .route("/health", post(|| async { "OK" }))
            .layer(from_fn(move |req, next| {
                let state = state.clone();
                csrf_protection_middleware(State(state), req, next)
            }));

        // Health endpoint should be excluded from CSRF protection
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_csrf_get_requests_allowed() {
        let state = Arc::new(CsrfState::new(CsrfConfig::default()));
        let app = Router::new()
            .route("/test", get(|| async { "OK" }))
            .layer(from_fn(move |req, next| {
                let state = state.clone();
                csrf_protection_middleware(State(state), req, next)
            }));

        // GET requests should be allowed without CSRF token
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_csrf_head_requests_allowed() {
        let state = Arc::new(CsrfState::new(CsrfConfig::default()));
        let app = Router::new()
            .route("/test", get(|| async { "OK" }))
            .layer(from_fn(move |req, next| {
                let state = state.clone();
                csrf_protection_middleware(State(state), req, next)
            }));

        // HEAD requests should be allowed without CSRF token
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::HEAD)
                    .uri("/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_csrf_options_requests_allowed() {
        let state = Arc::new(CsrfState::new(CsrfConfig::default()));
        let app = Router::new()
            .route("/test", get(|| async { "OK" }).options(|| async { "OK" }))
            .layer(from_fn(move |req, next| {
                let state = state.clone();
                csrf_protection_middleware(State(state), req, next)
            }));

        // OPTIONS requests should be allowed without CSRF token
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_csrf_valid_token() {
        let state = Arc::new(CsrfState::new(CsrfConfig::default()));
        let token = state.generate_token();

        let app = Router::new()
            .route("/test", post(|| async { "OK" }))
            .layer(from_fn(move |req, next| {
                let state = state.clone();
                csrf_protection_middleware(State(state), req, next)
            }));

        // Request with valid CSRF token should succeed
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/test")
                    .header("X-CSRF-Token", token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_csrf_invalid_token() {
        let state = Arc::new(CsrfState::new(CsrfConfig::default()));

        let app = Router::new()
            .route("/test", post(|| async { "OK" }))
            .layer(from_fn(move |req, next| {
                let state = state.clone();
                csrf_protection_middleware(State(state), req, next)
            }));

        // Request with invalid CSRF token should fail
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/test")
                    .header("X-CSRF-Token", "invalid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_csrf_empty_token() {
        let state = Arc::new(CsrfState::new(CsrfConfig::default()));

        let app = Router::new()
            .route("/test", post(|| async { "OK" }))
            .layer(from_fn(move |req, next| {
                let state = state.clone();
                csrf_protection_middleware(State(state), req, next)
            }));

        // Request with empty CSRF token should fail
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/test")
                    .header("X-CSRF-Token", "")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_csrf_custom_header_name() {
        let config = CsrfConfig {
            header_name: "X-Custom-CSRF-Token".to_string(),
            ..Default::default()
        };
        let state = Arc::new(CsrfState::new(config));
        let token = state.generate_token();

        let app = Router::new()
            .route("/test", post(|| async { "OK" }))
            .layer(from_fn(move |req, next| {
                let state = state.clone();
                csrf_protection_middleware(State(state), req, next)
            }));

        // Request with custom header name should succeed
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/test")
                    .header("X-Custom-CSRF-Token", token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_csrf_token_generation() {
        let state = Arc::new(CsrfState::new(CsrfConfig::default()));

        let token1 = state.generate_token();
        let token2 = state.generate_token();

        // Tokens should be different
        assert_ne!(token1, token2);

        // Tokens should be valid (base64 URL-safe encoded)
        assert!(state.validate_token(&token1));
        assert!(state.validate_token(&token2));

        // Tokens should have expected length (32 bytes = ~43 base64 chars)
        assert!(token1.len() >= 40);
        assert!(token2.len() >= 40);
    }

    #[tokio::test]
    async fn test_csrf_token_validation() {
        let state = Arc::new(CsrfState::new(CsrfConfig::default()));

        // Valid token should pass
        let valid_token = state.generate_token();
        assert!(state.validate_token(&valid_token));

        // Empty token should fail
        assert!(!state.validate_token(""));

        // Too short token should fail
        assert!(!state.validate_token("short"));

        // Token with invalid characters should still be valid if long enough
        // (our validation is basic)
        let long_invalid = "a".repeat(32);
        assert!(state.validate_token(&long_invalid));
    }

    #[tokio::test]
    async fn test_csrf_config_defaults() {
        let config = CsrfConfig::default();

        assert!(config.enabled);
        assert_eq!(config.header_name, "X-CSRF-Token");
        assert_eq!(config.cookie_name, "csrf_token");
        assert_eq!(config.token_length, 32);
        assert!(config.excluded_paths.contains(&"/health".to_string()));
        assert!(config.excluded_paths.contains(&"/metrics".to_string()));
    }
}
