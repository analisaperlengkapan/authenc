use authenc::middleware::auth::{AuthState, AuthUserExt, auth_middleware};
use axum::{
    Router,
    body::Body,
    extract::Request,
    http::{StatusCode, header},
    middleware,
    routing::get,
};
use axum_test::TestServer;
use std::sync::Arc;

// Middleware Integration Tests
// Validating end-to-end integration of the authentication middleware with the router

#[tokio::test]
async fn test_protected_api_access_with_token() {
    // 1. Setup
    // Use a shared secret for testing (in production, this would be a secure key or keypair)
    let secret = "integration-test-secret";

    // Define a protected handler that inspects the injected user context
    async fn protected_handler(req: Request<Body>) -> Result<String, StatusCode> {
        let user = req.auth_user().ok_or(StatusCode::UNAUTHORIZED)?;
        Ok(format!("Hello, {}!", user.id))
    }

    let state = Arc::new(AuthState {
        jwt_secret: secret.to_string(),
    });

    // Build the router with the auth layer manually to ensure type compatibility
    let app = Router::new()
        .route("/api/protected", get(protected_handler))
        .layer(middleware::from_fn_with_state(state, auth_middleware));

    let server = TestServer::new(app).unwrap();

    // 2. Test with Valid Token
    // We need to generate a valid token using the same mechanism the middleware expects.
    // Since the middleware uses the global ED25519_KEYPAIR, we use the standard generator.
    use authenc::utils::crypto::jwt::generate_jwt;
    let valid_token = generate_jwt("test-integration-user").expect("Failed to generate token");

    let response = server
        .get("/api/protected")
        .add_header(header::AUTHORIZATION, format!("Bearer {}", valid_token))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(response.text(), "Hello, test-integration-user!");

    // 3. Test with Invalid Token
    let response = server
        .get("/api/protected")
        .add_header(header::AUTHORIZATION, "Bearer invalid.token.here")
        .await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // 4. Test with Missing Token
    let response = server.get("/api/protected").await;

    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_public_vs_protected_routes_integration() {
    let secret = "integration-test-secret";
    let state = Arc::new(AuthState {
        jwt_secret: secret.to_string(),
    });

    let app = Router::new()
        .route("/api/public", get(|| async { "Public Area" }))
        .route(
            "/api/private",
            get(|req: Request<Body>| async move {
                let user = req.auth_user().ok_or(StatusCode::UNAUTHORIZED)?;
                Ok::<String, StatusCode>(format!("Private Area for {}", user.id))
            }),
        )
        // Note: The middleware logic has a hardcoded list of public endpoints in `is_public_endpoint`.
        // Ideally, we should be able to configure this, but for this integration test,
        // we are testing the `auth_layer` application.
        // Since `is_public_endpoint` is internal and hardcoded to /health*,
        // we expect /api/public to actually *require* auth unless we modify the middleware or the path matches.
        // Let's verify standard behavior: if it's not in the allowlist, it requires auth.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let server = TestServer::new(app).unwrap();

    // /api/public should actually be BLOCKED because it's not in the hardcoded allowlist in the middleware
    // This confirms the "secure by default" behavior
    let response = server.get("/api/public").await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // But /health (which is in the allowlist) should be allowed
    // We need to mount a health route to test this integration
    let app_with_health = Router::new()
        .route("/health", get(|| async { "Health OK" }))
        .layer(middleware::from_fn_with_state(state, auth_middleware));

    let health_server = TestServer::new(app_with_health).unwrap();
    let response = health_server.get("/health").await;
    assert_eq!(response.status_code(), StatusCode::OK);
}
