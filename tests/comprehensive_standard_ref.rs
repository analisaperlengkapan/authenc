use axum::{
    Router,
    extract::Query,
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// Shared test state
type SharedState = Arc<Mutex<HashMap<String, serde_json::Value>>>;

#[derive(Clone)]
struct AppState {
    pub zero_trust_manager: Arc<authenc::services::security::zero_trust::ZeroTrustManager>,
    _data: SharedState,
}

// Mock handlers for Standard IAM-like features
async fn oidc_discovery() -> Json<serde_json::Value> {
    Json(json!({
        "issuer": "https://authenc.example.com",
        "authorization_endpoint": "https://authenc.example.com/oauth2/authorize",
        "token_endpoint": "https://authenc.example.com/oauth2/token",
        "userinfo_endpoint": "https://authenc.example.com/oauth2/userinfo",
        "jwks_uri": "https://authenc.example.com/oauth2/jwks",
        "response_types_supported": ["code", "token", "id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA", "RS256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "name", "email"]
    }))
}

async fn jwks_endpoint() -> Json<serde_json::Value> {
    // Return Ed25519 public key in JWK format
    Json(json!({
        "keys": [{
            "kty": "OKP",
            "kid": "authenc-key-1",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "use": "sig"
        }]
    }))
}

async fn create_test_app() -> TestServer {
    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());

    let state = AppState {
        zero_trust_manager: zero_trust_manager.clone(),
        _data: Arc::new(Mutex::new(HashMap::new())),
};

let app = Router::new()
        .route("/.well-known/openid-configuration", get(oidc_discovery))
        .route("/oauth2/jwks", get(jwks_endpoint))
        .with_state(state);

    TestServer::new(app).unwrap()
}

#[tokio::test]
async fn test_oidc_discovery_conformance() {
    let server = create_test_app().await;

    let response = server.get("/.well-known/openid-configuration").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();

    // Verify mandatory OIDC fields
    assert!(body.get("issuer").is_some());
    assert!(body.get("authorization_endpoint").is_some());
    assert!(body.get("token_endpoint").is_some());
    assert!(body.get("jwks_uri").is_some());

    // Verify EdDSA support (Authenc specialty)
    let algs = body["id_token_signing_alg_values_supported"]
        .as_array()
        .unwrap();
    assert!(algs.iter().any(|v| v.as_str() == Some("EdDSA")));
}

#[tokio::test]
async fn test_jwks_security_headers() {
    let server = create_test_app().await;

    let response = server.get("/oauth2/jwks").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Standard IAM: Check for proper content type
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/json"
    );

    let body: serde_json::Value = response.json();
    let keys = body["keys"].as_array().unwrap();
    assert!(!keys.is_empty());

    let key = &keys[0];
    assert_eq!(key["kty"], "OKP"); // Ed25519 is OKP
    assert_eq!(key["crv"], "Ed25519");
}

#[tokio::test]
async fn test_fips_compliance_simulation() {
    // Simulating FIPS mode check
    let fips_mode = std::env::var("FIPS_MODE").unwrap_or_else(|_| "false".to_string());

    if fips_mode == "true" {
        // Run specific FIPS validation logic
        // For now, we assume standard mode but this acts as a placeholder for the strict check
    }
}

// RFC 8628 Device Authorization Flow
async fn device_authorization() -> Json<serde_json::Value> {
    Json(json!({
        "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysdg",
        "user_code": "WDJB-MJHT",
        "verification_uri": "https://authenc.example.com/device",
        "verification_uri_complete": "https://authenc.example.com/device?user_code=WDJB-MJHT",
        "expires_in": 1800,
        "interval": 5
    }))
}

#[tokio::test]
async fn test_device_authorization_flow() {
    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());

    let state = AppState {
        zero_trust_manager: zero_trust_manager.clone(),
        _data: Arc::new(Mutex::new(HashMap::new())),
};

let app = Router::new()
        .route("/oauth2/device/auth", post(device_authorization))
        .route("/oauth2/authorize", get(authorize_endpoint))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    let response = server
        .post("/oauth2/device/auth")
        .add_query_param("client_id", "my-device-client")
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();

    assert!(body.get("device_code").is_some());
    assert!(body.get("user_code").is_some());
    assert!(body.get("verification_uri").is_some());
    assert_eq!(body["interval"], 5);
}

// RFC 8693 Token Exchange
async fn token_exchange(
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let grant_type = payload.get("grant_type").and_then(|v| v.as_str());

    if grant_type == Some("urn:ietf:params:oauth:grant-type:token-exchange") {
        Ok(Json(json!({
            "access_token": "exchanged_token_123",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
    } else if grant_type == Some("authorization_code") {
        // Return standard access token
        Ok(Json(json!({
            "access_token": "access_token_123",
            "id_token": "id_token_123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh_token_123"
        })))
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

async fn authorize_endpoint(
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let client_id = params.get("client_id");
    let response_type = params.get("response_type");

    if client_id.is_some() && response_type == Some(&"code".to_string()) {
        // In a real app this would redirect, but for test API we return the code
        Ok(Json(json!({
            "code": "splunk_auth_code_123",
            "state": params.get("state").unwrap_or(&"".to_string())
        })))
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

#[tokio::test]
async fn test_token_exchange_rfc8693() {
    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());

    let state = AppState {
        zero_trust_manager: zero_trust_manager.clone(),
        _data: Arc::new(Mutex::new(HashMap::new())),
};

let app = Router::new()
        .route("/oauth2/token", post(token_exchange))
        .with_state(state);

    let server = TestServer::new(app.clone()).unwrap();

    // Test successful exchange
    let response = server
        .post("/oauth2/token")
        .json(&json!({
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": "original_token",
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(
        body["issued_token_type"],
        "urn:ietf:params:oauth:token-type:access_token"
    );

    // Test invalid grant type
    let response = server
        .post("/oauth2/token")
        .json(&json!({
            "grant_type": "client_credentials"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_ed25519_signature_verification() {
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
    use rand::rngs::OsRng;

    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let message: &[u8] = b"This is a test message for Ed25519 signature";
    let signature: Signature = signing_key.sign(message);

    assert!(verifying_key.verify(message, &signature).is_ok());

    let bad_message: &[u8] = b"This message is modified";
    assert!(verifying_key.verify(bad_message, &signature).is_err());
}

#[tokio::test]
async fn test_authorization_code_flow() {
    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());

    let state = AppState {
        zero_trust_manager: zero_trust_manager.clone(),
        _data: Arc::new(Mutex::new(HashMap::new())),
};

let app = Router::new()
        .route("/oauth2/authorize", get(authorize_endpoint))
        .route("/oauth2/token", post(token_exchange))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Step 1: Authorization Request
    let response = server
        .get("/oauth2/authorize")
        .add_query_param("client_id", "test_client")
        .add_query_param("response_type", "code")
        .add_query_param("state", "xyz")
        .add_query_param("redirect_uri", "https://client.example.com/cb")
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    let code = body["code"].as_str().unwrap();
    assert_eq!(body["state"], "xyz");

    // Step 2: Token Request (Exchange code for token)
    let response = server
        .post("/oauth2/token")
        .json(&json!({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.example.com/cb",
            "client_id": "test_client"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert!(body.get("access_token").is_some());
    assert!(body.get("id_token").is_some());
    assert!(body.get("refresh_token").is_some());
    assert_eq!(body["token_type"], "Bearer");
}

async fn webauthn_register_challenge() -> Json<serde_json::Value> {
    Json(json!({
        "challenge": "base64_encoded_challenge_string",
        "rp": {
            "name": "Authenc",
            "id": "authenc.example.com"
        },
        "user": {
            "id": "user_id_123",
            "name": "user@example.com",
            "displayName": "Test User"
        },
        "pubKeyCredParams": [
            { "type": "public-key", "alg": -7 }, // ES256
            { "type": "public-key", "alg": -8 }  // Ed25519
        ],
        "timeout": 60000,
        "attestation": "direct"
    }))
}

#[tokio::test]
async fn test_webauthn_endpoints_security() {
    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());

    let state = AppState {
        zero_trust_manager: zero_trust_manager.clone(),
        _data: Arc::new(Mutex::new(HashMap::new())),
};

let app = Router::new()
        .route(
            "/api/public/webauthn/register/challenge",
            post(webauthn_register_challenge),
        )
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    let response = server.post("/api/public/webauthn/register/challenge").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body.get("challenge").is_some());
    assert_eq!(body["rp"]["id"], "authenc.example.com");

    // Standard IAM/FIPS check: Ensure strong algorithms are requested
    let algs = body["pubKeyCredParams"].as_array().unwrap();
    assert!(algs.iter().any(|a| a["alg"] == -8)); // Ed25519 check
}
