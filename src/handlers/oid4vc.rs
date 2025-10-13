use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use crate::app::AppState;
use crate::services::oid4vc::{
    CredentialAuthorizationRequest, CredentialRequest, CredentialTokenRequest, Oid4VcService,
};

/// Create OID4VC router
pub fn create_oid4vc_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/.well-known/openid-credential-issuer",
            get(get_issuer_metadata),
        )
        .route("/authorize", get(handle_authorization))
        .route("/token", post(handle_token))
        .route("/credentials", post(issue_credential))
}

/// Get credential issuer metadata
/// GET /.well-known/openid-credential-issuer
async fn get_issuer_metadata(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match state.oid4vc_service.get_issuer_metadata().await {
        Ok(metadata) => Ok(Json(json!(metadata))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e})))),
    }
}

/// Handle authorization request
/// GET /authorize
async fn handle_authorization(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Parse authorization request from query parameters
    let request = CredentialAuthorizationRequest {
        response_type: params.get("response_type").cloned().unwrap_or_default(),
        client_id: params.get("client_id").cloned().unwrap_or_default(),
        redirect_uri: params.get("redirect_uri").cloned().unwrap_or_default(),
        scope: params.get("scope").cloned().unwrap_or_default(),
        state: params.get("state").cloned(),
        authorization_details: vec![], // Parse from params if needed
        nonce: params.get("nonce").cloned(),
        code_challenge: params.get("code_challenge").cloned(),
        code_challenge_method: params.get("code_challenge_method").cloned(),
    };

    match state
        .oid4vc_service
        .handle_authorization_request(request)
        .await
    {
        Ok(code) => Ok(Json(json!({
            "code": code,
            "state": params.get("state")
        }))),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

/// Handle token request
/// POST /token
async fn handle_token(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CredentialTokenRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match state.oid4vc_service.handle_token_request(request).await {
        Ok(token_response) => Ok(Json(serde_json::to_value(token_response).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("Serialization error: {}", e)})),
            )
        })?)),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

/// Issue credential
/// POST /credentials
async fn issue_credential(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(request): Json<CredentialRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Extract access token from Authorization header
    let access_token = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "Missing or invalid access token"})),
            )
        })?;

    match state
        .oid4vc_service
        .issue_credential(request, access_token)
        .await
    {
        Ok(credential_response) => Ok(Json(json!(credential_response))),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

/// Verify credential endpoint
/// POST /credentials/verify
pub async fn verify_credential(
    State(state): State<Arc<AppState>>,
    Json(credential): Json<crate::services::oid4vc::VerifiableCredential>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match state.oid4vc_service.verify_credential(&credential).await {
        Ok(is_valid) => Ok(Json(json!({
            "valid": is_valid
        }))),
        Err(e) => Err((StatusCode::BAD_REQUEST, Json(json!({"error": e})))),
    }
}

/// Create verifiable presentation router
pub fn create_vp_router() -> Router<Arc<AppState>> {
    Router::new().route("/credentials/verify", post(verify_credential))
}
