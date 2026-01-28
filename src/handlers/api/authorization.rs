use axum::{
    extract::{State, Json},
    http::StatusCode,
    response::IntoResponse,
    Router,
    routing::post,
};
use std::sync::Arc;
use crate::app::AppState;
use crate::services::authorization::{AuthorizationContext, AuthorizationService, Decision};
use crate::error::AuthencError;

/// Create authorization routes
pub fn create_authorization_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/authz/evaluate", post(evaluate_policy))
}

/// Evaluate authorization policy
#[axum::debug_handler]
pub async fn evaluate_policy(
    State(state): State<Arc<AppState>>,
    Json(context): Json<AuthorizationContext>,
) -> Result<impl IntoResponse, AuthencError> {
    let decision = state.authorization_manager.evaluate(&context).await
        .map_err(|e| AuthencError::internal(format!("Authorization evaluation failed: {}", e)))?;

    Ok(Json(decision))
}
