use crate::app::AppState;
use crate::services::social::{
    SocialLoginService, SocialProvider,
};
use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Request to initiate social login
#[derive(Deserialize)]
pub struct InitiateLoginRequest {
    /// Social provider to use for authentication
    pub provider: SocialProvider,
    /// URI to redirect to after successful authentication
    pub redirect_uri: String,
}

/// Response containing authorization URL for social login
#[derive(Serialize)]
pub struct InitiateLoginResponse {
    /// URL to redirect user to for social provider authentication
    pub authorization_url: String,
}

/// Query parameters from social provider callback
#[derive(Deserialize)]
pub struct CallbackQuery {
    /// Authorization code from social provider
    pub code: String,
    /// State parameter for CSRF protection
    pub state: String,
}

/// Social user profile information
#[derive(Serialize)]
pub struct SocialUserProfile {
    /// Social provider that authenticated the user
    pub provider: SocialProvider,
    /// User ID from the social provider
    pub provider_user_id: String,
    /// Email address from social provider
    pub email: Option<String>,
    /// Display name from social provider
    pub name: Option<String>,
    /// Avatar/profile image URL
    pub avatar_url: Option<String>,
    /// Raw profile data from social provider
    pub raw_profile: serde_json::Value,
}

/// Handler for initiating social login
pub async fn initiate_login(
    State(state): State<Arc<AppState>>,
    Json(request): Json<InitiateLoginRequest>,
) -> Result<Json<InitiateLoginResponse>, StatusCode> {
    // Generate authorization URL using shared manager
    match state.social_login_manager
        .initiate_login(request.provider, &request.redirect_uri)
        .await
    {
        Ok(url) => Ok(Json(InitiateLoginResponse {
            authorization_url: url,
        })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Handler for social login callback
pub async fn social_callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<CallbackQuery>,
) -> Result<Json<SocialUserProfile>, StatusCode> {
    // Handle callback and get user profile using shared manager
    match state.social_login_manager.handle_callback(&query.code, &query.state).await {
        Ok(profile) => {
            // Convert to our response format
            let response_profile = SocialUserProfile {
                provider: profile.provider,
                provider_user_id: profile.provider_user_id,
                email: profile.email,
                name: profile.name,
                avatar_url: profile.picture_url,
                raw_profile: profile.raw_data,
            };
            Ok(Json(response_profile))
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Create social login routes
pub fn create_social_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/social/initiate", post(initiate_login))
        .route("/social/callback", get(social_callback))
}
