use crate::database::Database;
use crate::services::social::{
    OAuthConfig, SocialLoginManager, SocialLoginService, SocialProvider,
};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct InitiateLoginRequest {
    pub provider: SocialProvider,
    pub redirect_uri: String,
}

#[derive(Serialize)]
pub struct InitiateLoginResponse {
    pub authorization_url: String,
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

#[derive(Serialize)]
pub struct SocialUserProfile {
    pub provider: SocialProvider,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub raw_profile: serde_json::Value,
}

/// Handler for initiating social login
pub async fn initiate_login(
    State(_db): State<Arc<Database>>,
    Json(request): Json<InitiateLoginRequest>,
) -> Result<Json<InitiateLoginResponse>, StatusCode> {
    // Create social login manager with configurations
    let mut manager = SocialLoginManager::new();

    // Register providers based on environment variables
    if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("GOOGLE_CLIENT_ID"),
        std::env::var("GOOGLE_CLIENT_SECRET"),
    ) {
        let google_config = OAuthConfig {
            client_id,
            client_secret,
            redirect_uri: std::env::var("GOOGLE_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:3000/auth/social/callback".to_string()),
            authorization_url: "https://accounts.google.com/o/oauth2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            provider: SocialProvider::Google,
        };
        manager.register_provider(google_config);
    }

    if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("GITHUB_CLIENT_ID"),
        std::env::var("GITHUB_CLIENT_SECRET"),
    ) {
        let github_config = OAuthConfig {
            client_id,
            client_secret,
            redirect_uri: std::env::var("GITHUB_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:3000/auth/social/callback".to_string()),
            authorization_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            user_info_url: "https://api.github.com/user".to_string(),
            scopes: vec!["user:email".to_string()],
            provider: SocialProvider::GitHub,
        };
        manager.register_provider(github_config);
    }

    if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("FACEBOOK_CLIENT_ID"),
        std::env::var("FACEBOOK_CLIENT_SECRET"),
    ) {
        let facebook_config = OAuthConfig {
            client_id,
            client_secret,
            redirect_uri: std::env::var("FACEBOOK_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:3000/auth/social/callback".to_string()),
            authorization_url: "https://www.facebook.com/v12.0/dialog/oauth".to_string(),
            token_url: "https://graph.facebook.com/v12.0/oauth/access_token".to_string(),
            user_info_url: "https://graph.facebook.com/me".to_string(),
            scopes: vec!["email".to_string(), "public_profile".to_string()],
            provider: SocialProvider::Facebook,
        };
        manager.register_provider(facebook_config);
    }

    // Generate authorization URL
    match manager
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
    State(_db): State<Arc<Database>>,
    Query(query): Query<CallbackQuery>,
) -> Result<Json<SocialUserProfile>, StatusCode> {
    // Create social login manager with configurations
    let mut manager = SocialLoginManager::new();

    // Register providers based on environment variables
    if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("GOOGLE_CLIENT_ID"),
        std::env::var("GOOGLE_CLIENT_SECRET"),
    ) {
        let google_config = OAuthConfig {
            client_id,
            client_secret,
            redirect_uri: std::env::var("GOOGLE_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:3000/auth/social/callback".to_string()),
            authorization_url: "https://accounts.google.com/o/oauth2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
            scopes: vec![
                "openid".to_string(),
                "email".to_string(),
                "profile".to_string(),
            ],
            provider: SocialProvider::Google,
        };
        manager.register_provider(google_config);
    }

    if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("GITHUB_CLIENT_ID"),
        std::env::var("GITHUB_CLIENT_SECRET"),
    ) {
        let github_config = OAuthConfig {
            client_id,
            client_secret,
            redirect_uri: std::env::var("GITHUB_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:3000/auth/social/callback".to_string()),
            authorization_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            user_info_url: "https://api.github.com/user".to_string(),
            scopes: vec!["user:email".to_string()],
            provider: SocialProvider::GitHub,
        };
        manager.register_provider(github_config);
    }

    if let (Ok(client_id), Ok(client_secret)) = (
        std::env::var("FACEBOOK_CLIENT_ID"),
        std::env::var("FACEBOOK_CLIENT_SECRET"),
    ) {
        let facebook_config = OAuthConfig {
            client_id,
            client_secret,
            redirect_uri: std::env::var("FACEBOOK_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:3000/auth/social/callback".to_string()),
            authorization_url: "https://www.facebook.com/v12.0/dialog/oauth".to_string(),
            token_url: "https://graph.facebook.com/v12.0/oauth/access_token".to_string(),
            user_info_url: "https://graph.facebook.com/me".to_string(),
            scopes: vec!["email".to_string(), "public_profile".to_string()],
            provider: SocialProvider::Facebook,
        };
        manager.register_provider(facebook_config);
    }

    // Handle callback and get user profile
    match manager.handle_callback(&query.code, &query.state).await {
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
pub fn create_social_routes() -> Router<Arc<Database>> {
    Router::new()
        .route("/social/initiate", post(initiate_login))
        .route("/social/callback", get(social_callback))
}
