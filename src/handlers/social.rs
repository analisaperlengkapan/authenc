use crate::app::AppState;
use authenc_services::services::social::{
    SocialLoginService, SocialProvider,
};
use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Redirect},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use authenc_models::models::social_account::CreateSocialAccountRequest;
use authenc_models::models::user::CreateUserRequest;
use authenc_services::services::sso::SsoSessionManager;
use authenc_services::services::stores::social_account_store::SocialAccountStoreTrait;
use authenc_services::services::stores::user_store::UserStoreTrait;
use uuid::Uuid;
use url::Url;

/// Request to initiate social login
#[derive(Deserialize)]
pub struct InitiateLoginRequest {
    /// Social provider to use for authentication
    pub provider: SocialProvider,
    /// URI to redirect to after successful authentication
    pub redirect_uri: String,
    /// Realm ID to initiate login for (optional, defaults to provider realm)
    pub realm_id: Option<String>,
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

/// Handler for initiating social login
pub async fn initiate_login(
    State(state): State<Arc<AppState>>,
    Json(request): Json<InitiateLoginRequest>,
) -> Result<Json<InitiateLoginResponse>, StatusCode> {
    // Generate authorization URL using shared manager
    match state.social_login_manager
        .initiate_login(request.provider, &request.redirect_uri, request.realm_id)
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
) -> Result<impl IntoResponse, StatusCode> {
    // Handle callback and get user profile using shared manager
    let (profile, state_data) = match state.social_login_manager.handle_callback(&query.code, &query.state).await {
        Ok(res) => res,
        Err(e) => {
            tracing::error!("Social login callback error: {}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    // Fix Open Redirect: Validate redirect_uri
    // We expect a relative path. We validate it by ensuring it starts with / (but not //)
    // and that it parses successfully when appended to a dummy base.
    // Also check for URL-encoded open redirect attempts
    let redirect_uri = &state_data.redirect_uri;

    // Decode URI to check for hidden sequences like %2f%2f or %5c
    let decoded_uri = match urlencoding::decode(redirect_uri) {
        Ok(s) => s.into_owned(),
        Err(_) => {
            tracing::error!("Failed to decode redirect URI");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    if !redirect_uri.starts_with('/')
        || redirect_uri.starts_with("//")
        || redirect_uri.contains('\\')
        || decoded_uri.starts_with("//")
        || decoded_uri.contains('\\')
        || Url::parse(&format!("http://localhost{}", redirect_uri)).is_err()
    {
        tracing::error!("Invalid redirect URI in state: {}", redirect_uri);
        return Err(StatusCode::BAD_REQUEST);
    }

    let provider = profile.provider.clone();
    let provider_user_id = profile.provider_user_id.clone();

    // Resolve target realm ID
    // Fix Realm Selection: Use realm_id from state if available, otherwise query DB for provider's realm
    let target_realm_id = if let Some(rid_str) = &state_data.realm_id {
        Uuid::parse_str(rid_str).map_err(|_| {
            tracing::error!("Invalid realm_id in state");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
    } else {
        // Fallback: Query database for the realm associated with this provider
        // This handles cases where InMemoryStore is used (which doesn't infer realm)
        // or when PgStore was used but realm_id wasn't in the state payload for some reason
        let db = &state.database;
        let query = "SELECT realm_id FROM oauth2_provider_configs WHERE alias = $1";
        let row = db.query_opt(query, &[&provider.as_str()]).await.map_err(|e| {
            tracing::error!("Failed to query provider realm: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        if let Some(row) = row {
            row.get::<_, Uuid>(0)
        } else {
            tracing::error!("No realm found for provider: {:?}", provider);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    // Check if social account exists
    let existing_account_opt = state.social_account_store
        .get_social_account_by_provider(&provider, &provider_user_id)
        .await
        .map_err(|e| {
            tracing::error!("Database error: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Fix Cross-Realm Issue: Validate that the existing account belongs to the target realm
    let existing_account = if let Some(account) = existing_account_opt {
        // Fetch user to check realm
        let user_res = state.user_store.get_user(account.user_id).await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        if let Some(user) = user_res {
            if let Some(user_realm) = user.realm_id {
                if user_realm == target_realm_id {
                    Some(account)
                } else {
                    tracing::warn!("Social account found for user {} in realm {}, but login requested for realm {}. Treating as new user/linking for target realm.",
                        user.id, user_realm, target_realm_id);
                    None
                }
            } else {
                // User has no realm? Should not happen in valid state.
                None
            }
        } else {
            // Account points to non-existent user? Orphaned account.
            None
        }
    } else {
        None
    };

    let user_id = if let Some(account) = existing_account {
        account.user_id
    } else {
        // Account does not exist or was ignored due to realm mismatch.

        // Try to find user by email IN THE TARGET REALM
        let existing_user = if let Some(email) = &profile.email {
            state.user_store.get_user_by_email(&target_realm_id, email).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        } else {
            None
        };

        if let Some(user) = existing_user {
             // Fix Account Takeover: Verify email is verified ONLY when linking to EXISTING user
             if !profile.verified_email {
                 tracing::warn!("Cannot link social account with unverified email to existing user: {:?}", profile.email);
                 // We return CONFLICT to indicate that an account exists but we can't link due to security policy
                 return Err(StatusCode::CONFLICT);
             }

             // Link account
             let req = CreateSocialAccountRequest {
                 provider: provider.clone(),
                 provider_user_id: provider_user_id.clone(),
                 display_name: profile.name.clone(),
                 email: profile.email.clone(),
                 profile_picture_url: profile.picture_url.clone(),
                 access_token: None,
                 refresh_token: None,
                 token_expires_at: None,
             };
             // Note: This might fail if the DB enforces global uniqueness on (provider, provider_user_id)
             state.social_account_store.add_social_account(user.id, req).await.map_err(|e| {
                 tracing::error!("Failed to link account: {}", e);
                 // If it failed, it might be because it's already linked to another user (in another realm).
                 // In that case, we can't link it here unless we support one social ID -> multiple users.
                 StatusCode::CONFLICT
             })?;
             user.id
        } else {
             // Create new user in TARGET REALM
             let username = profile.email.clone().unwrap_or_else(|| format!("{}_{}", provider.as_str(), provider_user_id));
             let email = profile.email.clone().unwrap_or_else(|| format!("{}@placeholder.com", Uuid::new_v4()));

             let req = CreateUserRequest {
                 username,
                 email: email.clone(),
                 password: None,
                 first_name: profile.first_name.clone(),
                 last_name: profile.last_name.clone(),
                 phone_number: None,
                 realm_id: Some(target_realm_id),
                 organization_id: None,
                 attributes: None,
                 enabled: Some(true),
                 email_verified: Some(true),
                 require_password_change: Some(false),
             };

             let user = state.user_store.add_user(req).await.map_err(|e| {
                  tracing::error!("Failed to create user: {}", e);
                  StatusCode::INTERNAL_SERVER_ERROR
             })?;

             // If the social profile is verified, update the user status
             if profile.verified_email {
                 let update_req = crate::models::user::UpdateUserRequest {
                     username: None,
                     email: None,
                     first_name: None,
                     last_name: None,
                     phone_number: None,
                     enabled: None,
                     email_verified: Some(true),
                     phone_verified: None,
                     require_password_change: None,
                     attributes: None,
                 };
                 let _ = state.user_store.update_user(user.id, update_req).await;
             }

             // Link account
             let req = CreateSocialAccountRequest {
                 provider: provider.clone(),
                 provider_user_id: provider_user_id.clone(),
                 display_name: profile.name.clone(),
                 email: profile.email.clone(),
                 profile_picture_url: profile.picture_url.clone(),
                 access_token: None,
                 refresh_token: None,
                 token_expires_at: None,
             };
             state.social_account_store.add_social_account(user.id, req).await.map_err(|e| {
                 tracing::error!("Failed to add social account for new user: {}", e);
                 StatusCode::INTERNAL_SERVER_ERROR
             })?;
             user.id
        }
    };

    // Get user again to confirm realm_id (should match target_realm_id)
    let user = state.user_store.get_user(user_id).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?.ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    // Safety check - Realm mismatch
    if user.realm_id != Some(target_realm_id) {
        tracing::error!("Security violation: User realm mismatch during social login");
        return Err(StatusCode::FORBIDDEN);
    }

    // Safety check - User status (disabled/locked)
    if !user.is_active() {
        tracing::warn!("Social login attempt for inactive user: {}", user.id);
        return Err(StatusCode::FORBIDDEN);
    }

    let sso_session = state.sso_session_manager.create_session(
        &user_id.to_string(),
        &target_realm_id.to_string(),
        provider.as_str(),
        1800, // 30 min idle
        36000, // 10 hours max
        false, // remember me
        None, // IP
        None, // User Agent
    ).await.map_err(|e| {
         tracing::error!("Failed to create SSO session: {}", e);
         StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let cookie_value = state.sso_cookie_manager.generate_cookie(
        &sso_session.session_id,
        &user_id.to_string(),
        &sso_session.realm_id,
        36000
    ).map_err(|e| {
         tracing::error!("Failed to generate cookie: {}", e);
         StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Generate response with cookie and redirect
    let mut response = Redirect::to(redirect_uri).into_response();

    // Add Set-Cookie header
    use axum::http::header::SET_COOKIE;
    let cookie_header_val = state.sso_cookie_manager.generate_set_cookie_header(&cookie_value, 36000);

    if let Ok(header_value) = cookie_header_val.parse() {
        response.headers_mut().insert(SET_COOKIE, header_value);
    } else {
        tracing::error!("Failed to parse cookie header value");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(response)
}

/// Create social login routes
pub fn create_social_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/social/initiate", post(initiate_login))
        .route("/social/callback", get(social_callback))
}
