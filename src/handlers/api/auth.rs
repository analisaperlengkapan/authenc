use crate::error::AuthencError;
use authenc_services::services::stores::user_store::UserStoreTrait;
use authenc_crypto::utils::crypto::jwt;
use authenc_crypto::utils::crypto::password::verify_password;
use axum::{Router, extract::{ConnectInfo, State}, response::Json, routing::post};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;
use chrono::{Utc, Duration};

/// Create authentication routes
pub fn create_auth_routes() -> Router<Arc<crate::app::AppState>> {
    Router::new()
        .route("/login", post(login))
        .route("/test-login", post(test_login))
}

#[derive(Deserialize)]
/// Request payload for user login
pub struct LoginRequest {
    /// The username for authentication
    pub username: String,
    /// The password for authentication
    pub password: String,
    /// The realm the user belongs to
    pub realm: String,
}

#[derive(Serialize)]
/// Response payload for successful login
pub struct LoginResponse {
    /// JWT access token for authenticated requests
    pub access_token: String,
    /// Success message
    pub message: String,
}

/// Authenticate a user with username and password
pub async fn login(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<crate::app::AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AuthencError> {
    let ip = addr.ip().to_string();
    let rate_limit_key = format!("login:{}", ip);

    // 1. IP-based rate limiting
    match state.brute_force_protector.register_attempt(&rate_limit_key) {
        Ok(true) => {
            tracing::warn!("Rate limit exceeded for login request from IP: {}", ip);
            return Err(AuthencError::RateLimitExceeded);
        }
        Err(e) => {
            tracing::error!("Brute force protector error: {}", e);
            // Continue on error to avoid locking everyone out, but log it
        }
        _ => {}
    }

    // Determine realm_id. In a real scenario, this should come from the request (header/param)
    // or defaulted to master realm if not present.
    // For this endpoint, let's assume master realm if `req.realm` matches, otherwise error or lookup realm by name.
    // req.realm is a string name. We need to resolve it to UUID.
    // Assuming "master" or specific ID passed as string.

    let realm_id = if req.realm == "master" {
        Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap() // Safe unwrap for constant
    } else {
        // Here we should look up realm by name. Since we don't have realm store in state yet (or exposed easily),
        // we might fail or try to parse as UUID.
        if let Ok(id) = Uuid::parse_str(&req.realm) {
            id
        } else if let Some(realm_obj) = state.realm_store.get_by_name(&req.realm) {
            realm_obj.id
        } else {
            return Err(AuthencError::validation("Invalid realm"));
        }
    };

    // Get user by username from database, filtering by realm
    let user = state
        .user_store
        .get_user_by_username(&realm_id, &req.username)
        .await?
        .ok_or_else(|| AuthencError::unauthorized("Invalid credentials"))?;

    // 2. Account lockout check
    if user.account_locked {
        if let Some(until) = user.account_locked_until {
            if until > Utc::now() {
                tracing::warn!("Attempted login to locked account: {}", user.username);
                return Err(AuthencError::forbidden("Account is temporarily locked"));
            } else {
                // Lock has expired
                let _ = state.user_store.unlock_account(user.id).await;
            }
        } else {
            tracing::warn!("Attempted login to permanently locked account: {}", user.username);
            return Err(AuthencError::forbidden("Account is locked"));
        }
    }

    // Verify password
    if let Some(ref password_hash) = user.password_hash {
        if verify_password(password_hash, &req.password)
            .await
            .unwrap_or(false)
        {
            // Reset failed attempts on success
            let _ = state.user_store.record_login(user.id).await;

            let token = jwt::generate_jwt(&user.id.to_string())
                .map_err(|_| AuthencError::internal("Token generation failed"))?;
            let message = format!("Login successful for user {}", user.username);

            // Fire successful login event
            let event = crate::services::events::EventBuilder::new(
                crate::models::events::EventType::Login,
                req.realm.clone(),
            )
            .user_id(user.id.to_string())
            .client_id("api".to_string()) // API login
            .detail("method", "password")
            .build();

            if let Err(e) = state.event_manager.write().await.fire_event(event).await {
                tracing::error!("Failed to fire login event: {}", e);
            }

            return Ok(Json(LoginResponse {
                access_token: token,
                message,
            }));
        }
    }

    // 3. Handle failed attempt
    let failed_attempts = state
        .user_store
        .record_failed_login(user.id)
        .await
        .unwrap_or(0);

    if failed_attempts >= state.config.security.brute_force_max_attempts as i32 {
        let lockout_duration = state.config.security.brute_force_window_seconds;
        let until = Utc::now() + Duration::seconds(lockout_duration as i64);
        let _ = state.user_store.lock_account(user.id, Some(until)).await;
        tracing::warn!(
            "Account locked due to too many failed attempts: {} ({} attempts)",
            user.username,
            failed_attempts
        );
    }

    // Fire login error event
    let event = crate::services::events::EventBuilder::new(
        crate::models::events::EventType::LoginError,
        req.realm.clone(),
    )
    .user_id(user.id.to_string())
    .client_id("api".to_string())
    .detail("method", "password")
    .detail("reason", "invalid_credentials")
    .build();

    if let Err(e) = state.event_manager.write().await.fire_event(event).await {
        tracing::error!("Failed to fire login error event: {}", e);
    }

    Err(AuthencError::unauthorized("Invalid credentials"))
}

/// Test login endpoint for development - creates a test user if it doesn't exist
pub async fn test_login(
    State(state): State<Arc<crate::app::AppState>>,
) -> Result<Json<LoginResponse>, AuthencError> {
    // Only allow in development mode or if explicitly enabled
    if std::env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()) == "production" {
        return Err(AuthencError::unauthorized("Test login disabled in production"));
    }

    // Use master realm for test
    let realm_id = Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap();

    // Check if test user exists
    let test_user = state
        .user_store
        .get_user_by_username(&realm_id, "testuser")
        .await?
        .ok_or_else(|| AuthencError::internal("Test user not found"))?;

    // Generate JWT token
    let token = jwt::generate_jwt(&test_user.id.to_string())
        .map_err(|_| AuthencError::internal("Token generation failed"))?;
    let message = format!("Test login successful for user {}", test_user.username);

    // Fire successful login event
    let event = crate::services::events::EventBuilder::new(
        crate::models::events::EventType::Login,
        "test-realm".to_string(),
    )
    .user_id(test_user.id.to_string())
    .client_id("api".to_string())
    .detail("method", "test")
    .build();

    if let Err(e) = state.event_manager.write().await.fire_event(event).await {
        tracing::error!("Failed to fire test login event: {}", e);
    }

    Ok(Json(LoginResponse {
        access_token: token,
        message,
    }))
}
