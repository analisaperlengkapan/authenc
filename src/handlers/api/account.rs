use axum::{
    extract::{Extension, Path, State},
    http::{header, StatusCode},
    response::{Json, Response},
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Digest;
use std::sync::Arc;
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AuthencError;
use crate::models::session::SessionResponse;
use crate::models::social_account::SocialAccountResponse;
use crate::models::user::{UpdateUserRequest, UserResponse};
use crate::services::oidc_client_store::OidcClientStore;
use crate::services::pg_audit_log_store::PgAuditLogStore;
use crate::services::session_store::SessionStore;
use crate::services::social::SocialProvider;
use crate::services::stores::consent_store::ConsentStoreTrait;
use crate::services::stores::social_account_store::{SocialAccountStore, SocialAccountStoreTrait};
use crate::services::stores::user_store::UserStore;
use crate::services::stores::user_store::UserStoreTrait;
use crate::services::totp_store::TotpStore;

/// Request to setup TOTP
#[derive(Debug, Deserialize, Serialize)]
pub struct TotpSetupRequest {
    /// Optional user-provided name for the TOTP device
    pub device_name: Option<String>,
}

/// Response for TOTP setup
#[derive(Debug, Deserialize, Serialize)]
pub struct TotpSetupResponse {
    /// The base32-encoded TOTP secret
    pub secret: String,
    /// QR code URL for easy setup
    pub qr_code_url: String,
    /// Backup codes for recovery
    pub backup_codes: Vec<String>,
}

/// Response for TOTP status
#[derive(Debug, Deserialize, Serialize)]
pub struct TotpStatusResponse {
    /// Whether TOTP is enabled
    pub enabled: bool,
    /// When TOTP was configured (if enabled)
    pub configured_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Response for user consent information
#[derive(Debug, Deserialize, Serialize)]
pub struct ConsentResponse {
    /// Client ID that has consent
    pub client_id: String,
    /// Client name
    pub client_name: String,
    /// Granted scopes
    pub scopes: Vec<String>,
    /// When consent was granted
    pub granted_at: String,
    /// When consent expires (if applicable)
    pub expires_at: Option<String>,
}

/// Create account management routes for user self-service
pub fn create_account_routes() -> Router<(
    Arc<UserStore>,
    Arc<SessionStore>,
    Arc<OidcClientStore>,
    Arc<TotpStore>,
    Arc<PgAuditLogStore>,
    Arc<SocialAccountStore>,
)> {
    Router::new()
        .route("/account", get(get_account_profile))
        .route("/account", put(update_account_profile))
        .route("/account/sessions", get(get_account_sessions))
        .route(
            "/account/sessions/{session_id}",
            delete(revoke_account_session),
        )
        .route("/account/applications", get(get_account_applications))
        .route(
            "/account/applications/{client_id}",
            delete(revoke_application_access),
        )
        .route("/account/export", get(export_account_data))
        .route("/account", delete(delete_account))
        .route("/account/totp/setup", post(setup_totp))
        .route("/account/totp", get(get_totp_status))
        .route("/account/totp", delete(disable_totp))
        .route("/account/social", get(get_linked_social_accounts))
        .route("/account/social/{provider}", delete(unlink_social_account))
}

/// Create consent management routes
pub fn create_consent_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/account/consents", get(get_user_consents))
        .route("/account/consents/{client_id}", delete(revoke_consent))
}

/// Get current user's account profile
pub async fn get_account_profile(
    State((user_store, _, _, _, _, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
        Arc<SocialAccountStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
) -> Result<Json<UserResponse>, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    let user = user_store
        .get_user(user_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

    Ok(Json(user.into()))
}

/// Update current user's account profile
pub async fn update_account_profile(
    State((user_store, _, _, _, _, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
        Arc<SocialAccountStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
    Json(update_request): Json<UpdateUserRequest>,
) -> Result<StatusCode, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    user_store.update_user(user_id, update_request).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get current user's active sessions
pub async fn get_account_sessions(
    State((_, session_store, _, _, _, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
        Arc<SocialAccountStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
) -> Result<Json<Vec<SessionResponse>>, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    let sessions = session_store.get_user_sessions(user_id).await?;

    let response = sessions.into_iter().map(|s| s.into()).collect();

    Ok(Json(response))
}

/// Revoke a specific session
pub async fn revoke_account_session(
    State((_, session_store, _, _, _, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
        Arc<SocialAccountStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Verify the session belongs to the current user
    let session = session_store
        .get_session(session_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("Session not found"))?;

    if session.user_id != user_id {
        return Err(AuthencError::forbidden(
            "Cannot revoke session belonging to another user",
        ));
    }

    session_store.delete_session(session_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Application response for account console
#[derive(Debug, Serialize)]
pub struct ApplicationResponse {
    /// The client ID of the application
    pub client_id: String,
    /// The name of the application
    pub name: String,
    /// When the application was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the application was last accessed
    pub last_access: Option<chrono::DateTime<chrono::Utc>>,
}

/// Get current user's authorized applications
pub async fn get_account_applications(
    State((_, _, oidc_client_store, _, _, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
        Arc<SocialAccountStore>,
    )>,
    Extension(_auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
) -> Result<Json<Vec<ApplicationResponse>>, AuthencError> {
    // For now, return all clients as "authorized applications"
    // In a production system, this should only return clients that have active tokens/consents
    let clients = oidc_client_store.all().await?;

    let applications = clients
        .into_iter()
        .map(|client| ApplicationResponse {
            client_id: client.client_id,
            name: client.name,
            created_at: client.created_at,
            last_access: Some(client.updated_at),
        })
        .collect();

    Ok(Json(applications))
}

/// Revoke access to a specific application
pub async fn revoke_application_access(
    State((user_store, _, _, _, _, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
        Arc<SocialAccountStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
    Path(client_id): Path<String>,
) -> Result<StatusCode, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Create consent store from the same database
    let consent_store = Arc::new(crate::services::stores::consent_store::ConsentStore::new(
        user_store.database().clone(),
    ));

    // Revoke consent for the client
    consent_store.revoke_consent(user_id, &client_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Export current user's account data
pub async fn export_account_data(
    State((user_store, session_store, oidc_client_store, _, audit_log_store, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
        Arc<SocialAccountStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
) -> Result<Response<String>, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Get user profile
    let user = user_store
        .get_user(user_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

    // Get user sessions
    let sessions = session_store.get_user_sessions(user_id).await?;

    // Get authorized applications
    let applications = oidc_client_store.all().await?;

    // Create export data structure
    let export_data = json!({
        "user_profile": user,
        "sessions": sessions,
        "authorized_applications": applications,
        "export_timestamp": chrono::Utc::now(),
        "export_version": "1.0"
    });

    let json_string = serde_json::to_string_pretty(&export_data)
        .map_err(|_| AuthencError::internal("Failed to serialize export data"))?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"account-data.json\"",
        )
        .body(json_string)
        .map_err(|_| AuthencError::internal("Failed to create response"))?;

    // Log the data export for audit purposes
    let audit_log = crate::models::audit_log::AuditLog {
        timestamp: chrono::Utc::now(),
        event: "ACCOUNT_DATA_EXPORT".to_string(),
        user_id: Some(auth_user.id.clone()),
        client_id: None,
        status: "success".to_string(),
        detail: Some(format!(
            "User exported account data containing profile, {} sessions, and {} applications",
            sessions.len(),
            applications.len()
        )),
    };

    if let Err(e) = audit_log_store.add_log(&audit_log).await {
        // Log the error but don't fail the export
        eprintln!("Failed to log account data export: {}", e);
    }

    Ok(response)
}

/// Delete current user's account
pub async fn delete_account(
    State((user_store, _session_store, _oidc_client_store, totp_store, audit_log_store, _)): State<
        (
            Arc<UserStore>,
            Arc<SessionStore>,
            Arc<OidcClientStore>,
            Arc<TotpStore>,
            Arc<PgAuditLogStore>,
            Arc<SocialAccountStore>,
        ),
    >,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
) -> Result<StatusCode, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Get user info before deletion for logging
    let _user = user_store
        .get_user(user_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

    // Revoke all active sessions for the user
    _session_store.delete_user_sessions(user_id).await?;

    // Revoke all OAuth2 tokens for the user
    crate::database::operations::oauth2::revoke_user_tokens(user_store.database(), user_id).await?;

    // Delete all WebAuthn credentials for the user
    crate::database::operations::webauthn::delete_user_credentials(user_store.database(), user_id)
        .await?;

    // Remove TOTP secret
    totp_store
        .remove_secret(&user_id.to_string())
        .map_err(|e| AuthencError::internal(format!("Failed to remove TOTP secret: {}", e)))?;

    // Delete the user account
    user_store.delete_user(user_id).await?;

    // Log the account deletion for audit purposes
    let audit_log = crate::models::audit_log::AuditLog {
        timestamp: chrono::Utc::now(),
        event: "ACCOUNT_DELETION".to_string(),
        user_id: Some(auth_user.id.clone()),
        client_id: None,
        status: "success".to_string(),
        detail: Some(
            "User account deleted with complete data cleanup (sessions, tokens, credentials, TOTP)"
                .to_string(),
        ),
    };

    if let Err(e) = audit_log_store.add_log(&audit_log).await {
        // Log the error but don't fail the deletion
        eprintln!("Failed to log account deletion: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Setup TOTP for current user
#[axum::debug_handler]
pub async fn setup_totp(
    State((_, _, _, totp_store, audit_log_store, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
        Arc<SocialAccountStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
    Json(_request): Json<TotpSetupRequest>,
) -> Result<Json<TotpSetupResponse>, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Generate TOTP secret
    use rand::{rngs::OsRng, RngCore};
    let mut rng = OsRng;
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let secret = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret_bytes);

    // Store the secret
    totp_store
        .set_secret(&user_id.to_string(), &secret)
        .map_err(|e| AuthencError::internal(format!("Failed to store TOTP secret: {}", e)))?;

    // Generate QR code URL
    let qr_code_url = format!(
        "otpauth://totp/Authenc:{}?secret={}&issuer=Authenc",
        auth_user.email, secret
    );

    // Generate backup codes
    let backup_codes: Vec<String> = (0..10)
        .map(|_| {
            let mut bytes = [0u8; 4];
            rng.fill_bytes(&mut bytes);
            let num = u32::from_be_bytes(bytes) % 100000000;
            format!("{:08}", num)
        })
        .collect();

    // Hash backup codes for storage
    let hashed_codes: Vec<String> = backup_codes
        .iter()
        .map(|code| {
            use sha2::{Digest, Sha256};
            format!("{:x}", Sha256::digest(code.as_bytes()))
        })
        .collect();

    // Store hashed backup codes
    totp_store
        .set_backup_codes(&user_id.to_string(), hashed_codes)
        .map_err(|e| AuthencError::internal(format!("Failed to store backup codes: {}", e)))?;

    // Log TOTP setup
    let audit_log = crate::models::audit_log::AuditLog {
        timestamp: chrono::Utc::now(),
        event: "TOTP_SETUP".to_string(),
        user_id: Some(auth_user.id.clone()),
        client_id: None,
        status: "success".to_string(),
        detail: Some("TOTP two-factor authentication enabled".to_string()),
    };

    if let Err(e) = audit_log_store.add_log(&audit_log).await {
        eprintln!("Failed to log TOTP setup: {}", e);
    }

    Ok(Json(TotpSetupResponse {
        secret,
        qr_code_url,
        backup_codes,
    }))
}

/// Get TOTP status for current user
pub async fn get_totp_status(
    State((_, _, _, totp_store, _, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
        Arc<SocialAccountStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
) -> Result<Json<TotpStatusResponse>, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    let has_secret = totp_store
        .get_secret(&user_id.to_string())
        .map_err(|e| AuthencError::internal(format!("Failed to check TOTP status: {}", e)))?
        .is_some();

    let configured_at = if has_secret {
        totp_store
            .get_configured_at(&user_id.to_string())
            .map_err(|e| {
                AuthencError::internal(format!("Failed to get TOTP configured time: {}", e))
            })?
    } else {
        None
    };

    Ok(Json(TotpStatusResponse {
        enabled: has_secret,
        configured_at,
    }))
}

/// Disable TOTP for current user
pub async fn disable_totp(
    State((_, _, _, totp_store, audit_log_store, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
        Arc<SocialAccountStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
) -> Result<StatusCode, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    totp_store
        .remove_secret(&user_id.to_string())
        .map_err(|e| AuthencError::internal(format!("Failed to disable TOTP: {}", e)))?;

    // Also remove backup codes
    totp_store
        .remove_backup_codes(&user_id.to_string())
        .map_err(|e| AuthencError::internal(format!("Failed to remove backup codes: {}", e)))?;

    // Log TOTP disable
    let audit_log = crate::models::audit_log::AuditLog {
        timestamp: chrono::Utc::now(),
        event: "TOTP_DISABLED".to_string(),
        user_id: Some(auth_user.id.clone()),
        client_id: None,
        status: "success".to_string(),
        detail: Some("TOTP two-factor authentication disabled".to_string()),
    };

    if let Err(e) = audit_log_store.add_log(&audit_log).await {
        eprintln!("Failed to log TOTP disable: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Get linked social accounts for current user
pub async fn get_linked_social_accounts(
    State((user_store, _, _, _, _, social_account_store)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
        Arc<SocialAccountStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
) -> Result<Json<Vec<SocialAccountResponse>>, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Get user to check for social account links
    let user = user_store
        .get_user(user_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

    // Get social accounts for the user
    let social_accounts = social_account_store
        .get_user_social_accounts(user_id)
        .await?;

    // Convert to response format
    let responses: Vec<SocialAccountResponse> = social_accounts
        .into_iter()
        .map(|account| account.into())
        .collect();

    Ok(Json(responses))
}

/// Unlink a social account
pub async fn unlink_social_account(
    State((user_store, _, _, _, audit_log_store, social_account_store)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
        Arc<SocialAccountStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
    Path(provider): Path<String>,
) -> Result<StatusCode, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Parse provider
    let provider = match provider.as_str() {
        "google" => SocialProvider::Google,
        "github" => SocialProvider::GitHub,
        "microsoft" => SocialProvider::Microsoft,
        "facebook" => SocialProvider::Facebook,
        "twitter" => SocialProvider::Twitter,
        "linkedin" => SocialProvider::LinkedIn,
        _ => return Err(AuthencError::validation("Invalid social provider")),
    };

    // Remove the social account link
    social_account_store
        .remove_social_account_by_provider(user_id, &provider)
        .await?;

    // Log social account unlink
    let audit_log = crate::models::audit_log::AuditLog {
        timestamp: chrono::Utc::now(),
        event: "SOCIAL_ACCOUNT_UNLINKED".to_string(),
        user_id: Some(auth_user.id.clone()),
        client_id: None,
        status: "success".to_string(),
        detail: Some(format!("Social account {:?} unlinked", provider)),
    };

    if let Err(e) = audit_log_store.add_log(&audit_log).await {
        eprintln!("Failed to log social account unlink: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Get user consents for current user
pub async fn get_user_consents(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
) -> Result<Json<Vec<ConsentResponse>>, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Get user consents from the consent store
    let consents = state.consent_store.get_user_consents(user_id).await?;

    // Convert UserConsent to ConsentResponse
    let mut consent_responses = Vec::new();
    for consent in consents {
        // Get client name if available
        let client_name = match state.oidc_client_store.get(&consent.client_id).await {
            Ok(Some(client)) => Some(client.name),
            _ => None, // Client might not exist or be accessible
        };

        consent_responses.push(ConsentResponse {
            client_id: consent.client_id,
            client_name: client_name.unwrap_or_else(|| "Unknown Client".to_string()),
            scopes: consent.scopes,
            granted_at: consent.granted_at.to_string(),
            expires_at: consent.expires_at.map(|dt| dt.to_string()),
        });
    }

    Ok(Json(consent_responses))
}

/// Revoke consent for a specific client
pub async fn revoke_consent(
    State(state): State<Arc<AppState>>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
    Path(client_id): Path<String>,
) -> Result<StatusCode, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Revoke consent for the client
    state
        .consent_store
        .revoke_consent(user_id, &client_id)
        .await?;

    // Log consent revocation
    let audit_log = crate::models::audit_log::AuditLog {
        timestamp: chrono::Utc::now(),
        event: "CONSENT_REVOKED".to_string(),
        user_id: Some(auth_user.id.clone()),
        client_id: Some(client_id.clone()),
        status: "success".to_string(),
        detail: Some(format!("Consent revoked for client {}", client_id)),
    };

    if let Err(e) = state.audit_log_store.add_log(&audit_log).await {
        eprintln!("Failed to log consent revocation: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}
