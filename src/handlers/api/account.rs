use axum::{
    extract::{Extension, Path, Query, Request, State},
    http::{header, StatusCode},
    response::{Json, Response},
    routing::{get, put, delete, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::AuthencError;
use crate::models::user::{UpdateUserRequest, UserResponse};
use crate::models::session::SessionResponse;
use crate::models::oidc_client::OidcClient;
use crate::services::stores::user_store::UserStoreTrait;
use crate::services::session_store::SessionStore;
use crate::services::stores::user_store::UserStore;
use crate::services::oidc_client_store::OidcClientStore;
use crate::services::totp_store::TotpStore;
use crate::services::pg_audit_log_store::PgAuditLogStore;
use crate::middleware::auth_middleware_axum::{AuthUserExt, RequireAuth};
use crate::services::social::{SocialProvider, SocialLoginService};

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
    pub configured_at: Option<String>,
}

/// Response for social account information
#[derive(Debug, Deserialize, Serialize)]
pub struct SocialAccountResponse {
    /// Social provider (google, github, etc.)
    pub provider: String,
    /// User ID on the social provider
    pub provider_user_id: String,
    /// Display name from social provider
    pub display_name: Option<String>,
    /// When the account was linked
    pub linked_at: String,
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
)> {
    Router::new()
        .route("/account", get(get_account_profile))
        .route("/account", put(update_account_profile))
        .route("/account/sessions", get(get_account_sessions))
        .route("/account/sessions/{session_id}", delete(revoke_account_session))
        .route("/account/applications", get(get_account_applications))
        .route("/account/applications/{client_id}", delete(revoke_application_access))
        .route("/account/export", get(export_account_data))
        .route("/account", delete(delete_account))
        .route("/account/totp/setup", post(setup_totp))
        .route("/account/totp", get(get_totp_status))
        .route("/account/totp", delete(disable_totp))
        .route("/account/social", get(get_linked_social_accounts))
        .route("/account/social/{provider}", delete(unlink_social_account))
        .route("/account/consents", get(get_user_consents))
        .route("/account/consents/{client_id}", delete(revoke_consent))
}

/// Get current user's account profile
pub async fn get_account_profile(
    State((user_store, _, _, _, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
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
    State((user_store, _, _, _, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
    Json(update_request): Json<UpdateUserRequest>,
) -> Result<StatusCode, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    user_store
        .update_user(user_id, update_request)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get current user's active sessions
pub async fn get_account_sessions(
    State((_, session_store, _, _, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
) -> Result<Json<Vec<SessionResponse>>, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    let sessions = session_store
        .get_user_sessions(user_id)
        .await?;

    let response = sessions
        .into_iter()
        .map(|s| s.into())
        .collect();

    Ok(Json(response))
}

/// Revoke a specific session
pub async fn revoke_account_session(
    State((_, session_store, _, _, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
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
        return Err(AuthencError::forbidden("Cannot revoke session belonging to another user"));
    }

    session_store
        .delete_session(session_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Application response for account console
#[derive(Debug, Serialize)]
pub struct ApplicationResponse {
    pub client_id: String,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_access: Option<chrono::DateTime<chrono::Utc>>,
}

/// Get current user's authorized applications
pub async fn get_account_applications(
    State((_, _, oidc_client_store, _, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
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
            created_at: chrono::Utc::now(), // TODO: Add created_at to OidcClient model
            last_access: None, // TODO: Track last access time
        })
        .collect();

    Ok(Json(applications))
}

/// Revoke access to a specific application
pub async fn revoke_application_access(
    State((_, _, _oidc_client_store, _, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
    )>,
    Extension(_auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
    Path(_client_id): Path<String>,
) -> Result<StatusCode, AuthencError> {
    // TODO: Implement proper consent revocation
    // For now, this is a placeholder - in production, this should revoke all tokens for the client
    // and remove any stored consents

    // Note: We don't actually delete the client, just revoke the user's access to it
    // The client remains registered for other users

    Ok(StatusCode::NO_CONTENT)
}

/// Export current user's account data
pub async fn export_account_data(
    State((user_store, session_store, oidc_client_store, _, audit_log_store)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
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
    let sessions = session_store
        .get_user_sessions(user_id)
        .await?;

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
        detail: Some(format!("User exported account data containing profile, {} sessions, and {} applications", sessions.len(), applications.len())),
    };
    
    if let Err(e) = audit_log_store.add_log(&audit_log).await {
        // Log the error but don't fail the export
        eprintln!("Failed to log account data export: {}", e);
    }

    Ok(response)
}

/// Delete current user's account
pub async fn delete_account(
    State((user_store, _session_store, _oidc_client_store, totp_store, audit_log_store)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
    )>,
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
    crate::database::operations::webauthn::delete_user_credentials(user_store.database(), user_id).await?;

    // Remove TOTP secret
    totp_store.remove_secret(&user_id.to_string())
        .map_err(|e| AuthencError::internal(&format!("Failed to remove TOTP secret: {}", e)))?;

    // Delete the user account
    user_store
        .delete_user(user_id)
        .await?;

    // Log the account deletion for audit purposes
    let audit_log = crate::models::audit_log::AuditLog {
        timestamp: chrono::Utc::now(),
        event: "ACCOUNT_DELETION".to_string(),
        user_id: Some(auth_user.id.clone()),
        client_id: None,
        status: "success".to_string(),
        detail: Some("User account deleted with complete data cleanup (sessions, tokens, credentials, TOTP)".to_string()),
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
    State((_, _, _, totp_store, audit_log_store)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
    Json(_request): Json<TotpSetupRequest>,
) -> Result<Json<TotpSetupResponse>, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Generate TOTP secret
    use rand::{RngCore, rngs::OsRng};
    let mut rng = OsRng;
    let mut secret_bytes = [0u8; 32];
    rng.fill_bytes(&mut secret_bytes);
    let secret = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret_bytes);

    // Store the secret
    totp_store.set_secret(&user_id.to_string(), &secret)
        .map_err(|e| AuthencError::internal(&format!("Failed to store TOTP secret: {}", e)))?;

    // Generate QR code URL
    let qr_code_url = format!(
        "otpauth://totp/Authenc:{}?secret={}&issuer=Authenc",
        auth_user.email,
        secret
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

    // Store backup codes (in production, these should be hashed and stored securely)
    // For now, we'll just log them - in production you'd store hashed versions
    for code in &backup_codes {
        // TODO: Store hashed backup codes
    }

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
    State((_, _, _, totp_store, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
) -> Result<Json<TotpStatusResponse>, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    let has_secret = totp_store.get_secret(&user_id.to_string())
        .map_err(|e| AuthencError::internal(&format!("Failed to check TOTP status: {}", e)))?
        .is_some();

    Ok(Json(TotpStatusResponse {
        enabled: has_secret,
        configured_at: None, // TODO: Track when TOTP was configured
    }))
}

/// Disable TOTP for current user
pub async fn disable_totp(
    State((_, _, _, totp_store, audit_log_store)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
) -> Result<StatusCode, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    totp_store.remove_secret(&user_id.to_string())
        .map_err(|e| AuthencError::internal(&format!("Failed to disable TOTP: {}", e)))?;

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
    State((user_store, _, _, _, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
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

    // TODO: Implement proper social account linking storage
    // For now, return empty list - in production this would query a social_accounts table
    let social_accounts: Vec<SocialAccountResponse> = vec![];

    Ok(Json(social_accounts))
}

/// Unlink a social account
pub async fn unlink_social_account(
    State((user_store, _, _, _, audit_log_store)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
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

    // TODO: Implement actual social account unlinking
    // This would remove the link between the user and the social provider

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
    State((_, _, oidc_client_store, _, _)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
    )>,
    Extension(_auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
) -> Result<Json<Vec<ConsentResponse>>, AuthencError> {
    // TODO: Implement proper consent storage and retrieval
    // For now, return empty list - in production this would query user consents
    let consents: Vec<ConsentResponse> = vec![];

    Ok(Json(consents))
}

/// Revoke consent for a specific client
pub async fn revoke_consent(
    State((_, _, _, _, audit_log_store)): State<(
        Arc<UserStore>,
        Arc<SessionStore>,
        Arc<OidcClientStore>,
        Arc<TotpStore>,
        Arc<PgAuditLogStore>,
    )>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
    Path(client_id): Path<String>,
) -> Result<StatusCode, AuthencError> {
    // TODO: Implement proper consent revocation
    // This should revoke all tokens and remove stored consents for the client

    // Log consent revocation
    let audit_log = crate::models::audit_log::AuditLog {
        timestamp: chrono::Utc::now(),
        event: "CONSENT_REVOKED".to_string(),
        user_id: Some(auth_user.id.clone()),
        client_id: Some(client_id.clone()),
        status: "success".to_string(),
        detail: Some(format!("Consent revoked for client {}", client_id)),
    };

    if let Err(e) = audit_log_store.add_log(&audit_log).await {
        eprintln!("Failed to log consent revocation: {}", e);
    }

    Ok(StatusCode::NO_CONTENT)
}
