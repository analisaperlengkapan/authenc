use axum::{
    Router,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::AuthencError;
use crate::services::stores::user_store::{UserStore, UserStoreTrait};
use crate::services::totp_store::TotpStore;

/// State for account credentials handlers
#[derive(Clone)]
pub struct AccountCredentialsState {
    /// Store for user data
    pub user_store: Arc<UserStore>,
    /// Store for TOTP (Time-based One-Time Password) data
    pub totp_store: Arc<TotpStore>,
}

/// Create account credentials management routes
pub fn create_account_credentials_routes() -> Router<AccountCredentialsState> {
    Router::new()
        .route("/account/credentials", get(get_account_credentials))
        .route(
            "/account/credentials/password",
            put(update_account_password),
        )
        .route(
            "/account/credentials/{credential_id}",
            delete(remove_account_credential),
        )
        .route("/account/credentials/totp/setup", post(setup_totp))
        .route("/account/credentials/totp/verify", post(verify_totp_setup))
        .route("/account/credentials/totp/disable", delete(disable_totp))
}

/// Get current user's credentials
pub async fn get_account_credentials(
    State(state): State<AccountCredentialsState>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
) -> Result<Json<Vec<CredentialResponse>>, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    let user = state
        .user_store
        .get_user(user_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

    let mut credentials = Vec::new();

    // Add password credential (always present)
    credentials.push(CredentialResponse {
        id: "password".to_string(),
        credential_type: CredentialType::Password,
        user_label: Some("Password".to_string()),
        created_at: user.created_at,
        last_used_at: user.last_login_at,
    });

    // Check if TOTP is configured using atomic retrieval
    let user_id_str = user_id.to_string();
    if let Ok(Some((_, created_at))) = state.totp_store.get_totp_info(&user_id_str) {
        let totp_last_used_at = state
            .totp_store
            .get_last_used_at(&user_id_str)
            .unwrap_or(None);

        credentials.push(CredentialResponse {
            id: "totp".to_string(),
            credential_type: CredentialType::Totp,
            user_label: Some("Authenticator App".to_string()),
            created_at,
            last_used_at: totp_last_used_at,
        });
    }

    Ok(Json(credentials))
}

/// Update current user's password
#[derive(Deserialize)]
pub struct UpdatePasswordRequest {
    /// The current password for verification
    pub current_password: String,
    /// The new password to set
    pub new_password: String,
}

/// Update the authenticated user's account password
pub async fn update_account_password(
    State(state): State<AccountCredentialsState>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
    Json(password_request): Json<UpdatePasswordRequest>,
) -> Result<StatusCode, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Retrieve the user to get the current password hash
    let user = state
        .user_store
        .get_user(user_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

    // Verify current password
    let password_valid = match &user.password_hash {
        Some(hash) => crate::utils::crypto::password::verify_password(
            hash,
            &password_request.current_password,
        )
        .unwrap_or(false),
        None => false,
    };

    if !password_valid {
        return Err(AuthencError::unauthorized("Invalid current password"));
    }

    // Hash the new password
    let new_password_hash = crate::utils::crypto::password::hash_password(&password_request.new_password)
        .map_err(|e| AuthencError::internal(format!("Failed to hash password: {}", e)))?;

    // Update the password
    state
        .user_store
        .update_password(user_id, new_password_hash)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
/// Remove a credential from current user's account
pub async fn remove_account_credential(
    State(state): State<AccountCredentialsState>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
    Path(credential_id): Path<String>,
) -> Result<StatusCode, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    match credential_id.as_str() {
        "totp" => {
            // Remove TOTP secret for the current user.
            // Ownership is implicitly verified because we only delete using the authenticated user_id.
            // If the secret doesn't exist for this user, remove_secret returns false, allowing us to return 404.
            // This is atomic and more efficient than get-then-remove.
            let removed = state
                .totp_store
                .remove_secret(&user_id.to_string())
                .map_err(|e| {
                    AuthencError::internal(format!("Failed to remove TOTP secret: {}", e))
                })?;

            if !removed {
                return Err(AuthencError::resource_not_found("Credential not found"));
            }
        }
        "password" => {
            return Err(AuthencError::validation("Cannot delete password credential"));
        }
        _ => {
            return Err(AuthencError::resource_not_found("Credential not found"));
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Setup TOTP for current user
#[derive(Deserialize)]
pub struct SetupTotpRequest {
    /// Optional label for the TOTP credential
    pub user_label: Option<String>,
}

#[derive(serde::Serialize)]
/// Response containing TOTP setup information
pub struct SetupTotpResponse {
    /// The TOTP secret key
    pub secret: String,
    /// URI for generating QR code
    pub qr_code_uri: String,
    /// Optional label for the TOTP credential
    pub user_label: Option<String>,
}

/// Setup TOTP (Time-based One-Time Password) authentication for the user
#[axum::debug_handler]
pub async fn setup_totp(
    State(state): State<AccountCredentialsState>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
    Json(setup_request): Json<SetupTotpRequest>,
) -> Result<Json<SetupTotpResponse>, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Check if TOTP is already configured
    if let Ok(Some(_)) = state.totp_store.get_secret(&user_id.to_string()) {
        return Err(AuthencError::validation("TOTP already configured"));
    }

    // Generate a new TOTP secret
    use rand::Rng;
    let secret_bytes: Vec<u8> = (0..32).map(|_| rand::thread_rng().r#gen()).collect();
    let secret = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret_bytes);

    // Store the secret temporarily (will be confirmed in verify_totp_setup)
    // For now, we'll store it directly - in production, use a temporary store
    state
        .totp_store
        .set_secret(&user_id.to_string(), &secret)
        .map_err(|e| AuthencError::internal(format!("Failed to store TOTP secret: {}", e)))?;

    // Get user for account name
    let user = state
        .user_store
        .get_user(user_id)
        .await?
        .ok_or_else(|| AuthencError::resource_not_found("User not found"))?;

    let account_name = &user.username;
    let issuer = "Authenc"; // Should be configurable

    // Generate TOTP URI for QR code
    let qr_code_uri = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}",
        issuer, account_name, secret, issuer
    );

    Ok(Json(SetupTotpResponse {
        secret,
        qr_code_uri,
        user_label: setup_request.user_label,
    }))
}

/// Verify TOTP setup with a code
#[derive(Deserialize)]
pub struct VerifyTotpSetupRequest {
    /// The TOTP code to verify
    pub code: String,
}

/// Verify TOTP setup by validating a provided code against the stored secret
pub async fn verify_totp_setup(
    State(state): State<AccountCredentialsState>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
    Json(verify_request): Json<VerifyTotpSetupRequest>,
) -> Result<StatusCode, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Get the stored secret
    let secret = state
        .totp_store
        .get_secret(&user_id.to_string())
        .map_err(|e| AuthencError::internal(format!("Failed to get TOTP secret: {}", e)))?
        .ok_or_else(|| AuthencError::validation("TOTP not configured"))?;

    // Verify the code
    if !verify_totp_code(&secret, &verify_request.code) {
        return Err(AuthencError::validation("Invalid TOTP code"));
    }

    // Record usage
    if let Err(e) = state.totp_store.record_usage(&user_id.to_string()) {
        tracing::error!("Failed to record TOTP usage: {}", e);
    }

    // TOTP is now verified and active
    Ok(StatusCode::NO_CONTENT)
}

/// Disable TOTP for current user
pub async fn disable_totp(
    State(state): State<AccountCredentialsState>,
    Extension(auth_user): Extension<crate::middleware::auth_middleware_axum::AuthUser>,
) -> Result<StatusCode, AuthencError> {
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID in token"))?;

    // Remove the TOTP secret
    state
        .totp_store
        .remove_secret(&user_id.to_string())
        .map_err(|e| AuthencError::internal(format!("Failed to remove TOTP secret: {}", e)))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Verify a TOTP code against a secret
fn verify_totp_code(secret: &str, code: &str) -> bool {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Decode the base32 secret
    let secret_bytes = match base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret) {
        Some(bytes) => bytes,
        None => return false,
    };

    // Get current time
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Check current 30-second window and adjacent windows for clock skew
    for offset in -1..=1 {
        let time_window = (timestamp / 30) as i64 + offset;

        // Generate HMAC-SHA1
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        type HmacSha1 = Hmac<Sha1>;

        let mut mac = HmacSha1::new_from_slice(&secret_bytes).unwrap();
        mac.update(&time_window.to_be_bytes());
        let result = mac.finalize();
        let hash = result.into_bytes();

        // Dynamic truncation
        let offset = (hash[hash.len() - 1] & 0xf) as usize;
        let code_bytes = &hash[offset..offset + 4];
        let generated_code = u32::from_be_bytes(code_bytes.try_into().unwrap()) & 0x7FFFFFFF;
        let generated_code_str = format!("{:06}", generated_code % 1000000);

        if generated_code_str == code {
            return true;
        }
    }

    false
}

/// Credential response structure
#[derive(serde::Serialize)]
pub struct CredentialResponse {
    /// Unique identifier for the credential
    pub id: String,
    /// Type of credential
    pub credential_type: CredentialType,
    /// User-friendly name for the credential
    pub user_label: Option<String>,
    /// When the credential was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the credential was last used
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Types of credentials
#[derive(serde::Serialize)]
pub enum CredentialType {
    /// Password credential
    Password,
    /// TOTP credential
    Totp,
    /// WebAuthn credential
    WebAuthn,
    /// Backup codes
    BackupCode,
}
