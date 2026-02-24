use authenc_core::error::{AuthencError, Result};
use authenc_crypto::utils::crypto::password::hash_password;
use authenc_spi::spi::store_traits::UserStoreTrait;
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

/// Service for handling password reset flows
pub struct PasswordResetService {
    user_store: Arc<dyn UserStoreTrait>,
    token_validity_minutes: i64,
}

impl PasswordResetService {
    /// Create a new password reset service
    pub fn new(user_store: Arc<dyn UserStoreTrait>) -> Self {
        Self {
            user_store,
            token_validity_minutes: 60, // Default 1 hour validity
        }
    }

    /// Request a password reset for a given email
    pub async fn request_reset(&self, email: &str, realm_id: &Uuid) -> Result<()> {
        // Find user by email
        let user = match self.user_store.get_user_by_email(realm_id, email).await? {
            Some(u) if u.enabled => u,
            _ => {
                // Return OK to prevent email enumeration attacks (and hide disabled status)
                tracing::debug!("Password reset requested for non-existent or disabled email: {}", email);
                // Perform dummy work to mitigate timing attacks
                let dummy_token = Uuid::new_v4().to_string();
                let mut hasher = Sha256::new();
                hasher.update(dummy_token.as_bytes());
                let token_hash = hex::encode(hasher.finalize());
                let expires_at = Utc::now() + Duration::minutes(self.token_validity_minutes);

                // Execute a DB write with a random UUID to match timing of the success path
                let _ = self.user_store
                    .set_reset_token(Uuid::new_v4(), Some(token_hash), Some(expires_at))
                    .await;

                return Ok(());
            }
        };

        // Generate secure token (using UUID for simplicity in this implementation)
        // In production, consider cryptographically secure random strings
        let token = Uuid::new_v4().to_string();

        // Hash token for storage
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        let expires_at = Utc::now() + Duration::minutes(self.token_validity_minutes);

        // Store token hash in database
        self.user_store
            .set_reset_token(user.id, Some(token_hash), Some(expires_at))
            .await?;

        // Send email (MOCKED)
        // In a real implementation, this would call an EmailService
        tracing::info!(
            "Password reset email sent to {}",
            email
        );
        // In a real implementation, the token would be sent via email here.
        // For development/testing, you might need a way to retrieve it (e.g., implementation-specific logging)
        // but never in production logs.

        // For local dev convenience ONLY (remove in prod)
        #[cfg(debug_assertions)]
        println!("*** EMAIL SIMULATION: Password reset for {} - Token: {} ***", email, token);

        Ok(())
    }

    /// Reset password using a token
    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<()> {
        // Hash token for lookup
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        // Find user by token hash
        let user = self
            .user_store
            .get_user_by_reset_token(&token_hash)
            .await?
            .ok_or_else(|| AuthencError::not_found("Invalid or expired reset token"))?;

        // Check expiration
        if let Some(expires_at) = user.reset_token_expires_at {
            if Utc::now() > expires_at {
                return Err(AuthencError::validation("Reset token has expired"));
            }
        } else {
            return Err(AuthencError::validation("Invalid reset token"));
        }

        // Hash new password
        let password_hash = hash_password(new_password).await.map_err(|e| {
            AuthencError::internal(format!("Failed to hash password: {}", e))
        })?;

        // Use transactional update to reset password and clear token atomically
        self.user_store
            .reset_password_transaction(user.id, password_hash, token_hash)
            .await?;

        tracing::info!("Password reset successfully for user {}", user.id);

        Ok(())
    }
}
