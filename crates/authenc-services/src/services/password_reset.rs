use authenc_core::error::{AuthencError, Result};
use authenc_crypto::utils::crypto::password::hash_password;
use authenc_spi::spi::store_traits::UserStoreTrait;
use chrono::{Duration, Utc};
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
            Some(u) => u,
            None => {
                // Return OK to prevent email enumeration attacks
                tracing::info!("Password reset requested for non-existent email: {}", email);
                return Ok(());
            }
        };

        // Generate secure token (using UUID for simplicity in this implementation)
        // In production, consider cryptographically secure random strings
        let token = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + Duration::minutes(self.token_validity_minutes);

        // Store token in database
        self.user_store
            .set_reset_token(user.id, Some(token.clone()), Some(expires_at))
            .await?;

        // Send email (MOCKED)
        // In a real implementation, this would call an EmailService
        tracing::info!(
            "Password reset email sent to {} with token: {}",
            email,
            token
        );
        println!(
            "*** EMAIL SIMULATION: Password reset for {} - Token: {} ***",
            email, token
        );

        Ok(())
    }

    /// Reset password using a token
    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<()> {
        // Find user by token
        let user = self
            .user_store
            .get_user_by_reset_token(token)
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
            .reset_password_transaction(user.id, password_hash)
            .await?;

        tracing::info!("Password reset successfully for user {}", user.id);

        Ok(())
    }
}
