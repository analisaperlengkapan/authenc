use authenc_core::error::{AuthencError, Result};
use authenc_spi::spi::store_traits::UserStoreTrait;
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

/// Service for handling email verification flows
pub struct EmailVerificationService {
    user_store: Arc<dyn UserStoreTrait>,
    token_validity_hours: i64,
}

impl EmailVerificationService {
    /// Create a new email verification service
    pub fn new(user_store: Arc<dyn UserStoreTrait>) -> Self {
        Self {
            user_store,
            token_validity_hours: 24, // 24 hours validity
        }
    }

    /// Request verification for a given email
    pub async fn request_verification(&self, email: &str, realm_id: &Uuid) -> Result<()> {
        // Find user by email
        let user_opt = self.user_store.get_user_by_email(realm_id, email).await?;

        let user = match user_opt {
            Some(u) if u.enabled && !u.email_verified => u,
            _ => {
                // Return OK to prevent email enumeration attacks (and hide disabled status/already verified status)
                tracing::debug!("Verification requested for non-existent, disabled, or already verified email: {}", email);

                // Perform dummy work to mitigate timing attacks
                let dummy_token = Uuid::new_v4().to_string();
                let mut hasher = Sha256::new();
                hasher.update(dummy_token.as_bytes());
                let token_hash = hex::encode(hasher.finalize());
                let expires_at = Utc::now() + Duration::hours(self.token_validity_hours);

                // Execute a DB write with a random UUID to match timing of the success path
                // This simulates the set_verification_token call in the success path
                let _ = self.user_store
                    .set_verification_token(Uuid::new_v4(), Some(token_hash), Some(expires_at))
                    .await;

                return Ok(());
            }
        };

        // Generate secure token
        let token = Uuid::new_v4().to_string();

        // Hash token for storage
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        let expires_at = Utc::now() + Duration::hours(self.token_validity_hours);

        // Store token hash in database
        self.user_store
            .set_verification_token(user.id, Some(token_hash), Some(expires_at))
            .await?;

        // Send email (MOCKED)
        // In a real implementation, this would call an EmailService
        tracing::info!(
            "Email verification link sent to {}",
            email
        );

        // For local dev convenience ONLY (remove in prod)
        #[cfg(debug_assertions)]
        println!("*** EMAIL SIMULATION: Verify {} - Token: {} ***", email, token);

        Ok(())
    }

    /// Verify email using a token
    pub async fn verify_email(&self, token: &str) -> Result<()> {
        // Hash token for lookup
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        // Find user by token hash
        let user = self
            .user_store
            .get_user_by_verification_token(&token_hash)
            .await?
            .ok_or_else(|| AuthencError::validation("Invalid or expired verification token"))?;

        // Check expiration
        if let Some(expires_at) = user.verification_token_expires_at {
            if Utc::now() > expires_at {
                return Err(AuthencError::validation("Verification token has expired"));
            }
        } else {
            return Err(AuthencError::validation("Invalid verification token"));
        }

        // Use transactional update to verify email and clear token atomically
        self.user_store
            .verify_email_transaction(user.id, token_hash)
            .await?;

        tracing::info!("Email verified successfully for user {}", user.id);

        Ok(())
    }
}
