impl Default for FederationRegistry {
    fn default() -> Self {
        Self::new()
    }
}
use crate::models::user::User;
use subtle::ConstantTimeEq;

/// Trait for federation providers that can authenticate users from external systems
pub trait FederationProvider: Send + Sync {
    /// Get user by username from external system
    fn get_user_by_username(&self, username: &str) -> Option<User>;
    /// Verify user password against external system
    fn verify_password(&self, username: &str, password: &str) -> bool;
}

/// Registry for managing multiple federation providers
pub struct FederationRegistry {
    /// Collection of registered federation providers
    providers: Vec<Box<dyn FederationProvider>>,
}

impl FederationRegistry {
    /// Create new federation registry
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Register a federation provider
    pub fn register(&mut self, provider: Box<dyn FederationProvider>) {
        self.providers.push(provider);
    }

    /// Get user by username across all providers
    pub fn get_user_by_username(&self, username: &str) -> Option<User> {
        for p in &self.providers {
            if let Some(u) = p.get_user_by_username(username) {
                return Some(u);
            }
        }
        None
    }

    /// Verify password across all providers
    pub fn verify_password(&self, username: &str, password: &str) -> bool {
        for p in &self.providers {
            if p.verify_password(username, password) {
                return true;
            }
        }
        false
    }
}

// Example stub provider (in-memory, for demo)
/// Dummy federation provider for testing and demonstration purposes
pub struct DummyFederationProvider;
impl FederationProvider for DummyFederationProvider {
    fn get_user_by_username(&self, username: &str) -> Option<User> {
        if username == "federated" {
            Some(User {
                id: uuid::Uuid::new_v4(),
                username: username.into(),
                email: "federated@example.com".into(),
                email_verified: false,
                first_name: None,
                last_name: None,
                phone_number: None,
                phone_verified: false,
                password_hash: Some("federatedpass".into()),
                totp_secret: None,
                totp_backup_codes: None,
                webauthn_enabled: false,
                account_locked: false,
                account_locked_until: None,
                failed_login_attempts: 0,
                last_login_at: None,
                last_failed_login_at: None,
                password_changed_at: None,
                password_expires_at: None,
                require_password_change: false,
                realm_id: Some(uuid::Uuid::nil()),
                organization_id: None,
                attributes: None,
                enabled: true,
                federated: true,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                deleted_at: None,
                login_count: 0,
            })
        } else {
            None
        }
    }

    /// Verify password using constant-time comparison to prevent timing attacks
    ///
    /// # Security
    /// - Uses constant-time comparison to prevent timing attacks
    /// - Attacker cannot infer password by measuring response time
    /// - In production, passwords should be hashed with bcrypt/argon2
    fn verify_password(&self, username: &str, password: &str) -> bool {
        // Expected credentials (in production, these should be hashed)
        let expected_username = b"federated";
        let expected_password = b"federatedpass";

        // Constant-time comparison for both username and password
        let username_match = username.as_bytes().ct_eq(expected_username);
        let password_match = password.as_bytes().ct_eq(expected_password);

        // Both must match - using & instead of && for constant-time evaluation
        (username_match & password_match).into()
    }
}
