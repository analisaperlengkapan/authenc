impl Default for FederationRegistry {
    fn default() -> Self {
        Self::new()
    }
}
use crate::models::user::User;

pub trait FederationProvider: Send + Sync {
    fn get_user_by_username(&self, username: &str) -> Option<User>;
    fn verify_password(&self, username: &str, password: &str) -> bool;
}

pub struct FederationRegistry {
    providers: Vec<Box<dyn FederationProvider>>,
}

impl FederationRegistry {
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }
    pub fn register(&mut self, provider: Box<dyn FederationProvider>) {
        self.providers.push(provider);
    }
    pub fn get_user_by_username(&self, username: &str) -> Option<User> {
        for p in &self.providers {
            if let Some(u) = p.get_user_by_username(username) {
                return Some(u);
            }
        }
        None
    }
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
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                deleted_at: None,
            })
        } else {
            None
        }
    }
    fn verify_password(&self, username: &str, password: &str) -> bool {
        username == "federated" && password == "federatedpass"
    }
}
