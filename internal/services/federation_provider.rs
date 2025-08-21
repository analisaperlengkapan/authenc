
use crate::model::user::User;

pub trait FederationProvider: Send + Sync {
    fn get_user_by_username(&self, username: &str) -> Option<User>;
    fn verify_password(&self, username: &str, password: &str) -> bool;
}

pub struct FederationRegistry {
    providers: Vec<Box<dyn FederationProvider>>,
}

impl FederationRegistry {
    pub fn new() -> Self {
        Self { providers: Vec::new() }
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
                id: "fed-1".into(),
                username: username.into(),
                email: "federated@example.com".into(),
                password_hash: "federatedpass".into(),
                is_active: true,
            })
        } else {
            None
        }
    }
    fn verify_password(&self, username: &str, password: &str) -> bool {
        username == "federated" && password == "federatedpass"
    }
}
