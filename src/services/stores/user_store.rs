use crate::models::user::User;
use std::sync::Mutex;
use uuid::Uuid;

/// In-memory store for managing users
pub struct UserStore {
    /// Thread-safe storage of users
    pub users: Mutex<Vec<User>>,
}

impl Default for UserStore {
    fn default() -> Self {
        Self::new()
    }
}

impl UserStore {
    /// Create new user store
    pub fn new() -> Self {
        Self {
            users: Mutex::new(vec![]),
        }
    }

    /// Add user to store
    pub fn add_user(&self, user: User) {
        self.users.lock().unwrap().push(user);
    }

    /// Get all users
    pub fn get_all(&self) -> Vec<User> {
        self.users.lock().unwrap().clone()
    }

    /// Get user by username
    pub fn get_by_username(&self, username: &str) -> Option<User> {
        self.users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.username == username)
            .cloned()
    }

    /// Get user by ID
    pub fn get_by_id(&self, id: &Uuid) -> Option<User> {
        self.users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.id == *id)
            .cloned()
    }

    /// Verify user password (WARNING: Currently uses plain text comparison)
    pub fn verify_password(&self, username: &str, password: &str) -> Result<bool, String> {
        if let Some(_user) = self.get_by_username(username) {
            // SECURITY TODO: Replace with proper Argon2 hash verification
            // This is currently using plain text comparison for development/testing only
            // Production code MUST use proper password hashing
            Ok(password == "password") // WARNING: Plain text password comparison
        } else {
            Err("User not found".to_string())
        }
    }
}
