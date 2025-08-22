use std::sync::Mutex;
use crate::models::user::User;
use uuid::Uuid;

pub struct UserStore {
    pub users: Mutex<Vec<User>>,
}

impl UserStore {
    pub fn new() -> Self {
        Self {
            users: Mutex::new(vec![]),
        }
    }

    pub fn add_user(&self, user: User) {
        self.users.lock().unwrap().push(user);
    }

    pub fn get_all(&self) -> Vec<User> {
        self.users.lock().unwrap().clone()
    }
    
    pub fn get_by_username(&self, username: &str) -> Option<User> {
        self.users.lock().unwrap()
            .iter()
            .find(|u| u.username == username)
            .cloned()
    }
    
    pub fn get_by_id(&self, id: &Uuid) -> Option<User> {
        self.users.lock().unwrap()
            .iter()
            .find(|u| u.id == *id)
            .cloned()
    }
    
    pub fn verify_password(&self, username: &str, password: &str) -> Result<bool, String> {
        if let Some(_user) = self.get_by_username(username) {
            // TODO: replace with Argon2 hash verify
            Ok(password == "password") // Placeholder logic
        } else {
            Err("User not found".to_string())
        }
    }
}
