use crate::model::user::User;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct UserStore {
	users: Arc<RwLock<HashMap<String, User>>>,
}

impl UserStore {
	pub fn update(&self, id: &str, username: Option<&str>, email: Option<&str>, password: Option<&str>, is_active: Option<bool>) -> Option<User> {
		let mut users = self.users.write().unwrap();
		if let Some(user) = users.get_mut(id) {
			if let Some(username) = username {
				user.username = username.to_string();
			}
			if let Some(email) = email {
				user.email = email.to_string();
			}
			if let Some(password) = password {
				user.password_hash = password.to_string(); // For demo, store plain. Use hash in prod.
			}
			if let Some(is_active) = is_active {
				user.is_active = is_active;
			}
			return Some(user.clone());
		}
		None
	}

	pub fn delete(&self, id: &str) -> bool {
		let mut users = self.users.write().unwrap();
		users.remove(id).is_some()
	}
	pub fn new() -> Self {
		UserStore {
			users: Arc::new(RwLock::new(HashMap::new())),
		}
	}

	pub fn get_by_username(&self, username: &str) -> Option<User> {
		let users = self.users.read().unwrap();
		users.values().find(|u| u.username == username).cloned()
	}

	pub fn all(&self) -> Vec<User> {
		let users = self.users.read().unwrap();
		users.values().cloned().collect()
	}

	pub fn verify_password(&self, username: &str, password: &str) -> bool {
		if let Some(user) = self.get_by_username(username) {
			// For demo, use plain text. Replace with argon2 or bcrypt in production.
			user.password_hash == password
		} else {
			false
		}
	}

	pub fn add_user(&self, user: User) {
		let mut users = self.users.write().unwrap();
		users.insert(user.id.clone(), user);
	}
}
