use std::sync::Mutex;
use crate::model::user::User;

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
}
