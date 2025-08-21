use std::sync::Mutex;
use crate::model::role::Role;

pub struct RoleStore {
    pub roles: Mutex<Vec<Role>>,
}

impl RoleStore {
    pub fn new() -> Self {
        Self {
            roles: Mutex::new(vec![]),
        }
    }

    pub fn add_role(&self, role: Role) {
        self.roles.lock().unwrap().push(role);
    }

    pub fn get_all(&self) -> Vec<Role> {
        self.roles.lock().unwrap().clone()
    }

    pub fn get_by_name(&self, realm: &str, name: &str) -> Option<Role> {
        self.roles.lock().unwrap().iter().find(|r| r.realm == realm && r.name == name).cloned()
    }

    pub fn delete_by_name(&self, realm: &str, name: &str) -> bool {
        let mut roles = self.roles.lock().unwrap();
        let len_before = roles.len();
        roles.retain(|r| !(r.realm == realm && r.name == name));
        roles.len() < len_before
    }
}
