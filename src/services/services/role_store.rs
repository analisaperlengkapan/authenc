use std::sync::Mutex;
use crate::models::role::Role;

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

    pub fn get_by_realm(&self, realm_id: &str) -> Vec<Role> {
        self.roles.lock().unwrap()
            .iter()
            .filter(|r| r.realm_id.to_string() == realm_id)
            .cloned()
            .collect()
    }

    pub fn get_by_name(&self, name: &str) -> Option<Role> {
        self.roles.lock().unwrap()
            .iter()
            .find(|r| r.name == name)
            .cloned()
    }

    pub fn delete_by_name(&self, realm_id: &str, name: &str) -> bool {
        let mut roles = self.roles.lock().unwrap();
        let len_before = roles.len();
        roles.retain(|r| !(r.realm_id.to_string() == realm_id && r.name == name));
        roles.len() < len_before
    }
}
