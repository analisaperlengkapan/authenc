use std::sync::Mutex;
use crate::model::permission::Permission;

pub struct PermissionStore {
    pub permissions: Mutex<Vec<Permission>>,
}

impl PermissionStore {
    pub fn new() -> Self {
        Self {
            permissions: Mutex::new(vec![]),
        }
    }

    pub fn add_permission(&self, permission: Permission) {
        self.permissions.lock().unwrap().push(permission);
    }

    pub fn get_all(&self) -> Vec<Permission> {
        self.permissions.lock().unwrap().clone()
    }

    pub fn get_by_name(&self, realm: &str, name: &str) -> Option<Permission> {
        self.permissions.lock().unwrap().iter().find(|p| p.realm == realm && p.name == name).cloned()
    }

    pub fn delete_by_name(&self, realm: &str, name: &str) -> bool {
        let mut permissions = self.permissions.lock().unwrap();
        let len_before = permissions.len();
        permissions.retain(|p| !(p.realm == realm && p.name == name));
        permissions.len() < len_before
    }
}
