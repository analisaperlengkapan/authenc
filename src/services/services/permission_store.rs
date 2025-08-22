use std::sync::Mutex;
use crate::models::permission::Permission;

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

    pub fn get_by_realm(&self, realm_id: &str) -> Vec<Permission> {
        self.permissions.lock().unwrap()
            .iter()
            .filter(|p| p.realm_id.to_string() == realm_id)
            .cloned()
            .collect()
    }

    pub fn get_by_resource(&self, resource: &str) -> Option<Permission> {
        self.permissions.lock().unwrap()
            .iter()
            .find(|p| p.resource == resource)
            .cloned()
    }

    pub fn delete_by_name(&self, realm_id: &str, name: &str) -> bool {
        let mut permissions = self.permissions.lock().unwrap();
        let len_before = permissions.len();
        permissions.retain(|p| !(p.realm_id.to_string() == realm_id && p.name == name));
        permissions.len() < len_before
    }
}
