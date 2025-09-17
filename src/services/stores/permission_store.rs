use crate::models::permission::Permission;
use std::sync::Mutex;

/// In-memory store for managing permissions
pub struct PermissionStore {
    /// Thread-safe storage of permissions
    pub permissions: Mutex<Vec<Permission>>,
}

impl Default for PermissionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PermissionStore {
    /// Create new permission store
    pub fn new() -> Self {
        Self {
            permissions: Mutex::new(vec![]),
        }
    }

    /// Add permission to store
    pub fn add_permission(&self, permission: Permission) {
        self.permissions.lock().unwrap().push(permission);
    }

    /// Get all permissions
    pub fn get_all(&self) -> Vec<Permission> {
        self.permissions.lock().unwrap().clone()
    }

    /// Get permissions by realm ID
    pub fn get_by_realm(&self, realm_id: &str) -> Vec<Permission> {
        self.permissions
            .lock()
            .unwrap()
            .iter()
            .filter(|p| p.realm_id.to_string() == realm_id)
            .cloned()
            .collect()
    }

    /// Get permission by resource name
    pub fn get_by_resource(&self, resource: &str) -> Option<Permission> {
        self.permissions
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.resource == resource)
            .cloned()
    }

    /// Delete permission by realm and name
    pub fn delete_by_name(&self, realm_id: &str, name: &str) -> bool {
        let mut permissions = self.permissions.lock().unwrap();
        let len_before = permissions.len();
        permissions.retain(|p| !(p.realm_id.to_string() == realm_id && p.name == name));
        permissions.len() < len_before
    }
}
