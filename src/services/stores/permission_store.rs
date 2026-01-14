use crate::models::permission::Permission;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// In-memory store for managing permissions
pub struct PermissionStore {
    /// Thread-safe storage of permissions
    pub permissions: RwLock<Arc<Vec<Permission>>>,
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
            permissions: RwLock::new(Arc::new(vec![])),
        }
    }

    /// Add permission to store
    pub fn add_permission(&self, permission: Permission) {
        let mut permissions = self.permissions.write().unwrap();
        Arc::make_mut(&mut permissions).push(permission);
    }

    /// Get all permissions
    pub fn get_all(&self) -> Arc<Vec<Permission>> {
        self.permissions.read().unwrap().clone()
    }

    /// Get permissions by realm ID
    pub fn get_by_realm(&self, realm_id: &str) -> Vec<Permission> {
        let realm_uuid = match Uuid::parse_str(realm_id) {
            Ok(uuid) => uuid,
            Err(_) => return vec![],
        };

        self.permissions
            .read()
            .unwrap()
            .iter()
            .filter(|p| p.realm_id == realm_uuid)
            .cloned()
            .collect()
    }

    /// Get permission by resource name
    pub fn get_by_resource(&self, resource: &str) -> Option<Permission> {
        self.permissions
            .read()
            .unwrap()
            .iter()
            .find(|p| p.resource == resource)
            .cloned()
    }

    /// Delete permission by realm and name
    pub fn delete_by_name(&self, realm_id: &str, name: &str) -> bool {
        let mut permissions = self.permissions.write().unwrap();
        let vec = Arc::make_mut(&mut permissions);
        let len_before = vec.len();
        vec.retain(|p| !(p.realm_id.to_string() == realm_id && p.name == name));
        vec.len() < len_before
    }
}
