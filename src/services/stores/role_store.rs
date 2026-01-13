use crate::models::role::Role;
use std::sync::{Mutex, MutexGuard};

/// In-memory store for managing roles
pub struct RoleStore {
    /// Thread-safe storage of roles
    pub roles: Mutex<Vec<Role>>,
}

impl Default for RoleStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RoleStore {
    /// Create new role store
    pub fn new() -> Self {
        Self {
            roles: Mutex::new(vec![]),
        }
    }

    /// Add role to store
    pub fn add_role(&self, role: Role) {
        self.roles.lock().unwrap().push(role);
    }

    /// Get all roles
    pub fn get_roles(&self) -> MutexGuard<'_, Vec<Role>> {
        self.roles.lock().unwrap()
    }

    /// Get roles by realm ID
    pub fn get_by_realm(&self, realm_id: &str) -> Vec<Role> {
        self.roles
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.realm_id.map(|id| id.to_string()).as_ref() == Some(&realm_id.to_string()))
            .cloned()
            .collect()
    }

    /// Get role by name
    pub fn get_by_name(&self, name: &str) -> Option<Role> {
        self.roles
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.name == name)
            .cloned()
    }

    /// Delete role by realm and name
    pub fn delete_by_name(&self, realm_id: &str, name: &str) -> bool {
        let mut roles = self.roles.lock().unwrap();
        let len_before = roles.len();
        roles.retain(|r| {
            !(r.realm_id.map(|id| id.to_string()).as_ref() == Some(&realm_id.to_string())
                && r.name == name)
        });
        roles.len() < len_before
    }
}
