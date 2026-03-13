use authenc_models::models::role::Role;
use std::sync::{Arc, RwLock};
pub use authenc_spi::spi::store_traits::RoleStoreTrait;

/// In-memory store for managing roles
pub struct RoleStore {
    /// Thread-safe storage of roles
    pub roles: RwLock<Arc<Vec<Role>>>,
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
            roles: RwLock::new(Arc::new(vec![])),
        }
    }

    /// Add role to store
    pub fn add_role(&self, role: Role) {
        let mut roles = self.roles.write().unwrap();
        Arc::make_mut(&mut roles).push(role);
    }

    /// Get all roles
    pub fn get_all(&self) -> Arc<Vec<Role>> {
        self.roles.read().unwrap().clone()
    }

    /// Get roles by realm ID
    pub fn get_by_realm(&self, realm_id: &str) -> Vec<Role> {
        self.roles
            .read()
            .unwrap()
            .iter()
            .filter(|r| r.realm_id.map(|id| id.to_string()).as_ref() == Some(&realm_id.to_string()))
            .cloned()
            .collect()
    }

    /// Get role by name
    pub fn get_by_name(&self, name: &str) -> Option<Role> {
        self.roles
            .read()
            .unwrap()
            .iter()
            .find(|r| r.name == name)
            .cloned()
    }

    /// Delete role by realm and name
    pub fn delete_by_name(&self, realm_id: &str, name: &str) -> bool {
        let mut roles = self.roles.write().unwrap();
        let vec = Arc::make_mut(&mut roles);
        let len_before = vec.len();
        vec.retain(|r| {
            !(r.realm_id.map(|id| id.to_string()).as_ref() == Some(&realm_id.to_string())
                && r.name == name)
        });
        vec.len() < len_before
    }

    /// Update an existing role
    pub fn update_role(&self, realm_id: &str, name: &str, updated_role: Role) -> bool {
        let mut roles = self.roles.write().unwrap();
        let vec = Arc::make_mut(&mut roles);

        if let Some(index) = vec.iter().position(|r| {
            r.realm_id.map(|id| id.to_string()).as_ref() == Some(&realm_id.to_string())
                && r.name == name
        }) {
            vec[index] = updated_role;
            true
        } else {
            false
        }
    }
}

impl RoleStoreTrait for RoleStore {
    fn get_by_name(&self, name: &str) -> Option<Role> {
        self.get_by_name(name)
    }

    fn get_all(&self) -> Arc<Vec<Role>> {
        self.get_all()
    }

    fn add_role(&self, role: Role) {
        self.add_role(role)
    }
}
