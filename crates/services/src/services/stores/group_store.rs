impl Default for GroupStore {
    fn default() -> Self {
        Self::new()
    }
}
use authenc_api::models::group::Group;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// In-memory store for groups.
///
/// Provides thread-safe CRUD operations for `Group`.
pub struct GroupStore {
    /// id -> group mapping
    groups: Arc<RwLock<HashMap<Uuid, Group>>>,
}

impl GroupStore {
    /// Create a new, empty GroupStore.
    pub fn new() -> Self {
        GroupStore {
            groups: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get all groups.
    pub fn all(&self) -> Vec<Group> {
        self.groups
            .read()
            .map(|groups| groups.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Get a group by ID.
    pub fn get(&self, id: &Uuid) -> Option<Group> {
        self.groups
            .read()
            .ok()
            .and_then(|groups| groups.get(id).cloned())
    }

    /// Create a new group.
    pub fn create(&self, realm_id: Uuid, name: &str, description: Option<String>) -> Option<Group> {
        let now = Utc::now();
        let group = Group {
            id: Uuid::new_v4(),
            name: name.to_owned(),
            path: format!("/{}", name), // Root level group
            parent_id: None,
            description,
            attributes: serde_json::json!({}),
            realm_id,
            created_at: now,
            updated_at: now,
        };
        if let Ok(mut groups) = self.groups.write() {
            groups.insert(group.id, group.clone());
            Some(group)
        } else {
            None
        }
    }

    /// Delete a group by ID.
    pub fn delete(&self, id: &Uuid) -> bool {
        if let Ok(mut groups) = self.groups.write() {
            groups.remove(id).is_some()
        } else {
            false
        }
    }
}
