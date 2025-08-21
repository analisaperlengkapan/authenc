use crate::model::group::Group;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

pub struct GroupStore {
    groups: Arc<RwLock<HashMap<String, Group>>>,
}

impl GroupStore {
    pub fn new() -> Self {
        GroupStore {
            groups: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn all(&self) -> Vec<Group> {
        let groups = self.groups.read().unwrap();
        groups.values().cloned().collect()
    }

    pub fn get(&self, id: &str) -> Option<Group> {
        let groups = self.groups.read().unwrap();
        groups.get(id).cloned()
    }

    pub fn create(&self, name: &str, description: Option<String>) -> Group {
        let group = Group {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            description,
            members: vec![],
            roles: vec![],
        };
        let mut groups = self.groups.write().unwrap();
        groups.insert(group.id.clone(), group.clone());
        group
    }

    pub fn add_member(&self, group_id: &str, user_id: &str) -> bool {
        let mut groups = self.groups.write().unwrap();
        if let Some(group) = groups.get_mut(group_id) {
            if !group.members.contains(&user_id.to_string()) {
                group.members.push(user_id.to_string());
            }
            return true;
        }
        false
    }

    pub fn remove_member(&self, group_id: &str, user_id: &str) -> bool {
        let mut groups = self.groups.write().unwrap();
        if let Some(group) = groups.get_mut(group_id) {
            group.members.retain(|uid| uid != user_id);
            return true;
        }
        false
    }

    pub fn add_role(&self, group_id: &str, role_id: &str) -> bool {
        let mut groups = self.groups.write().unwrap();
        if let Some(group) = groups.get_mut(group_id) {
            if !group.roles.contains(&role_id.to_string()) {
                group.roles.push(role_id.to_string());
            }
            return true;
        }
        false
    }

    pub fn remove_role(&self, group_id: &str, role_id: &str) -> bool {
        let mut groups = self.groups.write().unwrap();
        if let Some(group) = groups.get_mut(group_id) {
            group.roles.retain(|rid| rid != role_id);
            return true;
        }
        false
    }

    pub fn delete(&self, id: &str) -> bool {
        let mut groups = self.groups.write().unwrap();
        groups.remove(id).is_some()
    }
}
