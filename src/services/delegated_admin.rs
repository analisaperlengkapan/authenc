//! Delegated Administration Framework
//!
//! Per-tenant/realm admin delegation with role-based access control.
//! Allows realm administrators to manage their own realm without global admin access.

use crate::error::AuthencError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Delegated admin permissions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DelegatedAdminPermission {
    /// Manage users in the realm
    ManageUsers,
    /// Manage roles in the realm
    ManageRoles,
    /// Manage clients in the realm
    ManageClients,
    /// Manage realm settings
    ManageRealm,
    /// View audit logs for the realm
    ViewAuditLogs,
    /// Manage identity providers
    ManageIdentityProviders,
    /// Manage authentication flows
    ManageAuthenticationFlows,
    /// Manage authorization policies
    ManageAuthorization,
}

/// Delegated admin role
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedAdminRole {
    /// Unique identifier for the role
    pub id: Uuid,
    /// Name of the role
    pub name: String,
    /// Description of the role
    pub description: String,
    /// Realm this role belongs to
    pub realm_id: Uuid,
    /// Permissions granted by this role
    pub permissions: HashSet<DelegatedAdminPermission>,
    /// Whether this is a composite role
    pub composite: bool,
    /// Parent roles if composite
    pub composites: Vec<Uuid>,
}

/// Delegated admin assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedAdminAssignment {
    /// Unique identifier for the assignment
    pub id: Uuid,
    /// User being granted admin access
    pub user_id: Uuid,
    /// Realm the user has admin access to
    pub realm_id: Uuid,
    /// Roles assigned to the user
    pub roles: Vec<Uuid>,
    /// Assignment is active
    pub active: bool,
    /// When the assignment was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the assignment expires (optional)
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Delegated admin service trait
#[async_trait]
pub trait DelegatedAdminService: Send + Sync {
    /// Check if a user has a specific permission in a realm
    async fn has_permission(
        &self,
        user_id: &Uuid,
        realm_id: &Uuid,
        permission: &DelegatedAdminPermission,
    ) -> Result<bool, AuthencError>;

    /// Get all permissions for a user in a realm
    async fn get_user_permissions(
        &self,
        user_id: &Uuid,
        realm_id: &Uuid,
    ) -> Result<HashSet<DelegatedAdminPermission>, AuthencError>;

    /// Assign admin role to user
    async fn assign_role(
        &self,
        user_id: &Uuid,
        realm_id: &Uuid,
        role_id: &Uuid,
    ) -> Result<(), AuthencError>;

    /// Revoke admin role from user
    async fn revoke_role(
        &self,
        user_id: &Uuid,
        realm_id: &Uuid,
        role_id: &Uuid,
    ) -> Result<(), AuthencError>;

    /// Get all admin assignments for a realm
    async fn get_realm_admins(
        &self,
        realm_id: &Uuid,
    ) -> Result<Vec<DelegatedAdminAssignment>, AuthencError>;

    /// Create a new delegated admin role
    async fn create_role(&self, role: DelegatedAdminRole) -> Result<Uuid, AuthencError>;

    /// Update an existing delegated admin role
    async fn update_role(&self, role: DelegatedAdminRole) -> Result<(), AuthencError>;

    /// Delete a delegated admin role
    async fn delete_role(&self, role_id: &Uuid) -> Result<(), AuthencError>;

    /// Get all roles for a realm
    async fn get_realm_roles(
        &self,
        realm_id: &Uuid,
    ) -> Result<Vec<DelegatedAdminRole>, AuthencError>;
}

/// Default implementation of delegated admin service
pub struct DefaultDelegatedAdminService {
    // In a real implementation, this would store data in a database
    roles: std::sync::RwLock<HashMap<Uuid, DelegatedAdminRole>>,
    assignments: std::sync::RwLock<HashMap<Uuid, DelegatedAdminAssignment>>,
}

impl Default for DefaultDelegatedAdminService {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultDelegatedAdminService {
    /// Create a new default delegated admin service
    pub fn new() -> Self {
        Self {
            roles: std::sync::RwLock::new(HashMap::new()),
            assignments: std::sync::RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl DelegatedAdminService for DefaultDelegatedAdminService {
    async fn has_permission(
        &self,
        user_id: &Uuid,
        realm_id: &Uuid,
        permission: &DelegatedAdminPermission,
    ) -> Result<bool, AuthencError> {
        let assignments = self.assignments.read().unwrap();
        let roles = self.roles.read().unwrap();

        // Find active assignments for this user in this realm
        for assignment in assignments.values() {
            if assignment.user_id == *user_id
                && assignment.realm_id == *realm_id
                && assignment.active
                && assignment
                    .expires_at
                    .map_or(true, |exp| chrono::Utc::now() < exp)
            {
                // Check if any of the user's roles grant this permission
                for role_id in &assignment.roles {
                    if let Some(role) = roles.get(role_id) {
                        if role.permissions.contains(permission) {
                            return Ok(true);
                        }
                        // Check composite roles recursively
                        if self.check_composite_permissions(role, permission, &roles) {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    async fn get_user_permissions(
        &self,
        user_id: &Uuid,
        realm_id: &Uuid,
    ) -> Result<HashSet<DelegatedAdminPermission>, AuthencError> {
        let assignments = self.assignments.read().unwrap();
        let roles = self.roles.read().unwrap();
        let mut permissions = HashSet::new();

        // Find active assignments for this user in this realm
        for assignment in assignments.values() {
            if assignment.user_id == *user_id
                && assignment.realm_id == *realm_id
                && assignment.active
                && assignment
                    .expires_at
                    .map_or(true, |exp| chrono::Utc::now() < exp)
            {
                // Collect permissions from all roles
                for role_id in &assignment.roles {
                    if let Some(role) = roles.get(role_id) {
                        permissions.extend(role.permissions.clone());
                        // Add permissions from composite roles
                        self.collect_composite_permissions(role, &mut permissions, &roles);
                    }
                }
            }
        }

        Ok(permissions)
    }

    async fn assign_role(
        &self,
        user_id: &Uuid,
        realm_id: &Uuid,
        role_id: &Uuid,
    ) -> Result<(), AuthencError> {
        let mut assignments = self.assignments.write().unwrap();

        // Find existing assignment or create new one
        let assignment_id = Uuid::new_v4();
        let assignment = DelegatedAdminAssignment {
            id: assignment_id,
            user_id: *user_id,
            realm_id: *realm_id,
            roles: vec![*role_id],
            active: true,
            created_at: chrono::Utc::now(),
            expires_at: None,
        };

        assignments.insert(assignment_id, assignment);
        Ok(())
    }

    async fn revoke_role(
        &self,
        user_id: &Uuid,
        realm_id: &Uuid,
        role_id: &Uuid,
    ) -> Result<(), AuthencError> {
        let mut assignments = self.assignments.write().unwrap();

        // Find and update assignment
        for assignment in assignments.values_mut() {
            if assignment.user_id == *user_id
                && assignment.realm_id == *realm_id
                && assignment.roles.contains(role_id)
            {
                assignment.roles.retain(|r| r != role_id);
                if assignment.roles.is_empty() {
                    assignment.active = false;
                }
                break;
            }
        }

        Ok(())
    }

    async fn get_realm_admins(
        &self,
        realm_id: &Uuid,
    ) -> Result<Vec<DelegatedAdminAssignment>, AuthencError> {
        let assignments = self.assignments.read().unwrap();
        let admins = assignments
            .values()
            .filter(|a| a.realm_id == *realm_id && a.active)
            .cloned()
            .collect();
        Ok(admins)
    }

    async fn create_role(&self, role: DelegatedAdminRole) -> Result<Uuid, AuthencError> {
        let mut roles = self.roles.write().unwrap();
        let role_id = role.id;
        roles.insert(role_id, role);
        Ok(role_id)
    }

    async fn update_role(&self, role: DelegatedAdminRole) -> Result<(), AuthencError> {
        let mut roles = self.roles.write().unwrap();
        roles.insert(role.id, role);
        Ok(())
    }

    async fn delete_role(&self, role_id: &Uuid) -> Result<(), AuthencError> {
        let mut roles = self.roles.write().unwrap();
        roles.remove(role_id);
        Ok(())
    }

    async fn get_realm_roles(
        &self,
        realm_id: &Uuid,
    ) -> Result<Vec<DelegatedAdminRole>, AuthencError> {
        let roles = self.roles.read().unwrap();
        let realm_roles = roles
            .values()
            .filter(|r| r.realm_id == *realm_id)
            .cloned()
            .collect();
        Ok(realm_roles)
    }
}

impl DefaultDelegatedAdminService {
    /// Helper method to check composite role permissions recursively
    fn check_composite_permissions(
        &self,
        role: &DelegatedAdminRole,
        permission: &DelegatedAdminPermission,
        all_roles: &HashMap<Uuid, DelegatedAdminRole>,
    ) -> bool {
        if !role.composite {
            return false;
        }

        for composite_id in &role.composites {
            if let Some(composite_role) = all_roles.get(composite_id) {
                if composite_role.permissions.contains(permission) {
                    return true;
                }
                // Recursively check composite roles
                if self.check_composite_permissions(composite_role, permission, all_roles) {
                    return true;
                }
            }
        }

        false
    }

    /// Helper method to collect permissions from composite roles
    fn collect_composite_permissions(
        &self,
        role: &DelegatedAdminRole,
        permissions: &mut HashSet<DelegatedAdminPermission>,
        all_roles: &HashMap<Uuid, DelegatedAdminRole>,
    ) {
        if !role.composite {
            return;
        }

        for composite_id in &role.composites {
            if let Some(composite_role) = all_roles.get(composite_id) {
                permissions.extend(composite_role.permissions.clone());
                // Recursively collect from composite roles
                self.collect_composite_permissions(composite_role, permissions, all_roles);
            }
        }
    }
}
