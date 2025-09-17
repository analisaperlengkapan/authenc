use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Permission entity for fine-grained access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// Unique identifier for the permission
    pub id: Uuid,
    /// Name of the permission
    pub name: String,
    /// Resource this permission applies to
    pub resource: String,
    /// Action allowed on the resource (read, write, delete, etc.)
    pub action: String,
    /// Description of what this permission allows
    pub description: Option<String>,
    /// ID of the realm this permission belongs to
    pub realm_id: Uuid,
    /// Timestamp when the permission was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the permission was last updated
    pub updated_at: DateTime<Utc>,
    /// Timestamp when the permission was soft deleted
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Permission creation request
#[derive(Debug, Deserialize)]
pub struct CreatePermissionRequest {
    /// Name of the permission to create
    pub name: String,
    /// Resource this permission applies to
    pub resource: String,
    /// Action allowed on the resource
    pub action: String,
    /// Description of what this permission allows
    pub description: Option<String>,
    /// ID of the realm this permission belongs to
    pub realm_id: Uuid,
}

/// Permission update request
#[derive(Debug, Deserialize)]
pub struct UpdatePermissionRequest {
    /// New name for the permission
    pub name: Option<String>,
    /// New resource for the permission
    pub resource: Option<String>,
    /// New action for the permission
    pub action: Option<String>,
    /// New description for the permission
    pub description: Option<String>,
}

/// Permission response
#[derive(Debug, Serialize)]
pub struct PermissionResponse {
    /// Unique identifier for the permission
    pub id: Uuid,
    /// Name of the permission
    pub name: String,
    /// Resource this permission applies to
    pub resource: String,
    /// Action allowed on the resource
    pub action: String,
    /// Description of what this permission allows
    pub description: Option<String>,
    /// ID of the realm this permission belongs to
    pub realm_id: Uuid,
    /// Timestamp when the permission was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the permission was last updated
    pub updated_at: DateTime<Utc>,
}

impl From<Permission> for PermissionResponse {
    fn from(permission: Permission) -> Self {
        Self {
            id: permission.id,
            name: permission.name,
            resource: permission.resource,
            action: permission.action,
            description: permission.description,
            realm_id: permission.realm_id,
            created_at: permission.created_at,
            updated_at: permission.updated_at,
        }
    }
}

impl Permission {
    /// Create a new permission
    pub fn new(
        name: String,
        resource: String,
        action: String,
        description: Option<String>,
        realm_id: Uuid,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            resource,
            action,
            description,
            realm_id,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    /// Check if permission is active
    pub fn is_active(&self) -> bool {
        self.deleted_at.is_none()
    }

    /// Soft delete the permission
    pub fn delete(&mut self) {
        self.deleted_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Update permission fields
    pub fn update(&mut self, request: UpdatePermissionRequest) {
        if let Some(name) = request.name {
            self.name = name;
        }
        if let Some(resource) = request.resource {
            self.resource = resource;
        }
        if let Some(action) = request.action {
            self.action = action;
        }
        if let Some(description) = request.description {
            self.description = Some(description);
        }
        self.updated_at = Utc::now();
    }

    /// Get permission key in format "resource:action"
    pub fn get_key(&self) -> String {
        format!("{}:{}", self.resource, self.action)
    }
}
