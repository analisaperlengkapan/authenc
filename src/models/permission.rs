use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Permission entity for fine-grained access control
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    pub id: Uuid,
    pub name: String,
    pub resource: String,
    pub action: String,
    pub description: Option<String>,
    pub realm_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Permission creation request
#[derive(Debug, Deserialize)]
pub struct CreatePermissionRequest {
    pub name: String,
    pub resource: String,
    pub action: String,
    pub description: Option<String>,
    pub realm_id: Uuid,
}

/// Permission update request
#[derive(Debug, Deserialize)]
pub struct UpdatePermissionRequest {
    pub name: Option<String>,
    pub resource: Option<String>,
    pub action: Option<String>,
    pub description: Option<String>,
}

/// Permission response
#[derive(Debug, Serialize)]
pub struct PermissionResponse {
    pub id: Uuid,
    pub name: String,
    pub resource: String,
    pub action: String,
    pub description: Option<String>,
    pub realm_id: Uuid,
    pub created_at: DateTime<Utc>,
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
