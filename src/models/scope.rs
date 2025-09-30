use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Scope entity for resource permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    /// Unique identifier for the scope
    pub id: Uuid,
    /// Name of the scope
    pub name: String,
    /// Display name of the scope
    pub display_name: Option<String>,
    /// Icon URI for the scope
    pub icon_uri: Option<String>,
    /// ID of the realm this scope belongs to
    pub realm_id: Uuid,
    /// ID of the resource server this scope belongs to
    pub resource_server_id: Uuid,
    /// Timestamp when the scope was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the scope was last updated
    pub updated_at: DateTime<Utc>,
}

/// Scope creation request
#[derive(Debug, Deserialize)]
pub struct CreateScopeRequest {
    /// Name of the scope
    pub name: String,
    /// Display name of the scope
    pub display_name: Option<String>,
    /// Icon URI for the scope
    pub icon_uri: Option<String>,
}

/// Scope update request
#[derive(Debug, Deserialize)]
pub struct UpdateScopeRequest {
    /// New display name for the scope
    pub display_name: Option<String>,
    /// New icon URI for the scope
    pub icon_uri: Option<String>,
}

/// Scope response
#[derive(Debug, Serialize)]
pub struct ScopeResponse {
    /// Unique identifier for the scope
    pub id: Uuid,
    /// Name of the scope
    pub name: String,
    /// Display name of the scope
    pub display_name: Option<String>,
    /// Icon URI for the scope
    pub icon_uri: Option<String>,
    /// ID of the realm this scope belongs to
    pub realm_id: Uuid,
    /// ID of the resource server this scope belongs to
    pub resource_server_id: Uuid,
    /// Timestamp when the scope was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the scope was last updated
    pub updated_at: DateTime<Utc>,
}

impl From<Scope> for ScopeResponse {
    fn from(scope: Scope) -> Self {
        Self {
            id: scope.id,
            name: scope.name,
            display_name: scope.display_name,
            icon_uri: scope.icon_uri,
            realm_id: scope.realm_id,
            resource_server_id: scope.resource_server_id,
            created_at: scope.created_at,
            updated_at: scope.updated_at,
        }
    }
}

impl Scope {
    /// Create a new scope
    pub fn new(name: String, realm_id: Uuid, resource_server_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            display_name: None,
            icon_uri: None,
            realm_id,
            resource_server_id,
            created_at: now,
            updated_at: now,
        }
    }

    /// Update scope fields
    pub fn update(&mut self, request: UpdateScopeRequest) {
        if let Some(display_name) = request.display_name {
            self.display_name = Some(display_name);
        }
        if let Some(icon_uri) = request.icon_uri {
            self.icon_uri = Some(icon_uri);
        }
        self.updated_at = Utc::now();
    }
}
