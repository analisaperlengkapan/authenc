use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Resource entity for fine-grained authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    /// Unique identifier for the resource
    pub id: Uuid,
    /// Name of the resource
    pub name: String,
    /// Display name of the resource
    pub display_name: Option<String>,
    /// URIs associated with the resource
    pub uris: Vec<String>,
    /// Icon URI for the resource
    pub icon_uri: Option<String>,
    /// Type of the resource
    pub resource_type: Option<String>,
    /// Owner of the resource (user ID)
    pub owner: String,
    /// Whether the resource is enabled
    pub enabled: bool,
    /// ID of the realm this resource belongs to
    pub realm_id: Uuid,
    /// ID of the resource server this resource belongs to
    pub resource_server_id: Uuid,
    /// Scopes associated with this resource
    pub scopes: Vec<String>,
    /// Additional attributes
    pub attributes: std::collections::HashMap<String, Vec<String>>,
    /// Timestamp when the resource was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the resource was last updated
    pub updated_at: DateTime<Utc>,
}

/// Resource creation request
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateResourceRequest {
    /// Name of the resource
    pub name: String,
    /// Display name of the resource
    pub display_name: Option<String>,
    /// URIs associated with the resource
    pub uris: Option<Vec<String>>,
    /// Icon URI for the resource
    pub icon_uri: Option<String>,
    /// Type of the resource
    pub resource_type: Option<String>,
    /// Owner of the resource (user ID)
    pub owner: Option<String>,
    /// Scopes associated with this resource
    pub scopes: Option<Vec<String>>,
    /// Additional attributes
    pub attributes: Option<std::collections::HashMap<String, Vec<String>>>,
}

/// Resource update request
#[derive(Debug, Deserialize)]
pub struct UpdateResourceRequest {
    /// New display name for the resource
    pub display_name: Option<String>,
    /// New URIs for the resource
    pub uris: Option<Vec<String>>,
    /// New icon URI for the resource
    pub icon_uri: Option<String>,
    /// New type for the resource
    pub resource_type: Option<String>,
    /// New owner for the resource
    pub owner: Option<String>,
    /// New scopes for the resource
    pub scopes: Option<Vec<String>>,
    /// New attributes for the resource
    pub attributes: Option<std::collections::HashMap<String, Vec<String>>>,
}

/// Resource response
#[derive(Debug, Serialize)]
pub struct ResourceResponse {
    /// Unique identifier for the resource
    pub id: Uuid,
    /// Name of the resource
    pub name: String,
    /// Display name of the resource
    pub display_name: Option<String>,
    /// URIs associated with the resource
    pub uris: Vec<String>,
    /// Icon URI for the resource
    pub icon_uri: Option<String>,
    /// Type of the resource
    pub resource_type: Option<String>,
    /// Owner of the resource (user ID)
    pub owner: String,
    /// Whether the resource is enabled
    pub enabled: bool,
    /// ID of the realm this resource belongs to
    pub realm_id: Uuid,
    /// ID of the resource server this resource belongs to
    pub resource_server_id: Uuid,
    /// Scopes associated with this resource
    pub scopes: Vec<String>,
    /// Additional attributes
    pub attributes: std::collections::HashMap<String, Vec<String>>,
    /// Timestamp when the resource was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the resource was last updated
    pub updated_at: DateTime<Utc>,
}

impl From<Resource> for ResourceResponse {
    fn from(resource: Resource) -> Self {
        Self {
            id: resource.id,
            name: resource.name,
            display_name: resource.display_name,
            uris: resource.uris,
            icon_uri: resource.icon_uri,
            resource_type: resource.resource_type,
            owner: resource.owner,
            enabled: resource.enabled,
            realm_id: resource.realm_id,
            resource_server_id: resource.resource_server_id,
            scopes: resource.scopes,
            attributes: resource.attributes,
            created_at: resource.created_at,
            updated_at: resource.updated_at,
        }
    }
}

impl Resource {
    /// Create a new resource
    pub fn new(name: String, owner: String, realm_id: Uuid, resource_server_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            display_name: None,
            uris: Vec::new(),
            icon_uri: None,
            resource_type: None,
            owner,
            enabled: true,
            realm_id,
            resource_server_id,
            scopes: Vec::new(),
            attributes: std::collections::HashMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Update resource fields
    pub fn update(&mut self, request: UpdateResourceRequest) {
        if let Some(display_name) = request.display_name {
            self.display_name = Some(display_name);
        }
        if let Some(uris) = request.uris {
            self.uris = uris;
        }
        if let Some(icon_uri) = request.icon_uri {
            self.icon_uri = Some(icon_uri);
        }
        if let Some(resource_type) = request.resource_type {
            self.resource_type = Some(resource_type);
        }
        if let Some(owner) = request.owner {
            self.owner = owner;
        }
        if let Some(scopes) = request.scopes {
            self.scopes = scopes;
        }
        if let Some(attributes) = request.attributes {
            self.attributes = attributes;
        }
        self.updated_at = Utc::now();
    }

    /// Check if resource is active
    pub fn is_active(&self) -> bool {
        self.enabled
    }

    /// Disable the resource
    pub fn disable(&mut self) {
        self.enabled = false;
        self.updated_at = Utc::now();
    }

    /// Enable the resource
    pub fn enable(&mut self) {
        self.enabled = true;
        self.updated_at = Utc::now();
    }
}
