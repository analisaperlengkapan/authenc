use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Role entity for role-based access control
/// 
/// Represents a role in the role-based access control (RBAC) system.
/// Roles define permissions and access levels for users within a realm.
/// 
/// # Fields
/// * `id` - Unique role identifier (UUID)
/// * `name` - Role name (unique within realm)
/// * `description` - Optional human-readable description
/// * `realm_id` - ID of the realm this role belongs to
/// * `composite` - Whether this is a composite role (contains other roles)
/// * `client_role` - Whether this is a client-specific role
/// * `client_id` - Client identifier if this is a client role
/// * `attributes` - Additional role attributes as JSON
/// * `created_at` - Role creation timestamp
/// * `updated_at` - Last modification timestamp
/// * `deleted_at` - Soft delete timestamp (None if active)
/// 
/// # Security Considerations
/// - Roles are scoped to realms for multi-tenancy
/// - Role names should be unique within a realm
/// - Soft deletes preserve referential integrity
/// - Role changes should trigger permission cache invalidation
/// - Role assignments control user access permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// Unique identifier for the role (UUID v4)
    pub id: Uuid,
    /// Human-readable name of the role (must be unique within the realm)
    pub name: String,
    /// Optional description of the role's purpose and permissions
    pub description: Option<String>,
    /// ID of the realm this role belongs to (enforces multi-tenancy)
    pub realm_id: Option<Uuid>,
    /// Whether this is a composite role (contains other roles)
    pub composite: bool,
    /// Whether this is a client-specific role
    pub client_role: bool,
    /// Client identifier if this is a client role
    pub client_id: Option<String>,
    /// Additional role attributes as JSON
    pub attributes: Option<serde_json::Value>,
    /// Timestamp when the role was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the role was last updated
    pub updated_at: DateTime<Utc>,
    /// Timestamp when the role was soft-deleted (None if active)
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Role creation request
/// 
/// Parameters required to create a new role.
/// Used when creating roles through the API.
/// 
/// # Fields
/// * `name` - Role name (must be unique within realm)
/// * `description` - Optional human-readable description
/// * `realm_id` - ID of the realm to create the role in
/// 
/// # Security Considerations
/// - Role names should follow naming conventions
/// - Realm ID must be validated before role creation
/// - Role creation should be authorized based on user permissions
/// - Input validation prevents malicious role names
#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    /// Role name (must be unique within realm)
    pub name: String,
    /// Optional human-readable description
    pub description: Option<String>,
    /// ID of the realm to create the role in
    pub realm_id: Uuid,
}

/// Role update request
/// 
/// Parameters for updating an existing role.
/// All fields are optional to allow partial updates.
/// 
/// # Fields
/// * `name` - New role name (if updating)
/// * `description` - New description (if updating)
/// 
/// # Security Considerations
/// - Role name changes may affect existing permissions
/// - Updates should be authorized based on user permissions
/// - Role name uniqueness must be maintained
/// - Changes should trigger audit logging
#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    /// New role name (if updating)
    pub name: Option<String>,
    /// New description (if updating)
    pub description: Option<String>,
}

/// Role response
/// 
/// Safe role information returned to clients.
/// Excludes sensitive internal fields.
/// 
/// # Fields
/// * `id` - Unique role identifier
/// * `name` - Role name
/// * `description` - Role description
/// * `realm_id` - Realm the role belongs to
/// * `created_at` - Role creation timestamp
/// * `updated_at` - Last modification timestamp
/// 
/// # Security Considerations
/// - Never includes deleted_at in responses
/// - Provides necessary role metadata for client management
/// - Helps clients track role state and permissions
/// - Realm scoping ensures proper data isolation
#[derive(Debug, Serialize)]
pub struct RoleResponse {
    /// Unique role identifier
    pub id: Uuid,
    /// Role name
    pub name: String,
    /// Role description
    pub description: Option<String>,
    /// Realm the role belongs to
    pub realm_id: Uuid,
    /// Role creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,
}

impl From<Role> for RoleResponse {
    fn from(role: Role) -> Self {
        Self {
            id: role.id,
            name: role.name,
            description: role.description,
            realm_id: role.realm_id.unwrap_or_else(Uuid::new_v4),
            created_at: role.created_at,
            updated_at: role.updated_at,
        }
    }
}

impl Role {
    /// Create a new role
    /// 
    /// Creates a new role instance with generated ID and timestamps.
    /// Initializes role with provided parameters.
    /// 
    /// # Arguments
    /// * `name` - Role name (should be unique within realm)
    /// * `description` - Optional human-readable description
    /// * `realm_id` - ID of the realm this role belongs to
    /// 
    /// # Returns
    /// A new Role instance ready for use
    /// 
    /// # Security Considerations
    /// - Generates cryptographically secure UUID for role ID
    /// - Sets appropriate creation and update timestamps
    /// - Role should be validated for uniqueness before creation
    pub fn new(name: String, description: Option<String>, realm_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            description,
            realm_id: Some(realm_id),
            composite: false,
            client_role: false,
            client_id: None,
            attributes: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }

    /// Check if role is active
    /// 
    /// Determines if the role is currently active (not soft deleted).
    /// Used for permission checks and role validation.
    /// 
    /// # Returns
    /// true if the role is active and can be used
    /// 
    /// # Security Considerations
    /// - Inactive roles should not grant permissions
    /// - Soft deleted roles maintain referential integrity
    /// - Role status affects user access control
    pub fn is_active(&self) -> bool {
        self.deleted_at.is_none()
    }

    /// Soft delete the role
    /// 
    /// Marks the role as deleted without removing the record.
    /// Preserves referential integrity and audit trails.
    /// 
    /// # Security Considerations
    /// - Immediately revokes role permissions
    /// - Preserves audit trail of role existence
    /// - Cascading effects should be handled by application logic
    /// - Role deletion should trigger permission cache invalidation
    pub fn delete(&mut self) {
        self.deleted_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Update role fields
    /// 
    /// Updates role information based on the update request.
    /// Only updates fields that are provided in the request.
    /// 
    /// # Arguments
    /// * `request` - Update parameters (partial update supported)
    /// 
    /// # Security Considerations
    /// - Role name changes may affect existing permissions
    /// - Updates should be authorized based on user permissions
    /// - Role name uniqueness must be maintained
    /// - Changes should trigger audit logging
    pub fn update(&mut self, request: UpdateRoleRequest) {
        if let Some(name) = request.name {
            self.name = name;
        }
        if let Some(description) = request.description {
            self.description = Some(description);
        }
        self.updated_at = Utc::now();
    }
}
