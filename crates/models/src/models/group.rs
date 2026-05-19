use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User group for organizing users
///
/// Represents a user group for organizing and managing users within a realm.
/// Groups can be hierarchical and used for bulk operations and access control.
///
/// # Fields
/// * `id` - Unique group identifier (UUID)
/// * `name` - Group name (unique within realm and parent)
/// * `path` - Full hierarchical path (e.g., /parent/child)
/// * `parent_id` - Optional parent group for hierarchy
/// * `description` - Optional human-readable description
/// * `attributes` - Custom attributes as JSON
/// * `realm_id` - ID of the realm this group belongs to
/// * `created_at` - Group creation timestamp
/// * `updated_at` - Last modification timestamp
///
/// # Security Considerations
/// - Groups are scoped to realms for multi-tenancy
/// - Group names should be unique within a realm and parent
/// - Groups can be used for access control and permissions
/// - Group membership affects user access levels
/// - Hierarchical structure allows inherited permissions
/// - Changes should trigger audit logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// Unique identifier for the group (UUID v4)
    pub id: Uuid,
    /// Human-readable name of the group (must be unique within the realm and parent)
    pub name: String,
    /// Full hierarchical path (e.g., /parent/child)
    pub path: String,
    /// Optional parent group ID for hierarchical groups
    pub parent_id: Option<Uuid>,
    /// Optional description of the group's purpose and membership criteria
    pub description: Option<String>,
    /// Custom attributes as JSON
    pub attributes: serde_json::Value,
    /// ID of the realm this group belongs to (enforces multi-tenancy)
    pub realm_id: Uuid,
    /// Timestamp when the group was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the group was last updated
    pub updated_at: DateTime<Utc>,
}

/// Group creation request
///
/// Parameters required to create a new user group.
/// Used when creating groups through the API.
///
/// # Fields
/// * `name` - Group name (must be unique within realm)
/// * `description` - Optional human-readable description
/// * `realm_id` - ID of the realm to create the group in
///
/// # Security Considerations
/// - Group names should follow naming conventions
/// - Realm ID must be validated before group creation
/// - Group creation should be authorized based on user permissions
/// - Input validation prevents malicious group names
#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    /// Group name (must be unique within realm)
    pub name: String,
    /// Optional human-readable description
    pub description: Option<String>,
    /// ID of the realm to create the group in
    pub realm_id: Uuid,
}

/// Group update request
///
/// Parameters for updating an existing user group.
/// All fields are optional to allow partial updates.
///
/// # Security Considerations
/// - Group name changes may affect existing memberships
/// - Parent changes affect hierarchical path
/// - Updates should be authorized based on user permissions
/// - Group name uniqueness must be maintained
/// - Changes should trigger audit logging
#[derive(Debug, Deserialize)]
pub struct UpdateGroupRequest {
    /// New group name (if updating)
    pub name: Option<String>,
    /// New parent group ID (if updating hierarchy)
    pub parent_id: Option<Uuid>,
    /// New description (if updating)
    pub description: Option<String>,
    /// New attributes (if updating)
    pub attributes: Option<serde_json::Value>,
}

/// Group response
///
/// Safe group information returned to clients.
/// Includes member count and hierarchical information.
///
/// # Fields
/// * `id` - Unique group identifier
/// * `name` - Group name
/// * `path` - Full hierarchical path
/// * `parent_id` - Optional parent group ID
/// * `description` - Group description
/// * `attributes` - Custom attributes
/// * `realm_id` - Realm the group belongs to
/// * `member_count` - Number of users in the group
/// * `subgroup_count` - Number of child groups
/// * `created_at` - Group creation timestamp
/// * `updated_at` - Last modification timestamp
///
/// # Security Considerations
/// - Provides necessary group metadata for client management
/// - Member count helps with group size management
/// - Hierarchical path shows group position
/// - Helps clients track group state and membership
/// - Realm scoping ensures proper data isolation
#[derive(Debug, Serialize)]
pub struct GroupResponse {
    /// Unique group identifier
    pub id: Uuid,
    /// Group name
    pub name: String,
    /// Full hierarchical path (e.g., /parent/child)
    pub path: String,
    /// Optional parent group ID
    pub parent_id: Option<Uuid>,
    /// Group description
    pub description: Option<String>,
    /// Custom attributes
    pub attributes: serde_json::Value,
    /// Realm the group belongs to
    pub realm_id: Uuid,
    /// Number of users in the group
    pub member_count: i64,
    /// Number of child groups
    pub subgroup_count: i64,
    /// Group creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,
}

impl From<Group> for GroupResponse {
    fn from(group: Group) -> Self {
        Self {
            id: group.id,
            name: group.name,
            path: group.path,
            parent_id: group.parent_id,
            description: group.description,
            attributes: group.attributes,
            realm_id: group.realm_id,
            member_count: 0,   // Will be populated by service
            subgroup_count: 0, // Will be populated by service
            created_at: group.created_at,
            updated_at: group.updated_at,
        }
    }
}
