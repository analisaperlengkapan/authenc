/// Database queries for user management
/// 
/// Contains SQL queries for user CRUD operations, authentication, and user data retrieval.
/// All queries include soft delete filtering (deleted_at IS NULL) for data integrity.
/// 
/// # Security Considerations
/// - Password hashes are stored securely using bcrypt/scrypt
/// - User data is filtered by realm for multi-tenancy
/// - Soft deletes preserve referential integrity
/// - All queries use parameterized statements to prevent SQL injection
pub mod users {
    /// Create a new user record
    /// 
    /// Inserts a new user into the database with all required fields.
    /// Returns the created user record with generated timestamps.
    /// 
    /// # Parameters
    /// - $1: user ID (UUID)
    /// - $2: username (unique within realm)
    /// - $3: email address
    /// - $4: password hash (bcrypt/scrypt)
    /// - $5: realm ID
    /// - $6: created_at timestamp
    /// - $7: updated_at timestamp
    pub const CREATE_USER: &str = r#"
        INSERT INTO users (id, username, email, password_hash, realm_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
    "#;

    /// Get user by ID
    /// 
    /// Retrieves a user record by their unique identifier.
    /// Only returns active (non-deleted) users.
    /// 
    /// # Parameters
    /// - $1: user ID (UUID)
    pub const GET_USER_BY_ID: &str = r#"
        SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL
    "#;

    /// Get user by username
    /// 
    /// Retrieves a user record by their username.
    /// Used during authentication and user lookup operations.
    /// 
    /// # Parameters
    /// - $1: username (string)
    pub const GET_USER_BY_USERNAME: &str = r#"
        SELECT * FROM users WHERE username = $1 AND deleted_at IS NULL
    "#;

    /// Get user by email
    /// 
    /// Retrieves a user record by their email address.
    /// Used for password reset and email-based authentication.
    /// 
    /// # Parameters
    /// - $1: email address (string)
    pub const GET_USER_BY_EMAIL: &str = r#"
        SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL
    "#;

    /// Update user information
    /// 
    /// Updates user profile information (username, email).
    /// Password updates are handled separately for security.
    /// 
    /// # Parameters
    /// - $1: user ID (UUID)
    /// - $2: new username
    /// - $3: new email address
    /// - $4: updated_at timestamp
    pub const UPDATE_USER: &str = r#"
        UPDATE users 
        SET username = $2, email = $3, updated_at = $4
        WHERE id = $1 AND deleted_at IS NULL
        RETURNING *
    "#;

    /// Soft delete user
    /// 
    /// Marks a user as deleted without removing the record.
    /// Preserves referential integrity and audit trails.
    /// 
    /// # Parameters
    /// - $1: user ID (UUID)
    /// - $2: deleted_at timestamp
    pub const DELETE_USER: &str = r#"
        UPDATE users 
        SET deleted_at = $2, updated_at = $2
        WHERE id = $1 AND deleted_at IS NULL
    "#;

    /// List users with pagination
    /// 
    /// Retrieves a paginated list of active users.
    /// Ordered by creation date (newest first).
    /// 
    /// # Parameters
    /// - $1: limit (number of records)
    /// - $2: offset (pagination offset)
    pub const LIST_USERS: &str = r#"
        SELECT * FROM users 
        WHERE deleted_at IS NULL 
        ORDER BY created_at DESC 
        LIMIT $1 OFFSET $2
    "#;
}

/// Database queries for realm management
/// 
/// Contains SQL queries for realm CRUD operations and multi-tenancy support.
/// Realms provide logical separation of users, roles, and resources.
/// 
/// # Security Considerations
/// - Realms enforce multi-tenancy isolation
/// - Realm-scoped queries prevent data leakage between tenants
/// - Soft deletes maintain referential integrity
/// - All queries use parameterized statements
pub mod realms {
    /// Create a new realm
    /// 
    /// Inserts a new realm record for multi-tenancy support.
    /// Returns the created realm with generated timestamps.
    /// 
    /// # Parameters
    /// - $1: realm ID (UUID)
    /// - $2: realm name (unique identifier)
    /// - $3: display name (human-readable)
    /// - $4: description
    /// - $5: created_at timestamp
    /// - $6: updated_at timestamp
    pub const CREATE_REALM: &str = r#"
        INSERT INTO realms (id, name, display_name, description, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
    "#;

    /// Get realm by ID
    /// 
    /// Retrieves a realm record by its unique identifier.
    /// Only returns active (non-deleted) realms.
    /// 
    /// # Parameters
    /// - $1: realm ID (UUID)
    pub const GET_REALM_BY_ID: &str = r#"
        SELECT * FROM realms WHERE id = $1 AND deleted_at IS NULL
    "#;

    /// Get realm by name
    /// 
    /// Retrieves a realm record by its name identifier.
    /// Used for realm resolution during authentication.
    /// 
    /// # Parameters
    /// - $1: realm name (string)
    pub const GET_REALM_BY_NAME: &str = r#"
        SELECT * FROM realms WHERE name = $1 AND deleted_at IS NULL
    "#;

    /// List all realms
    /// 
    /// Retrieves all active realms in the system.
    /// Used for realm selection and administration.
    pub const LIST_REALMS: &str = r#"
        SELECT * FROM realms 
        WHERE deleted_at IS NULL 
        ORDER BY created_at DESC
    "#;

    /// Update realm information
    /// 
    /// Updates realm metadata (display name, description).
    /// Core realm name cannot be changed for consistency.
    /// 
    /// # Parameters
    /// - $1: realm ID (UUID)
    /// - $2: new display name
    /// - $3: new description
    /// - $4: updated_at timestamp
    pub const UPDATE_REALM: &str = r#"
        UPDATE realms 
        SET display_name = $2, description = $3, updated_at = $4
        WHERE id = $1 AND deleted_at IS NULL
        RETURNING *
    "#;

    /// Soft delete realm
    /// 
    /// Marks a realm as deleted without removing the record.
    /// Cascading effects should be handled by application logic.
    /// 
    /// # Parameters
    /// - $1: realm ID (UUID)
    /// - $2: deleted_at timestamp
    pub const DELETE_REALM: &str = r#"
        UPDATE realms 
        SET deleted_at = $2, updated_at = $2
        WHERE id = $1 AND deleted_at IS NULL
    "#;
}

/// Database queries for role management
/// 
/// Contains SQL queries for role-based access control (RBAC) operations.
/// Manages roles, user-role assignments, and permission structures.
/// 
/// # Security Considerations
/// - Roles are scoped to realms for multi-tenancy
/// - User-role assignments control access permissions
/// - Role changes should trigger permission cache invalidation
/// - All queries prevent privilege escalation
pub mod roles {
    /// Create a new role
    /// 
    /// Inserts a new role record within a specific realm.
    /// Returns the created role with generated timestamps.
    /// 
    /// # Parameters
    /// - $1: role ID (UUID)
    /// - $2: role name (unique within realm)
    /// - $3: role description
    /// - $4: realm ID
    /// - $5: created_at timestamp
    /// - $6: updated_at timestamp
    pub const CREATE_ROLE: &str = r#"
        INSERT INTO roles (id, name, description, realm_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
    "#;

    /// Get role by ID
    /// 
    /// Retrieves a role record by its unique identifier.
    /// Only returns active (non-deleted) roles.
    /// 
    /// # Parameters
    /// - $1: role ID (UUID)
    pub const GET_ROLE_BY_ID: &str = r#"
        SELECT * FROM roles WHERE id = $1 AND deleted_at IS NULL
    "#;

    /// List roles by realm
    /// 
    /// Retrieves all roles within a specific realm.
    /// Used for role assignment and permission management.
    /// 
    /// # Parameters
    /// - $1: realm ID (UUID)
    pub const LIST_ROLES_BY_REALM: &str = r#"
        SELECT * FROM roles 
        WHERE realm_id = $1 AND deleted_at IS NULL 
        ORDER BY created_at DESC
    "#;

    /// Assign role to user
    /// 
    /// Creates a user-role assignment relationship.
    /// Uses ON CONFLICT DO NOTHING to prevent duplicate assignments.
    /// 
    /// # Parameters
    /// - $1: user ID (UUID)
    /// - $2: role ID (UUID)
    /// - $3: assignment timestamp
    pub const ASSIGN_ROLE_TO_USER: &str = r#"
        INSERT INTO user_roles (user_id, role_id, assigned_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, role_id) DO NOTHING
    "#;

    /// Remove role from user
    /// 
    /// Removes a user-role assignment relationship.
    /// Immediately revokes the role's permissions from the user.
    /// 
    /// # Parameters
    /// - $1: user ID (UUID)
    /// - $2: role ID (UUID)
    pub const REMOVE_ROLE_FROM_USER: &str = r#"
        DELETE FROM user_roles 
        WHERE user_id = $1 AND role_id = $2
    "#;

    /// Get user roles
    /// 
    /// Retrieves all roles assigned to a specific user.
    /// Used for permission checking and access control decisions.
    /// 
    /// # Parameters
    /// - $1: user ID (UUID)
    pub const GET_USER_ROLES: &str = r#"
        SELECT r.* FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = $1 AND r.deleted_at IS NULL
    "#;
}

/// Database queries for audit logging
/// 
/// Contains SQL queries for comprehensive audit logging and compliance.
/// Tracks all security-relevant actions, user activities, and system events.
/// 
/// # Security Considerations
/// - Audit logs are immutable and append-only
/// - All security events must be logged for compliance
/// - IP addresses and user agents are captured for forensics
/// - Timestamps ensure chronological ordering
/// - Filtering supports compliance reporting requirements
pub mod audit {
    /// Create audit log entry
    /// 
    /// Inserts a new audit log record for security monitoring.
    /// Captures user actions, system events, and security-relevant activities.
    /// 
    /// # Parameters
    /// - $1: audit log ID (UUID)
    /// - $2: user ID (UUID, nullable for system events)
    /// - $3: action performed (string)
    /// - $4: resource affected (string)
    /// - $5: action details (JSON/text)
    /// - $6: client IP address
    /// - $7: user agent string
    /// - $8: event timestamp
    pub const CREATE_AUDIT_LOG: &str = r#"
        INSERT INTO audit_logs (id, user_id, action, resource, details, ip_address, user_agent, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    "#;

    /// Get audit logs with filtering
    /// 
    /// Retrieves paginated audit log entries with optional filtering.
    /// Supports filtering by user, action type, and date range.
    /// 
    /// # Parameters
    /// - $1: user ID filter (UUID, nullable)
    /// - $2: action filter (string, nullable)
    /// - $3: start date (timestamp)
    /// - $4: end date (timestamp)
    /// - $5: limit (number of records)
    /// - $6: offset (pagination offset)
    pub const GET_AUDIT_LOGS: &str = r#"
        SELECT * FROM audit_logs 
        WHERE ($1::uuid IS NULL OR user_id = $1)
        AND ($2::text IS NULL OR action = $2)
        AND created_at >= $3
        AND created_at <= $4
        ORDER BY created_at DESC 
        LIMIT $5 OFFSET $6
    "#;

    /// Get audit log count
    /// 
    /// Returns the total count of audit log entries matching filters.
    /// Used for pagination and reporting purposes.
    /// 
    /// # Parameters
    /// - $1: user ID filter (UUID, nullable)
    /// - $2: action filter (string, nullable)
    /// - $3: start date (timestamp)
    /// - $4: end date (timestamp)
    pub const GET_AUDIT_LOG_COUNT: &str = r#"
        SELECT COUNT(*) FROM audit_logs 
        WHERE ($1::uuid IS NULL OR user_id = $1)
        AND ($2::text IS NULL OR action = $2)
        AND created_at >= $3
        AND created_at <= $4
    "#;
}
