/// Database queries for user management
pub mod users {
    pub const CREATE_USER: &str = r#"
        INSERT INTO users (id, username, email, password_hash, realm_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
    "#;

    pub const GET_USER_BY_ID: &str = r#"
        SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL
    "#;

    pub const GET_USER_BY_USERNAME: &str = r#"
        SELECT * FROM users WHERE username = $1 AND deleted_at IS NULL
    "#;

    pub const GET_USER_BY_EMAIL: &str = r#"
        SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL
    "#;

    pub const UPDATE_USER: &str = r#"
        UPDATE users 
        SET username = $2, email = $3, updated_at = $4
        WHERE id = $1 AND deleted_at IS NULL
        RETURNING *
    "#;

    pub const DELETE_USER: &str = r#"
        UPDATE users 
        SET deleted_at = $2, updated_at = $2
        WHERE id = $1 AND deleted_at IS NULL
    "#;

    pub const LIST_USERS: &str = r#"
        SELECT * FROM users 
        WHERE deleted_at IS NULL 
        ORDER BY created_at DESC 
        LIMIT $1 OFFSET $2
    "#;
}

/// Database queries for realm management
pub mod realms {
    pub const CREATE_REALM: &str = r#"
        INSERT INTO realms (id, name, display_name, description, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
    "#;

    pub const GET_REALM_BY_ID: &str = r#"
        SELECT * FROM realms WHERE id = $1 AND deleted_at IS NULL
    "#;

    pub const GET_REALM_BY_NAME: &str = r#"
        SELECT * FROM realms WHERE name = $1 AND deleted_at IS NULL
    "#;

    pub const LIST_REALMS: &str = r#"
        SELECT * FROM realms 
        WHERE deleted_at IS NULL 
        ORDER BY created_at DESC
    "#;

    pub const UPDATE_REALM: &str = r#"
        UPDATE realms 
        SET display_name = $2, description = $3, updated_at = $4
        WHERE id = $1 AND deleted_at IS NULL
        RETURNING *
    "#;

    pub const DELETE_REALM: &str = r#"
        UPDATE realms 
        SET deleted_at = $2, updated_at = $2
        WHERE id = $1 AND deleted_at IS NULL
    "#;
}

/// Database queries for role management
pub mod roles {
    pub const CREATE_ROLE: &str = r#"
        INSERT INTO roles (id, name, description, realm_id, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
    "#;

    pub const GET_ROLE_BY_ID: &str = r#"
        SELECT * FROM roles WHERE id = $1 AND deleted_at IS NULL
    "#;

    pub const LIST_ROLES_BY_REALM: &str = r#"
        SELECT * FROM roles 
        WHERE realm_id = $1 AND deleted_at IS NULL 
        ORDER BY created_at DESC
    "#;

    pub const ASSIGN_ROLE_TO_USER: &str = r#"
        INSERT INTO user_roles (user_id, role_id, assigned_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id, role_id) DO NOTHING
    "#;

    pub const REMOVE_ROLE_FROM_USER: &str = r#"
        DELETE FROM user_roles 
        WHERE user_id = $1 AND role_id = $2
    "#;

    pub const GET_USER_ROLES: &str = r#"
        SELECT r.* FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = $1 AND r.deleted_at IS NULL
    "#;
}

/// Database queries for audit logging
pub mod audit {
    pub const CREATE_AUDIT_LOG: &str = r#"
        INSERT INTO audit_logs (id, user_id, action, resource, details, ip_address, user_agent, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    "#;

    pub const GET_AUDIT_LOGS: &str = r#"
        SELECT * FROM audit_logs 
        WHERE ($1::uuid IS NULL OR user_id = $1)
        AND ($2::text IS NULL OR action = $2)
        AND created_at >= $3
        AND created_at <= $4
        ORDER BY created_at DESC 
        LIMIT $5 OFFSET $6
    "#;

    pub const GET_AUDIT_LOG_COUNT: &str = r#"
        SELECT COUNT(*) FROM audit_logs 
        WHERE ($1::uuid IS NULL OR user_id = $1)
        AND ($2::text IS NULL OR action = $2)
        AND created_at >= $3
        AND created_at <= $4
    "#;
}
