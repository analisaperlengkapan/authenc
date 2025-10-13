// Advanced Authorization Tests
// Testing role-based access control, permissions, policies, and access management

use axum::{
    Router,
    extract::{Json, State},
    http::StatusCode,
    routing::{get, post},
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
struct AuthzState {
    users: Arc<Mutex<HashMap<String, UserProfile>>>,
    roles: Arc<Mutex<HashMap<String, Role>>>,
    permissions: Arc<Mutex<HashMap<String, Permission>>>,
    policies: Arc<Mutex<HashMap<String, Policy>>>,
    resources: Arc<Mutex<HashMap<String, Resource>>>,
    user_roles: Arc<Mutex<HashMap<String, Vec<String>>>>, // user_id -> role_ids
    role_permissions: Arc<Mutex<HashMap<String, Vec<String>>>>, // role_id -> permission_ids
}

#[derive(Clone)]
struct UserProfile {
    id: String,
    email: String,
    department: String,
    manager_id: Option<String>,
    is_active: bool,
}

#[derive(Clone)]
struct Role {
    id: String,
    name: String,
    description: String,
    is_system_role: bool,
    created_at: String,
}

#[derive(Clone)]
struct Permission {
    id: String,
    name: String,
    resource: String,
    action: String, // read, write, delete, admin
    description: String,
}

#[derive(Clone)]
struct Policy {
    id: String,
    name: String,
    effect: String, // allow, deny
    conditions: Vec<Condition>,
    principals: Vec<String>, // user or role IDs
    resources: Vec<String>,
    actions: Vec<String>,
}

#[derive(Clone)]
struct Condition {
    key: String,
    operator: String, // equals, contains, greater_than, etc.
    value: String,
}

#[derive(Clone)]
struct Resource {
    id: String,
    name: String,
    resource_type: String,
    owner_id: String,
    is_public: bool,
    tags: Vec<String>,
}

impl AuthzState {
    fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            roles: Arc::new(Mutex::new(HashMap::new())),
            permissions: Arc::new(Mutex::new(HashMap::new())),
            policies: Arc::new(Mutex::new(HashMap::new())),
            resources: Arc::new(Mutex::new(HashMap::new())),
            user_roles: Arc::new(Mutex::new(HashMap::new())),
            role_permissions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tokio::test]
async fn test_role_based_access_control() {
    let authz_state = AuthzState::new();

    // Pre-populate with test data
    {
        let mut users = authz_state.users.lock().await;
        let mut roles = authz_state.roles.lock().await;
        let mut permissions = authz_state.permissions.lock().await;
        let mut user_roles = authz_state.user_roles.lock().await;
        let mut role_permissions = authz_state.role_permissions.lock().await;

        // Create users
        users.insert(
            "user_123".to_string(),
            UserProfile {
                id: "user_123".to_string(),
                email: "employee@example.com".to_string(),
                department: "Engineering".to_string(),
                manager_id: Some("user_manager".to_string()),
                is_active: true,
            },
        );

        users.insert(
            "user_manager".to_string(),
            UserProfile {
                id: "user_manager".to_string(),
                email: "manager@example.com".to_string(),
                department: "Engineering".to_string(),
                manager_id: None,
                is_active: true,
            },
        );

        // Create roles
        roles.insert(
            "role_employee".to_string(),
            Role {
                id: "role_employee".to_string(),
                name: "Employee".to_string(),
                description: "Basic employee role".to_string(),
                is_system_role: false,
                created_at: "2024-12-01T10:00:00Z".to_string(),
            },
        );

        roles.insert(
            "role_manager".to_string(),
            Role {
                id: "role_manager".to_string(),
                name: "Manager".to_string(),
                description: "Department manager role".to_string(),
                is_system_role: false,
                created_at: "2024-12-01T10:00:00Z".to_string(),
            },
        );

        // Create permissions
        permissions.insert(
            "perm_read_docs".to_string(),
            Permission {
                id: "perm_read_docs".to_string(),
                name: "Read Documents".to_string(),
                resource: "documents".to_string(),
                action: "read".to_string(),
                description: "Can read documents".to_string(),
            },
        );

        permissions.insert(
            "perm_write_docs".to_string(),
            Permission {
                id: "perm_write_docs".to_string(),
                name: "Write Documents".to_string(),
                resource: "documents".to_string(),
                action: "write".to_string(),
                description: "Can create and edit documents".to_string(),
            },
        );

        permissions.insert(
            "perm_manage_users".to_string(),
            Permission {
                id: "perm_manage_users".to_string(),
                name: "Manage Users".to_string(),
                resource: "users".to_string(),
                action: "admin".to_string(),
                description: "Can manage user accounts".to_string(),
            },
        );

        // Assign roles to users
        user_roles.insert("user_123".to_string(), vec!["role_employee".to_string()]);
        user_roles.insert(
            "user_manager".to_string(),
            vec!["role_employee".to_string(), "role_manager".to_string()],
        );

        // Assign permissions to roles
        role_permissions.insert(
            "role_employee".to_string(),
            vec!["perm_read_docs".to_string()],
        );
        role_permissions.insert(
            "role_manager".to_string(),
            vec![
                "perm_read_docs".to_string(),
                "perm_write_docs".to_string(),
                "perm_manage_users".to_string(),
            ],
        );
    }

    let app = Router::new()
        .route("/authz/check", post(move |State(state): State<AuthzState>, Json(check): Json<serde_json::Value>| async move {
            let user_roles = state.user_roles.lock().await;
            let role_permissions = state.role_permissions.lock().await;
            let permissions = state.permissions.lock().await;

            let user_id = check.get("user_id").and_then(|u| u.as_str()).unwrap_or("");
            let resource = check.get("resource").and_then(|r| r.as_str()).unwrap_or("");
            let action = check.get("action").and_then(|a| a.as_str()).unwrap_or("");

            // Get user's roles
            let user_role_ids = user_roles.get(user_id).cloned().unwrap_or_default();

            // Check if any of user's roles has the required permission
            let mut has_permission = false;
            for role_id in user_role_ids {
                if let Some(perm_ids) = role_permissions.get(&role_id) {
                    for perm_id in perm_ids {
                        if let Some(permission) = permissions.get(perm_id) {
                            if permission.resource == resource && permission.action == action {
                                has_permission = true;
                                break;
                            }
                        }
                    }
                    if has_permission {
                        break;
                    }
                }
            }

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "user_id": user_id,
                "resource": resource,
                "action": action,
                "allowed": has_permission,
                "reason": if has_permission { "permission_granted" } else { "permission_denied" }
            })))
        }))
        .route("/authz/user/roles", get(move |State(state): State<AuthzState>, Json(request): Json<serde_json::Value>| async move {
            let user_roles = state.user_roles.lock().await;
            let roles = state.roles.lock().await;

            let user_id = request.get("user_id").and_then(|u| u.as_str()).unwrap_or("");

            let user_role_ids = user_roles.get(user_id).cloned().unwrap_or_default();
            let mut user_role_details = Vec::new();

            for role_id in user_role_ids {
                if let Some(role) = roles.get(&role_id) {
                    user_role_details.push(json!({
                        "id": role.id,
                        "name": role.name,
                        "description": role.description
                    }));
                }
            }

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "user_id": user_id,
                "roles": user_role_details,
                "total_roles": user_role_details.len()
            })))
        }))
        .route("/authz/role/assign", post(move |State(state): State<AuthzState>, Json(assignment): Json<serde_json::Value>| async move {
            let mut user_roles = state.user_roles.lock().await;
            let roles = state.roles.lock().await;

            let user_id = assignment.get("user_id").and_then(|u| u.as_str()).unwrap_or("");
            let role_id = assignment.get("role_id").and_then(|r| r.as_str()).unwrap_or("");

            // Check if role exists
            if !roles.contains_key(role_id) {
                return Err(StatusCode::NOT_FOUND);
            }

            // Assign role to user
            user_roles.entry(user_id.to_string())
                .or_insert_with(Vec::new)
                .push(role_id.to_string());

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "user_id": user_id,
                "role_id": role_id,
                "status": "assigned",
                "message": "Role assigned successfully"
            })))
        }))
        .with_state(authz_state);

    let server = TestServer::new(app).unwrap();

    // Test permission check for employee (should have read permission)
    let check_data = json!({"user_id": "user_123", "resource": "documents", "action": "read"});
    let response = server.post("/authz/check").json(&check_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["allowed"], true);
    assert_eq!(body["reason"], "permission_granted");

    // Test permission check for employee (should NOT have write permission)
    let check_data = json!({"user_id": "user_123", "resource": "documents", "action": "write"});
    let response = server.post("/authz/check").json(&check_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["allowed"], false);
    assert_eq!(body["reason"], "permission_denied");

    // Test permission check for manager (should have write permission)
    let check_data = json!({"user_id": "user_manager", "resource": "documents", "action": "write"});
    let response = server.post("/authz/check").json(&check_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["allowed"], true);

    // Test getting user roles
    let roles_request = json!({"user_id": "user_manager"});
    let response = server.get("/authz/user/roles").json(&roles_request).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total_roles"], 2);

    // Test role assignment
    let assignment_data = json!({"user_id": "user_123", "role_id": "role_manager"});
    let response = server
        .post("/authz/role/assign")
        .json(&assignment_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "assigned");

    // Now employee should have write permission
    let check_data = json!({"user_id": "user_123", "resource": "documents", "action": "write"});
    let response = server.post("/authz/check").json(&check_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["allowed"], true);
}

#[tokio::test]
async fn test_policy_based_authorization() {
    let authz_state = AuthzState::new();

    // Pre-populate with policies and resources
    {
        let mut policies = authz_state.policies.lock().await;
        let mut resources = authz_state.resources.lock().await;
        let mut users = authz_state.users.lock().await;

        // Create users
        users.insert(
            "user_alice".to_string(),
            UserProfile {
                id: "user_alice".to_string(),
                email: "alice@example.com".to_string(),
                department: "Engineering".to_string(),
                manager_id: Some("user_bob".to_string()),
                is_active: true,
            },
        );

        users.insert(
            "user_bob".to_string(),
            UserProfile {
                id: "user_bob".to_string(),
                email: "bob@example.com".to_string(),
                department: "Engineering".to_string(),
                manager_id: None,
                is_active: true,
            },
        );

        // Create resources
        resources.insert(
            "doc_123".to_string(),
            Resource {
                id: "doc_123".to_string(),
                name: "Project Plan".to_string(),
                resource_type: "documents".to_string(),
                owner_id: "user_bob".to_string(),
                is_public: false,
                tags: vec!["confidential".to_string(), "project".to_string()],
            },
        );

        resources.insert(
            "doc_456".to_string(),
            Resource {
                id: "doc_456".to_string(),
                name: "Meeting Notes".to_string(),
                resource_type: "documents".to_string(),
                owner_id: "user_alice".to_string(),
                is_public: false,
                tags: vec!["internal".to_string()],
            },
        );

        // Create policies
        policies.insert(
            "policy_owner_access".to_string(),
            Policy {
                id: "policy_owner_access".to_string(),
                name: "Owner Full Access".to_string(),
                effect: "allow".to_string(),
                conditions: vec![Condition {
                    key: "resource.owner_id".to_string(),
                    operator: "equals".to_string(),
                    value: "user_id".to_string(),
                }],
                principals: vec!["*".to_string()], // All users
                resources: vec!["documents".to_string()],
                actions: vec![
                    "read".to_string(),
                    "write".to_string(),
                    "delete".to_string(),
                ],
            },
        );

        policies.insert(
            "policy_department_read".to_string(),
            Policy {
                id: "policy_department_read".to_string(),
                name: "Department Read Access".to_string(),
                effect: "allow".to_string(),
                conditions: vec![
                    Condition {
                        key: "user.department".to_string(),
                        operator: "equals".to_string(),
                        value: "resource.owner_department".to_string(),
                    },
                    Condition {
                        key: "resource.confidential".to_string(),
                        operator: "equals".to_string(),
                        value: "false".to_string(),
                    },
                ],
                principals: vec!["*".to_string()],
                resources: vec!["documents".to_string()],
                actions: vec!["read".to_string()],
            },
        );
    }

    let app =
        Router::new()
            .route(
                "/authz/policy/evaluate",
                post(
                    move |State(state): State<AuthzState>,
                          Json(evaluation): Json<serde_json::Value>| async move {
                        let policies = state.policies.lock().await;
                        let resources = state.resources.lock().await;
                        let users = state.users.lock().await;

                        let user_id = evaluation
                            .get("user_id")
                            .and_then(|u| u.as_str())
                            .unwrap_or("");
                        let resource_id = evaluation
                            .get("resource_id")
                            .and_then(|r| r.as_str())
                            .unwrap_or("");
                        let action = evaluation
                            .get("action")
                            .and_then(|a| a.as_str())
                            .unwrap_or("");

                        let user = users.get(user_id);
                        let resource = resources.get(resource_id);

                        if user.is_none() || resource.is_none() {
                            return Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                "user_id": user_id,
                                "resource_id": resource_id,
                                "action": action,
                                "allowed": false,
                                "reason": "user_or_resource_not_found"
                            })));
                        }

                        let user = user.unwrap();
                        let resource = resource.unwrap();

                        // Evaluate policies
                        let mut allowed = false;
                        let mut matched_policy = None;

                        for (policy_id, policy) in policies.iter() {
                            // Check if policy applies to this resource and action
                            if !policy.resources.contains(&resource.resource_type)
                                || !policy.actions.contains(&action.to_string())
                            {
                                continue;
                            }

                            // Check if user is in principals
                            if !policy.principals.contains(&"*".to_string())
                                && !policy.principals.contains(&user_id.to_string())
                            {
                                continue;
                            }

                            // Evaluate conditions
                            let mut conditions_met = true;
                            for condition in &policy.conditions {
                                match condition.key.as_str() {
                                    "resource.owner_id" => {
                                        let expected_value = if condition.value == "user_id" {
                                            user_id
                                        } else {
                                            &condition.value
                                        };
                                        if condition.operator == "equals"
                                            && resource.owner_id != expected_value
                                        {
                                            conditions_met = false;
                                            break;
                                        }
                                    }
                                    "user.department" => {
                                        // Check if user department matches resource owner's department
                                        if let Some(owner) = users.get(&resource.owner_id) {
                                            let expected_dept =
                                                if condition.value == "resource.owner_department" {
                                                    &owner.department
                                                } else {
                                                    &condition.value
                                                };
                                            if condition.operator == "equals"
                                                && user.department != *expected_dept
                                            {
                                                conditions_met = false;
                                                break;
                                            }
                                        } else {
                                            conditions_met = false;
                                            break;
                                        }
                                    }
                                    "resource.confidential" => {
                                        let is_confidential =
                                            resource.tags.contains(&"confidential".to_string());
                                        if condition.operator == "equals"
                                            && is_confidential.to_string() != condition.value
                                        {
                                            conditions_met = false;
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }

                            if conditions_met {
                                allowed = policy.effect == "allow";
                                matched_policy = Some(policy_id.clone());
                                break;
                            }
                        }

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "user_id": user_id,
                            "resource_id": resource_id,
                            "action": action,
                            "allowed": allowed,
                            "matched_policy": matched_policy,
                            "reason": if allowed { "policy_allow" } else { "policy_deny" }
                        })))
                    },
                ),
            )
            .route(
                "/authz/resource/access",
                get(
                    move |State(state): State<AuthzState>,
                          Json(request): Json<serde_json::Value>| async move {
                        let resources = state.resources.lock().await;
                        let users = state.users.lock().await;

                        let user_id = request
                            .get("user_id")
                            .and_then(|u| u.as_str())
                            .unwrap_or("");
                        let user = users.get(user_id);

                        if user.is_none() {
                            return Err(StatusCode::NOT_FOUND);
                        }

                        let user = user.unwrap();
                        let mut accessible_resources = Vec::new();

                        for (resource_id, resource) in resources.iter() {
                            // Owner always has access
                            if resource.owner_id == user_id {
                                accessible_resources.push(json!({
                                    "id": resource_id,
                                    "name": resource.name,
                                    "access_level": "owner"
                                }));
                                continue;
                            }

                            // Department access for non-confidential resources
                            if user.department == "Engineering"
                                && !resource.tags.contains(&"confidential".to_string())
                            {
                                accessible_resources.push(json!({
                                    "id": resource_id,
                                    "name": resource.name,
                                    "access_level": "department_read"
                                }));
                            }
                        }

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "user_id": user_id,
                            "accessible_resources": accessible_resources,
                            "total_accessible": accessible_resources.len()
                        })))
                    },
                ),
            )
            .with_state(authz_state);

    let server = TestServer::new(app).unwrap();

    // Test owner access (Bob should have full access to his document)
    let eval_data = json!({"user_id": "user_bob", "resource_id": "doc_123", "action": "write"});
    let response = server.post("/authz/policy/evaluate").json(&eval_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["allowed"].as_bool().unwrap(), true);
    assert_eq!(body["reason"], "policy_allow");

    // Test department access (Alice should have read access to Bob's non-confidential document)
    let eval_data = json!({"user_id": "user_alice", "resource_id": "doc_456", "action": "read"});
    let response = server.post("/authz/policy/evaluate").json(&eval_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["allowed"].as_bool().unwrap(), true);

    // Test denied access (Alice should NOT have write access to Bob's document)
    let eval_data = json!({"user_id": "user_alice", "resource_id": "doc_123", "action": "write"});
    let response = server.post("/authz/policy/evaluate").json(&eval_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["allowed"].as_bool().unwrap(), false);
    assert_eq!(body["reason"], "policy_deny");

    // Test accessible resources
    let access_request = json!({"user_id": "user_alice"});
    let response = server
        .get("/authz/resource/access")
        .json(&access_request)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["total_accessible"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn test_permission_management() {
    let authz_state = AuthzState::new();

    // Create a role directly in the state
    {
        let mut roles = authz_state.roles.lock().await;
        roles.insert(
            "role_manager".to_string(),
            Role {
                id: "role_manager".to_string(),
                name: "Manager".to_string(),
                description: "Department manager role".to_string(),
                is_system_role: false,
                created_at: "2024-12-01T10:00:00Z".to_string(),
            },
        );
    }

    let app = Router::new()
        .route("/authz/permission/create", post(move |State(state): State<AuthzState>, Json(create): Json<serde_json::Value>| async move {
            let mut permissions = state.permissions.lock().await;

            let name = create.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let resource = create.get("resource").and_then(|r| r.as_str()).unwrap_or("");
            let action = create.get("action").and_then(|a| a.as_str()).unwrap_or("");
            let description = create.get("description").and_then(|d| d.as_str()).unwrap_or("");

            let permission_id = format!("perm_{}", permissions.len() + 1);
            permissions.insert(permission_id.clone(), Permission {
                id: permission_id.clone(),
                name: name.to_string(),
                resource: resource.to_string(),
                action: action.to_string(),
                description: description.to_string(),
            });

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "permission_id": permission_id,
                "status": "created",
                "message": "Permission created successfully"
            })))
        }))
        .route("/authz/role/permission/grant", post(move |State(state): State<AuthzState>, Json(grant): Json<serde_json::Value>| async move {
            let mut role_permissions = state.role_permissions.lock().await;
            let permissions = state.permissions.lock().await;
            let roles = state.roles.lock().await;

            let role_id = grant.get("role_id").and_then(|r| r.as_str()).unwrap_or("");
            let permission_id = grant.get("permission_id").and_then(|p| p.as_str()).unwrap_or("");

            // Validate role and permission exist
            if !roles.contains_key(role_id) {
                return Err(StatusCode::NOT_FOUND);
            }
            if !permissions.contains_key(permission_id) {
                return Err(StatusCode::NOT_FOUND);
            }

            // Grant permission to role
            role_permissions.entry(role_id.to_string())
                .or_insert_with(Vec::new)
                .push(permission_id.to_string());

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "role_id": role_id,
                "permission_id": permission_id,
                "status": "granted",
                "message": "Permission granted to role"
            })))
        }))
        .route("/authz/role/permission/revoke", post(move |State(state): State<AuthzState>, Json(revoke): Json<serde_json::Value>| async move {
            let mut role_permissions = state.role_permissions.lock().await;

            let role_id = revoke.get("role_id").and_then(|r| r.as_str()).unwrap_or("");
            let permission_id = revoke.get("permission_id").and_then(|p| p.as_str()).unwrap_or("");

            if let Some(permissions) = role_permissions.get_mut(role_id) {
                permissions.retain(|p| p != permission_id);
                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "role_id": role_id,
                    "permission_id": permission_id,
                    "status": "revoked",
                    "message": "Permission revoked from role"
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .route("/authz/role/permissions", get(move |State(state): State<AuthzState>, Json(request): Json<serde_json::Value>| async move {
            let role_permissions = state.role_permissions.lock().await;
            let permissions = state.permissions.lock().await;

            let role_id = request.get("role_id").and_then(|r| r.as_str()).unwrap_or("");

            let permission_ids = role_permissions.get(role_id).cloned().unwrap_or_default();
            let mut permission_details = Vec::new();

            for perm_id in permission_ids {
                if let Some(permission) = permissions.get(&perm_id) {
                    permission_details.push(json!({
                        "id": permission.id,
                        "name": permission.name,
                        "resource": permission.resource,
                        "action": permission.action,
                        "description": permission.description
                    }));
                }
            }

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "role_id": role_id,
                "permissions": permission_details,
                "total_permissions": permission_details.len()
            })))
        }))
        .with_state(authz_state);

    let server = TestServer::new(app).unwrap();

    // Create a new permission
    let create_data = json!({
        "name": "Delete Users",
        "resource": "users",
        "action": "delete",
        "description": "Can delete user accounts"
    });
    let response = server
        .post("/authz/permission/create")
        .json(&create_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let permission_id = body["permission_id"].as_str().unwrap();

    // Grant permission to role (assuming role exists from previous test)
    let grant_data = json!({"role_id": "role_manager", "permission_id": permission_id});
    let response = server
        .post("/authz/role/permission/grant")
        .json(&grant_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Check role permissions
    let perm_request = json!({"role_id": "role_manager"});
    let response = server
        .get("/authz/role/permissions")
        .json(&perm_request)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["total_permissions"].as_u64().unwrap() >= 1);

    // Revoke permission
    let revoke_data = json!({"role_id": "role_manager", "permission_id": permission_id});
    let response = server
        .post("/authz/role/permission/revoke")
        .json(&revoke_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Verify permission was revoked
    let response = server
        .get("/authz/role/permissions")
        .json(&perm_request)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let permissions = body["permissions"].as_array().unwrap();
    assert!(!permissions.iter().any(|p| p["id"] == permission_id));
}

#[tokio::test]
async fn test_resource_based_access_control() {
    let authz_state = AuthzState::new();

    // Pre-populate with resources
    {
        let mut resources = authz_state.resources.lock().await;
        let mut users = authz_state.users.lock().await;

        users.insert(
            "user_owner".to_string(),
            UserProfile {
                id: "user_owner".to_string(),
                email: "owner@example.com".to_string(),
                department: "Engineering".to_string(),
                manager_id: None,
                is_active: true,
            },
        );

        users.insert(
            "user_viewer".to_string(),
            UserProfile {
                id: "user_viewer".to_string(),
                email: "viewer@example.com".to_string(),
                department: "Marketing".to_string(),
                manager_id: None,
                is_active: true,
            },
        );

        resources.insert(
            "res_public".to_string(),
            Resource {
                id: "res_public".to_string(),
                name: "Public Document".to_string(),
                resource_type: "document".to_string(),
                owner_id: "user_owner".to_string(),
                is_public: true,
                tags: vec![],
            },
        );

        resources.insert(
            "res_private".to_string(),
            Resource {
                id: "res_private".to_string(),
                name: "Private Document".to_string(),
                resource_type: "document".to_string(),
                owner_id: "user_owner".to_string(),
                is_public: false,
                tags: vec!["confidential".to_string()],
            },
        );
    }

    let app = Router::new()
        .route("/authz/resource/create", post(move |State(state): State<AuthzState>, Json(create): Json<serde_json::Value>| async move {
            let mut resources = state.resources.lock().await;

            let name = create.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let resource_type = create.get("resource_type").and_then(|t| t.as_str()).unwrap_or("");
            let owner_id = create.get("owner_id").and_then(|o| o.as_str()).unwrap_or("");
            let is_public = create.get("is_public").and_then(|p| p.as_bool()).unwrap_or(false);
            let tags = create.get("tags").and_then(|t| t.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                .unwrap_or_default();

            let resource_id = format!("res_{}", resources.len() + 1);
            resources.insert(resource_id.clone(), Resource {
                id: resource_id.clone(),
                name: name.to_string(),
                resource_type: resource_type.to_string(),
                owner_id: owner_id.to_string(),
                is_public,
                tags,
            });

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "resource_id": resource_id,
                "status": "created",
                "message": "Resource created successfully"
            })))
        }))
        .route("/authz/resource/access/check", post(move |State(state): State<AuthzState>, Json(check): Json<serde_json::Value>| async move {
            let resources = state.resources.lock().await;

            let user_id = check.get("user_id").and_then(|u| u.as_str()).unwrap_or("");
            let resource_id = check.get("resource_id").and_then(|r| r.as_str()).unwrap_or("");
            let action = check.get("action").and_then(|a| a.as_str()).unwrap_or("");

            let resource = resources.get(resource_id);

            if resource.is_none() {
                return Err(StatusCode::NOT_FOUND);
            }

            let resource = resource.unwrap();

            // Check access based on resource properties
            let mut has_access = false;
            let mut access_reason = "access_denied";

            // Owner always has access
            if resource.owner_id == user_id {
                has_access = true;
                access_reason = "owner_access";
            }
            // Public resources allow read access to everyone
            else if resource.is_public && action == "read" {
                has_access = true;
                access_reason = "public_access";
            }
            // Department access for non-confidential resources
            else if !resource.tags.contains(&"confidential".to_string()) && action == "read" {
                has_access = true;
                access_reason = "department_access";
            }

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "user_id": user_id,
                "resource_id": resource_id,
                "action": action,
                "has_access": has_access,
                "access_reason": access_reason,
                "resource_owner": resource.owner_id,
                "is_public": resource.is_public
            })))
        }))
        .route("/authz/resource/share", post(move |State(state): State<AuthzState>, Json(share): Json<serde_json::Value>| async move {
            let resources = state.resources.lock().await;

            let resource_id = share.get("resource_id").and_then(|r| r.as_str()).unwrap_or("");
            let owner_id = share.get("owner_id").and_then(|o| o.as_str()).unwrap_or("");
            let target_user_id = share.get("target_user_id").and_then(|t| t.as_str()).unwrap_or("");
            let permissions: Vec<String> = share.get("permissions").and_then(|p| p.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect())
                .unwrap_or_default();

            let resource = resources.get(resource_id);

            if resource.is_none() {
                return Err(StatusCode::NOT_FOUND);
            }

            let resource = resource.unwrap();

            // Only owner can share
            if resource.owner_id != owner_id {
                return Err(StatusCode::FORBIDDEN);
            }

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "resource_id": resource_id,
                "target_user_id": target_user_id,
                "permissions": permissions,
                "status": "shared",
                "message": "Resource shared successfully"
            })))
        }))
        .with_state(authz_state);

    let server = TestServer::new(app).unwrap();

    // Test access to public resource
    let access_check =
        json!({"user_id": "user_viewer", "resource_id": "res_public", "action": "read"});
    let response = server
        .post("/authz/resource/access/check")
        .json(&access_check)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["has_access"], true);
    assert_eq!(body["access_reason"], "public_access");

    // Test access to private resource by non-owner
    let access_check =
        json!({"user_id": "user_viewer", "resource_id": "res_private", "action": "read"});
    let response = server
        .post("/authz/resource/access/check")
        .json(&access_check)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["has_access"], false);
    assert_eq!(body["access_reason"], "access_denied");

    // Test owner access to private resource
    let access_check =
        json!({"user_id": "user_owner", "resource_id": "res_private", "action": "write"});
    let response = server
        .post("/authz/resource/access/check")
        .json(&access_check)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["has_access"], true);
    assert_eq!(body["access_reason"], "owner_access");

    // Test resource sharing
    let share_data = json!({
        "resource_id": "res_private",
        "owner_id": "user_owner",
        "target_user_id": "user_viewer",
        "permissions": ["read"]
    });
    let response = server.post("/authz/resource/share").json(&share_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "shared");

    // Test sharing by non-owner (should fail)
    let share_data = json!({
        "resource_id": "res_private",
        "owner_id": "user_viewer",
        "target_user_id": "user_owner",
        "permissions": ["read"]
    });
    let response = server.post("/authz/resource/share").json(&share_data).await;
    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
}
