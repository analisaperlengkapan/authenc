// Comprehensive API Endpoints Tests
// Testing all major API endpoints with various scenarios

use axum::{
    body::Body,
    extract::{Json, Path, Query, State},
    http::{header, Method, Request, StatusCode},
    middleware,
    response::Json as AxumJson,
    routing::{delete, get, post, put},
    Router,
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

// Shared test state for API tests
type SharedState = Arc<Mutex<HashMap<String, serde_json::Value>>>;

#[derive(Clone)]
struct AppState {
    users: SharedState,
    roles: SharedState,
    permissions: SharedState,
    clients: SharedState,
    sessions: SharedState,
}

// API Handlers for testing

// User management endpoints
async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    let mut users = state.users.lock().unwrap();
    let user_id = Uuid::new_v4().to_string();

    // Validate required fields
    if !payload.get("email").is_some() || !payload.get("username").is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check if user already exists
    for (_, user) in users.iter() {
        if user.get("email") == payload.get("email")
            || user.get("username") == payload.get("username")
        {
            return Err(StatusCode::CONFLICT);
        }
    }

    let mut user = payload.clone();
    user["id"] = json!(user_id.clone());
    user["created_at"] = json!(chrono::Utc::now().to_rfc3339());
    user["enabled"] = json!(true);
    user["email_verified"] = json!(false);

    users.insert(user_id.clone(), user.clone());

    Ok(AxumJson(json!({
        "success": true,
        "user_id": user_id,
        "user": user
    })))
}

async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    let users = state.users.lock().unwrap();

    if let Some(user) = users.get(&user_id) {
        Ok(AxumJson(user.clone()))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn update_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    let mut users = state.users.lock().unwrap();

    if let Some(user) = users.get_mut(&user_id) {
        // Update only provided fields
        if let Some(first_name) = payload.get("first_name") {
            user["first_name"] = first_name.clone();
        }
        if let Some(last_name) = payload.get("last_name") {
            user["last_name"] = last_name.clone();
        }
        if let Some(enabled) = payload.get("enabled") {
            user["enabled"] = enabled.clone();
        }

        user["updated_at"] = json!(chrono::Utc::now().to_rfc3339());

        Ok(AxumJson(json!({
            "success": true,
            "user": user.clone()
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn delete_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    let mut users = state.users.lock().unwrap();

    if users.remove(&user_id).is_some() {
        Ok(AxumJson(json!({
            "success": true,
            "message": "User deleted successfully"
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn list_users(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> AxumJson<serde_json::Value> {
    let users = state.users.lock().unwrap();
    let mut user_list: Vec<serde_json::Value> = users.values().cloned().collect();

    // Apply search filter
    if let Some(search) = params.get("search") {
        user_list.retain(|user| {
            let username = user.get("username").and_then(|u| u.as_str()).unwrap_or("");
            let email = user.get("email").and_then(|e| e.as_str()).unwrap_or("");
            username.contains(search) || email.contains(search)
        });
    }

    // Apply pagination
    let limit = params
        .get("limit")
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(10);
    let offset = params
        .get("offset")
        .and_then(|o| o.parse::<usize>().ok())
        .unwrap_or(0);

    let total = user_list.len();
    let paginated_users = user_list
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();

    AxumJson(json!({
        "users": paginated_users,
        "total": total,
        "limit": limit,
        "offset": offset
    }))
}

// Role management endpoints
async fn create_role(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    let mut roles = state.roles.lock().unwrap();
    let role_id = Uuid::new_v4().to_string();

    if !payload.get("name").is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut role = payload.clone();
    role["id"] = json!(role_id.clone());
    role["created_at"] = json!(chrono::Utc::now().to_rfc3339());
    role["composite"] = json!(false);

    roles.insert(role_id.clone(), role.clone());

    Ok(AxumJson(json!({
        "success": true,
        "role_id": role_id,
        "role": role
    })))
}

async fn assign_role_to_user(
    State(state): State<AppState>,
    Path((user_id, role_id)): Path<(String, String)>,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    let mut users = state.users.lock().unwrap();
    let roles = state.roles.lock().unwrap();

    // Check if user and role exist
    if !users.contains_key(&user_id) {
        return Err(StatusCode::NOT_FOUND);
    }
    if !roles.contains_key(&role_id) {
        return Err(StatusCode::NOT_FOUND);
    }

    if let Some(user) = users.get_mut(&user_id) {
        // Ensure user has a roles array
        if user
            .as_object()
            .map_or(true, |obj| !obj.contains_key("roles"))
        {
            user["roles"] = json!([]);
        }

        let user_roles = user.get_mut("roles").unwrap();
        let roles_array = user_roles.as_array_mut().unwrap();

        // Check if role already assigned
        for existing_role in roles_array.iter() {
            if existing_role.get("id").and_then(|id| id.as_str()) == Some(&role_id) {
                return Err(StatusCode::CONFLICT);
            }
        }

        roles_array.push(json!({
            "id": role_id,
            "assigned_at": chrono::Utc::now().to_rfc3339()
        }));

        Ok(AxumJson(json!({
            "success": true,
            "message": "Role assigned successfully"
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

// Permission management endpoints
async fn create_permission(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    let mut permissions = state.permissions.lock().unwrap();
    let permission_id = Uuid::new_v4().to_string();

    if !payload.get("name").is_some() || !payload.get("resource").is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut permission = payload.clone();
    permission["id"] = json!(permission_id.clone());
    permission["created_at"] = json!(chrono::Utc::now().to_rfc3339());

    permissions.insert(permission_id.clone(), permission.clone());

    Ok(AxumJson(json!({
        "success": true,
        "permission_id": permission_id,
        "permission": permission
    })))
}

async fn check_permission(
    State(state): State<AppState>,
    Path((user_id, resource, scope)): Path<(String, String, String)>,
) -> AxumJson<serde_json::Value> {
    let users = state.users.lock().unwrap();
    let permissions = state.permissions.lock().unwrap();

    let has_permission = if let Some(user) = users.get(&user_id) {
        if let Some(user_roles) = user.get("roles").and_then(|r| r.as_array()) {
            // Check if any of user's roles has the required permission
            user_roles.iter().any(|role_entry| {
                if let Some(role_id) = role_entry.get("id").and_then(|id| id.as_str()) {
                    // This is a simplified check - in real implementation,
                    // you'd check role-permission mappings
                    permissions.values().any(|perm| {
                        perm.get("resource").and_then(|r| r.as_str()) == Some(&resource)
                            && perm.get("scope").and_then(|s| s.as_str()) == Some(&scope)
                    })
                } else {
                    false
                }
            })
        } else {
            false
        }
    } else {
        false
    };

    AxumJson(json!({
        "user_id": user_id,
        "resource": resource,
        "scope": scope,
        "allowed": has_permission
    }))
}

// Client management endpoints
async fn create_client(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    let mut clients = state.clients.lock().unwrap();
    let client_id = Uuid::new_v4().to_string();

    if !payload.get("client_id").is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut client = payload.clone();
    client["id"] = json!(client_id.clone());
    client["created_at"] = json!(chrono::Utc::now().to_rfc3339());
    client["enabled"] = json!(true);
    client["secret"] = json!(Uuid::new_v4().to_string()); // Generate client secret

    clients.insert(client_id.clone(), client.clone());

    Ok(AxumJson(json!({
        "success": true,
        "client_id": client_id,
        "client": client
    })))
}

async fn get_client(
    State(state): State<AppState>,
    Path(client_id): Path<String>,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    let clients = state.clients.lock().unwrap();

    if let Some(client) = clients.get(&client_id) {
        Ok(AxumJson(client.clone()))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

// Session management endpoints
async fn create_session(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    let mut sessions = state.sessions.lock().unwrap();
    let session_id = Uuid::new_v4().to_string();

    if !payload.get("user_id").is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut session = payload.clone();
    session["id"] = json!(session_id.clone());
    session["created_at"] = json!(chrono::Utc::now().to_rfc3339());
    session["active"] = json!(true);
    session["ip_address"] = json!("127.0.0.1");

    sessions.insert(session_id.clone(), session.clone());

    Ok(AxumJson(json!({
        "success": true,
        "session_id": session_id,
        "session": session
    })))
}

async fn invalidate_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    let mut sessions = state.sessions.lock().unwrap();

    if let Some(session) = sessions.get_mut(&session_id) {
        session["active"] = json!(false);
        session["invalidated_at"] = json!(chrono::Utc::now().to_rfc3339());

        Ok(AxumJson(json!({
            "success": true,
            "message": "Session invalidated successfully"
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[tokio::test]
async fn test_user_crud_operations() {
    let state = AppState {
        users: Arc::new(Mutex::new(HashMap::new())),
        roles: Arc::new(Mutex::new(HashMap::new())),
        permissions: Arc::new(Mutex::new(HashMap::new())),
        clients: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/users", post(create_user))
        .route("/users", get(list_users))
        .route("/users/{id}", get(get_user))
        .route("/users/{id}", put(update_user))
        .route("/users/{id}", delete(delete_user))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Create a user
    let user_data = json!({
        "username": "testuser",
        "email": "test@example.com",
        "first_name": "Test",
        "last_name": "User"
    });

    let response = server.post("/users").json(&user_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: serde_json::Value = response.json();
    assert!(result.get("success").unwrap().as_bool().unwrap());
    let user_id = result["user_id"].as_str().unwrap().to_string();

    // Get the user
    let response = server.get(&format!("/users/{}", user_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: serde_json::Value = response.json();
    assert_eq!(result["username"], "testuser");
    assert_eq!(result["email"], "test@example.com");

    // Update the user
    let update_data = json!({
        "first_name": "Updated",
        "enabled": false
    });

    let response = server
        .put(&format!("/users/{}", user_id))
        .json(&update_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Verify update
    let response = server.get(&format!("/users/{}", user_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: serde_json::Value = response.json();
    assert_eq!(result["first_name"], "Updated");
    assert_eq!(result["enabled"], false);

    // Delete the user
    let response = server.delete(&format!("/users/{}", user_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Verify deletion
    let response = server.get(&format!("/users/{}", user_id)).await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_user_validation_and_conflicts() {
    let state = AppState {
        users: Arc::new(Mutex::new(HashMap::new())),
        roles: Arc::new(Mutex::new(HashMap::new())),
        permissions: Arc::new(Mutex::new(HashMap::new())),
        clients: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/users", post(create_user))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Create first user
    let user_data = json!({
        "username": "testuser",
        "email": "test@example.com",
        "first_name": "Test",
        "last_name": "User"
    });

    let response = server.post("/users").json(&user_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Try to create user with same email - should conflict
    let duplicate_email = json!({
        "username": "differentuser",
        "email": "test@example.com",
        "first_name": "Different",
        "last_name": "User"
    });

    let response = server.post("/users").json(&duplicate_email).await;
    assert_eq!(response.status_code(), StatusCode::CONFLICT);

    // Try to create user with same username - should conflict
    let duplicate_username = json!({
        "username": "testuser",
        "email": "different@example.com",
        "first_name": "Different",
        "last_name": "User"
    });

    let response = server.post("/users").json(&duplicate_username).await;
    assert_eq!(response.status_code(), StatusCode::CONFLICT);

    // Try to create user with missing required fields
    let incomplete_data = json!({
        "username": "incomplete"
        // Missing email
    });

    let response = server.post("/users").json(&incomplete_data).await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_user_listing_and_search() {
    let state = AppState {
        users: Arc::new(Mutex::new(HashMap::new())),
        roles: Arc::new(Mutex::new(HashMap::new())),
        permissions: Arc::new(Mutex::new(HashMap::new())),
        clients: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/users", post(create_user))
        .route("/users", get(list_users))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Create multiple users
    let users_data = vec![
        json!({
            "username": "alice",
            "email": "alice@example.com",
            "first_name": "Alice",
            "last_name": "Smith"
        }),
        json!({
            "username": "bob",
            "email": "bob@example.com",
            "first_name": "Bob",
            "last_name": "Johnson"
        }),
        json!({
            "username": "charlie",
            "email": "charlie@example.com",
            "first_name": "Charlie",
            "last_name": "Brown"
        }),
    ];

    for user_data in users_data {
        let response = server.post("/users").json(&user_data).await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }

    // List all users
    let response = server.get("/users").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: serde_json::Value = response.json();
    assert_eq!(result["total"].as_u64().unwrap(), 3);
    assert_eq!(result["users"].as_array().unwrap().len(), 3);

    // Search by username
    let response = server.get("/users?search=alice").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: serde_json::Value = response.json();
    assert_eq!(result["total"].as_u64().unwrap(), 1);
    assert_eq!(result["users"][0]["username"], "alice");

    // Search by email
    let response = server.get("/users?search=bob@example.com").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: serde_json::Value = response.json();
    assert_eq!(result["total"].as_u64().unwrap(), 1);
    assert_eq!(result["users"][0]["email"], "bob@example.com");

    // Test pagination
    let response = server.get("/users?limit=2&offset=1").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: serde_json::Value = response.json();
    assert_eq!(result["total"].as_u64().unwrap(), 3);
    assert_eq!(result["users"].as_array().unwrap().len(), 2);
    assert_eq!(result["limit"].as_u64().unwrap(), 2);
    assert_eq!(result["offset"].as_u64().unwrap(), 1);
}

#[tokio::test]
async fn test_role_management() {
    let state = AppState {
        users: Arc::new(Mutex::new(HashMap::new())),
        roles: Arc::new(Mutex::new(HashMap::new())),
        permissions: Arc::new(Mutex::new(HashMap::new())),
        clients: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/users", post(create_user))
        .route("/roles", post(create_role))
        .route(
            "/users/{user_id}/roles/{role_id}",
            post(assign_role_to_user),
        )
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Create a user
    let user_data = json!({
        "username": "testuser",
        "email": "test@example.com"
    });

    let response = server.post("/users").json(&user_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let user_result: serde_json::Value = response.json();
    let user_id = user_result["user_id"].as_str().unwrap().to_string();

    // Create a role
    let role_data = json!({
        "name": "admin",
        "description": "Administrator role"
    });

    let response = server.post("/roles").json(&role_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let role_result: serde_json::Value = response.json();
    let role_id = role_result["role_id"].as_str().unwrap().to_string();

    // Assign role to user
    let response = server
        .post(&format!("/users/{}/roles/{}", user_id, role_id))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Try to assign same role again - should conflict
    let response = server
        .post(&format!("/users/{}/roles/{}", user_id, role_id))
        .await;
    assert_eq!(response.status_code(), StatusCode::CONFLICT);

    // Try to assign role to non-existent user
    let response = server
        .post(&format!("/users/{}/roles/{}", "non-existent", role_id))
        .await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    // Try to assign non-existent role to user
    let response = server
        .post(&format!("/users/{}/roles/{}", user_id, "non-existent"))
        .await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_permission_system() {
    let state = AppState {
        users: Arc::new(Mutex::new(HashMap::new())),
        roles: Arc::new(Mutex::new(HashMap::new())),
        permissions: Arc::new(Mutex::new(HashMap::new())),
        clients: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/permissions", post(create_permission))
        .route(
            "/permissions/check/{user_id}/{resource}/{scope}",
            get(check_permission),
        )
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Create a permission
    let permission_data = json!({
        "name": "read_users",
        "resource": "users",
        "scope": "read",
        "description": "Can read user information"
    });

    let response = server.post("/permissions").json(&permission_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Check permission for non-existent user
    let response = server.get("/permissions/check/user123/users/read").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: serde_json::Value = response.json();
    assert_eq!(result["allowed"], false);

    // Note: In a real implementation, you'd need to set up the user-role-permission relationships
    // This test demonstrates the basic structure
}

#[tokio::test]
async fn test_client_management() {
    let state = AppState {
        users: Arc::new(Mutex::new(HashMap::new())),
        roles: Arc::new(Mutex::new(HashMap::new())),
        permissions: Arc::new(Mutex::new(HashMap::new())),
        clients: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/clients", post(create_client))
        .route("/clients/{id}", get(get_client))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Create a client
    let client_data = json!({
        "client_id": "test-client",
        "name": "Test Client",
        "description": "A test OAuth2 client"
    });

    let response = server.post("/clients").json(&client_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: serde_json::Value = response.json();
    assert!(result.get("success").unwrap().as_bool().unwrap());
    let client_id = result["client_id"].as_str().unwrap().to_string();

    // Get the client
    let response = server.get(&format!("/clients/{}", client_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: serde_json::Value = response.json();
    assert_eq!(result["client_id"], "test-client");
    assert_eq!(result["name"], "Test Client");
    assert!(result.get("secret").is_some()); // Should have generated secret
    assert_eq!(result["enabled"], true);

    // Try to get non-existent client
    let response = server.get("/clients/non-existent").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_session_management() {
    let state = AppState {
        users: Arc::new(Mutex::new(HashMap::new())),
        roles: Arc::new(Mutex::new(HashMap::new())),
        permissions: Arc::new(Mutex::new(HashMap::new())),
        clients: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/sessions", post(create_session))
        .route("/sessions/{id}/invalidate", post(invalidate_session))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Create a session
    let session_data = json!({
        "user_id": "user123",
        "client_id": "client456",
        "scope": "openid profile"
    });

    let response = server.post("/sessions").json(&session_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: serde_json::Value = response.json();
    assert!(result.get("success").unwrap().as_bool().unwrap());
    let session_id = result["session_id"].as_str().unwrap().to_string();

    // Invalidate the session
    let response = server
        .post(&format!("/sessions/{}/invalidate", session_id))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Try to invalidate non-existent session
    let response = server.post("/sessions/non-existent/invalidate").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_concurrent_api_operations() {
    let state = AppState {
        users: Arc::new(Mutex::new(HashMap::new())),
        roles: Arc::new(Mutex::new(HashMap::new())),
        permissions: Arc::new(Mutex::new(HashMap::new())),
        clients: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/users", post(create_user))
        .route("/users", get(list_users))
        .with_state(state);

    let server = Arc::new(TestServer::new(app).unwrap());

    // Create multiple users concurrently
    let mut handles = vec![];

    for i in 0..5 {
        let server_clone = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            let user_data = json!({
                "username": format!("user{}", i),
                "email": format!("user{}@example.com", i),
                "first_name": format!("User{}", i),
                "last_name": "Test"
            });

            let response = server_clone.post("/users").json(&user_data).await;
            assert_eq!(response.status_code(), StatusCode::OK);
        });
        handles.push(handle);
    }

    // Wait for all concurrent operations to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify all users were created
    let response = server.get("/users").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: serde_json::Value = response.json();
    assert_eq!(result["total"].as_u64().unwrap(), 5);
}

#[tokio::test]
async fn test_api_error_handling() {
    let state = AppState {
        users: Arc::new(Mutex::new(HashMap::new())),
        roles: Arc::new(Mutex::new(HashMap::new())),
        permissions: Arc::new(Mutex::new(HashMap::new())),
        clients: Arc::new(Mutex::new(HashMap::new())),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/users/{id}", get(get_user))
        .route("/users/{id}", put(update_user))
        .route("/users/{id}", delete(delete_user))
        .route(
            "/permissions/check/{user_id}/{resource}/{scope}",
            get(check_permission),
        )
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test 404 errors for non-existent resources
    let response = server.get("/users/non-existent-id").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    let response = server
        .put("/users/non-existent-id")
        .json(&json!({"enabled": false}))
        .await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    let response = server.delete("/users/non-existent-id").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    // Test malformed requests
    let response = server
        .get("/permissions/check/invalid-user/users/read")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK); // Permission check always returns 200

    let result: serde_json::Value = response.json();
    assert_eq!(result["allowed"], false);
}
