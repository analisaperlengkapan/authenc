use axum::{
    Router,
    body::Body,
    extract::{Path, Query, State},
    http::{Method, Request, StatusCode, header},
    middleware,
    response::Json,
    routing::{delete, get, post, put},
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::Duration;
use uuid::Uuid;

// Shared test state for integration tests
type SharedState = Arc<Mutex<HashMap<String, serde_json::Value>>>;

#[derive(Clone)]
struct AppState {
    pub zero_trust_manager: Arc<authenc::services::security::zero_trust::ZeroTrustManager>,
    data: SharedState,
}

// Integration test handlers
async fn health_check() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": "1.0.0"
    }))
}

async fn create_user(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();
    let user_id = Uuid::new_v4().to_string();

    if let Some(email) = payload.get("email") {
        // Check if user already exists
        for (_, user) in data.iter() {
            if user.get("email") == Some(email) {
                return Err(StatusCode::CONFLICT);
            }
        }
    }

    let mut user = payload.clone();
    user["id"] = json!(user_id);
    user["created_at"] = json!(chrono::Utc::now().to_rfc3339());
    user["updated_at"] = json!(chrono::Utc::now().to_rfc3339());

    data.insert(user_id.clone(), user.clone());

    Ok(Json(json!({
        "success": true,
        "user": user,
        "message": "User created successfully"
    })))
}

async fn get_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let data = state.data.lock().unwrap();

    if let Some(user) = data.get(&user_id) {
        Ok(Json(json!({
            "success": true,
            "user": user
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn update_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();

    if let Some(user) = data.get_mut(&user_id) {
        // Update user fields
        if let Some(name) = payload.get("name") {
            user["name"] = name.clone();
        }
        if let Some(email) = payload.get("email") {
            user["email"] = email.clone();
        }
        user["updated_at"] = json!(chrono::Utc::now().to_rfc3339());

        Ok(Json(json!({
            "success": true,
            "user": user,
            "message": "User updated successfully"
        })))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn delete_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();

    if data.remove(&user_id).is_some() {
        Ok(Json(json!({
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
) -> Json<serde_json::Value> {
    let data = state.data.lock().unwrap();
    let mut users: Vec<&serde_json::Value> = data.values().collect();

    // Apply pagination
    let page = params
        .get("page")
        .and_then(|p| p.parse::<usize>().ok())
        .unwrap_or(1);
    let limit = params
        .get("limit")
        .and_then(|l| l.parse::<usize>().ok())
        .unwrap_or(10);
    let offset = (page - 1) * limit;

    users = users.into_iter().skip(offset).take(limit).collect();

    Json(json!({
        "success": true,
        "users": users,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": data.len()
        }
    }))
}

async fn search_users(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let data = state.data.lock().unwrap();
    let mut results = Vec::new();

    if let Some(query) = params.get("q") {
        for user in data.values() {
            if let (Some(name), Some(email)) = (user.get("name"), user.get("email")) {
                if name
                    .as_str()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains(&query.to_lowercase())
                    || email
                        .as_str()
                        .unwrap_or("")
                        .to_lowercase()
                        .contains(&query.to_lowercase())
                {
                    results.push(user);
                }
            }
        }
    }

    Json(json!({
        "success": true,
        "results": results,
        "query": params.get("q").unwrap_or(&"".to_string())
    }))
}

async fn bulk_create_users(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mut data = state.data.lock().unwrap();

    if let Some(users) = payload.get("users").and_then(|u| u.as_array()) {
        let mut created_users = Vec::new();
        let mut errors = Vec::new();

        for (index, user_payload) in users.iter().enumerate() {
            let user_id = Uuid::new_v4().to_string();

            // Check for duplicate email
            if let Some(email) = user_payload.get("email") {
                let mut is_duplicate = false;
                for existing_user in data.values() {
                    if existing_user.get("email") == Some(email) {
                        is_duplicate = true;
                        break;
                    }
                }
                if is_duplicate {
                    errors.push(json!({
                        "index": index,
                        "error": "Email already exists",
                        "email": email
                    }));
                    continue;
                }
            }

            let mut user = user_payload.clone();
            user["id"] = json!(user_id);
            user["created_at"] = json!(chrono::Utc::now().to_rfc3339());
            user["updated_at"] = json!(chrono::Utc::now().to_rfc3339());

            data.insert(user_id.clone(), user.clone());
            created_users.push(user);
        }

        Ok(Json(json!({
            "success": true,
            "created": created_users.len(),
            "errors": errors,
            "users": created_users
        })))
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

async fn user_stats(State(state): State<AppState>) -> Json<serde_json::Value> {
    let data = state.data.lock().unwrap();

    let total_users = data.len();
    let active_users = data
        .values()
        .filter(|u| u.get("status").and_then(|s| s.as_str()) == Some("active"))
        .count();

    Json(json!({
        "success": true,
        "stats": {
            "total_users": total_users,
            "active_users": active_users,
            "inactive_users": total_users - active_users
        }
    }))
}

#[tokio::test]
async fn test_health_check_endpoint() {
    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());

    let state = AppState {
        zero_trust_manager: zero_trust_manager.clone(),
        data: Arc::new(Mutex::new(HashMap::new())),
};

let app = Router::new()
        .route("/health", get(health_check))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    let response = server.get("/health").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "healthy");
    assert!(body["timestamp"].is_string());
    assert_eq!(body["version"], "1.0.0");
}

#[tokio::test]
async fn test_user_crud_operations() {
    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());

    let state = AppState {
        zero_trust_manager: zero_trust_manager.clone(),
        data: Arc::new(Mutex::new(HashMap::new())),
};

let app = Router::new()
        .route("/users", post(create_user))
        .route(
            "/users/{id}",
            get(get_user).put(update_user).delete(delete_user),
        )
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Create user
    let response = server
        .post("/users")
        .json(&json!({
            "name": "John Doe",
            "email": "john@example.com",
            "status": "active"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["success"], true);
    assert!(body["user"]["id"].is_string());
    assert_eq!(body["user"]["name"], "John Doe");
    assert_eq!(body["user"]["email"], "john@example.com");

    let user_id = body["user"]["id"].as_str().unwrap();

    // Get user
    let response = server.get(&format!("/users/{}", user_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["user"]["name"], "John Doe");

    // Update user
    let response = server
        .put(&format!("/users/{}", user_id))
        .json(&json!({
            "name": "John Smith",
            "email": "johnsmith@example.com"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["user"]["name"], "John Smith");
    assert_eq!(body["user"]["email"], "johnsmith@example.com");

    // Delete user
    let response = server.delete(&format!("/users/{}", user_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Verify user is deleted
    let response = server.get(&format!("/users/{}", user_id)).await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_user_listing_and_pagination() {
    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());

    let state = AppState {
        zero_trust_manager: zero_trust_manager.clone(),
        data: Arc::new(Mutex::new(HashMap::new())),
};

let app = Router::new()
        .route("/users", get(list_users).post(create_user))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Create multiple users
    for i in 1..=25 {
        let response = server
            .post("/users")
            .json(&json!({
                "name": format!("User {}", i),
                "email": format!("user{}@example.com", i),
                "status": "active"
            }))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }

    // Test pagination - page 1
    let response = server.get("/users?page=1&limit=10").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["users"].as_array().unwrap().len(), 10);
    assert_eq!(body["pagination"]["page"], 1);
    assert_eq!(body["pagination"]["limit"], 10);
    assert_eq!(body["pagination"]["total"], 25);

    // Test pagination - page 2
    let response = server.get("/users?page=2&limit=10").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["users"].as_array().unwrap().len(), 10);
    assert_eq!(body["pagination"]["page"], 2);

    // Test pagination - page 3 (should have 5 users)
    let response = server.get("/users?page=3&limit=10").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["users"].as_array().unwrap().len(), 5);
    assert_eq!(body["pagination"]["page"], 3);
}

#[tokio::test]
async fn test_user_search_functionality() {
    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());

    let state = AppState {
        zero_trust_manager: zero_trust_manager.clone(),
        data: Arc::new(Mutex::new(HashMap::new())),
};

let app = Router::new()
        .route("/users", post(create_user))
        .route("/users/search", get(search_users))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Create test users
    let users = vec![
        ("Alice Johnson", "alice@example.com"),
        ("Bob Smith", "bob@example.com"),
        ("Charlie Brown", "charlie@example.com"),
        ("Diana Prince", "diana@example.com"),
    ];

    for (name, email) in users {
        let response = server
            .post("/users")
            .json(&json!({
                "name": name,
                "email": email,
                "status": "active"
            }))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }

    // Search by name
    let response = server.get("/users/search?q=Alice").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["results"].as_array().unwrap().len(), 1);
    assert_eq!(body["results"][0]["name"], "Alice Johnson");

    // Search by email
    let response = server.get("/users/search?q=bob@example.com").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["results"].as_array().unwrap().len(), 1);
    assert_eq!(body["results"][0]["email"], "bob@example.com");

    // Search with no results
    let response = server.get("/users/search?q=nonexistent").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["results"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_bulk_user_operations() {
    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());

    let state = AppState {
        zero_trust_manager: zero_trust_manager.clone(),
        data: Arc::new(Mutex::new(HashMap::new())),
};

let app = Router::new()
        .route("/users/bulk", post(bulk_create_users))
        .route("/users", post(create_user))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test bulk creation
    let response = server
        .post("/users/bulk")
        .json(&json!({
            "users": [
                {
                    "name": "Bulk User 1",
                    "email": "bulk1@example.com",
                    "status": "active"
                },
                {
                    "name": "Bulk User 2",
                    "email": "bulk2@example.com",
                    "status": "active"
                },
                {
                    "name": "Bulk User 1",  // Duplicate name but different email
                    "email": "bulk3@example.com",
                    "status": "active"
                }
            ]
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["created"], 3);
    assert_eq!(body["errors"].as_array().unwrap().len(), 0);

    // Test bulk creation with duplicate email
    let response = server
        .post("/users/bulk")
        .json(&json!({
            "users": [
                {
                    "name": "New User",
                    "email": "new@example.com",
                    "status": "active"
                },
                {
                    "name": "Duplicate Email",
                    "email": "bulk1@example.com",  // This should fail
                    "status": "active"
                }
            ]
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["created"], 1);
    assert_eq!(body["errors"].as_array().unwrap().len(), 1);
    assert_eq!(body["errors"][0]["error"], "Email already exists");
}

#[tokio::test]
async fn test_user_statistics() {
    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());

    let state = AppState {
        zero_trust_manager: zero_trust_manager.clone(),
        data: Arc::new(Mutex::new(HashMap::new())),
};

let app = Router::new()
        .route("/users", post(create_user))
        .route("/users/stats", get(user_stats))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Create users with different statuses
    let users = vec![
        ("Active User 1", "active1@example.com", "active"),
        ("Active User 2", "active2@example.com", "active"),
        ("Inactive User", "inactive@example.com", "inactive"),
    ];

    for (name, email, status) in users {
        let response = server
            .post("/users")
            .json(&json!({
                "name": name,
                "email": email,
                "status": status
            }))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }

    // Get statistics
    let response = server.get("/users/stats").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    assert_eq!(body["stats"]["total_users"], 3);
    assert_eq!(body["stats"]["active_users"], 2);
    assert_eq!(body["stats"]["inactive_users"], 1);
}

#[tokio::test]
async fn test_error_handling_and_edge_cases() {
    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());

    let state = AppState {
        zero_trust_manager: zero_trust_manager.clone(),
        data: Arc::new(Mutex::new(HashMap::new())),
};

let app = Router::new()
        .route("/users", post(create_user))
        .route(
            "/users/{id}",
            get(get_user).put(update_user).delete(delete_user),
        )
        .route("/users/bulk", post(bulk_create_users))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Test creating user with duplicate email
    let response = server
        .post("/users")
        .json(&json!({
            "name": "First User",
            "email": "test@example.com",
            "status": "active"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let response = server
        .post("/users")
        .json(&json!({
            "name": "Second User",
            "email": "test@example.com",  // Duplicate email
            "status": "active"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::CONFLICT);

    // Test getting non-existent user
    let response = server.get("/users/non-existent-id").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    // Test updating non-existent user
    let response = server
        .put("/users/non-existent-id")
        .json(&json!({
            "name": "Updated Name"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    // Test deleting non-existent user
    let response = server.delete("/users/non-existent-id").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    // Test bulk creation with invalid data
    let response = server
        .post("/users/bulk")
        .json(&json!({
            "invalid_field": "invalid"
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_concurrent_user_operations() {
    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());

    let state = AppState {
        zero_trust_manager: zero_trust_manager.clone(),
        data: Arc::new(Mutex::new(HashMap::new())),
};

let app = Router::new()
        .route("/users", post(create_user))
        .route("/users/{id}", get(get_user))
        .with_state(state);

    let server = TestServer::new(app.clone()).unwrap();

    // Spawn multiple concurrent tasks
    let mut handles = vec![];

    for i in 0..10 {
        let server_clone = TestServer::new(app.clone()).unwrap();
        let handle = tokio::spawn(async move {
            let response = server_clone
                .post("/users")
                .json(&json!({
                    "name": format!("Concurrent User {}", i),
                    "email": format!("concurrent{}@example.com", i),
                    "status": "active"
                }))
                .await;

            assert_eq!(response.status_code(), StatusCode::OK);
            let body: serde_json::Value = response.json();
            let user_id = body["user"]["id"].as_str().unwrap().to_string();

            // Immediately try to read the user
            let get_response = server_clone.get(&format!("/users/{}", user_id)).await;
            assert_eq!(get_response.status_code(), StatusCode::OK);

            user_id
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    let mut user_ids = vec![];
    for handle in handles {
        user_ids.push(handle.await.unwrap());
    }

    // Verify all users were created
    assert_eq!(user_ids.len(), 10);

    // Verify all users can be retrieved
    for user_id in user_ids {
        let response = server.get(&format!("/users/{}", user_id)).await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }
}

#[tokio::test]
async fn test_data_integrity_and_consistency() {
    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());

    let state = AppState {
        zero_trust_manager: zero_trust_manager.clone(),
        data: Arc::new(Mutex::new(HashMap::new())),
};

let app = Router::new()
        .route("/users", post(create_user))
        .route("/users/{id}", get(get_user).put(update_user))
        .with_state(state);

    let server = TestServer::new(app).unwrap();

    // Create a user
    let response = server
        .post("/users")
        .json(&json!({
            "name": "Integrity Test",
            "email": "integrity@example.com",
            "status": "active",
            "metadata": {
                "department": "Engineering",
                "role": "Developer"
            }
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();
    let user_id = body["user"]["id"].as_str().unwrap();

    // Verify data integrity - all fields should be preserved
    let response = server.get(&format!("/users/{}", user_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();

    assert_eq!(body["user"]["name"], "Integrity Test");
    assert_eq!(body["user"]["email"], "integrity@example.com");
    assert_eq!(body["user"]["status"], "active");
    assert_eq!(body["user"]["metadata"]["department"], "Engineering");
    assert_eq!(body["user"]["metadata"]["role"], "Developer");
    assert!(body["user"]["created_at"].is_string());
    assert!(body["user"]["updated_at"].is_string());

    // Test partial update preserves other fields
    let response = server
        .put(&format!("/users/{}", user_id))
        .json(&json!({
            "name": "Updated Integrity Test"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let body: serde_json::Value = response.json();

    // Verify updated field
    assert_eq!(body["user"]["name"], "Updated Integrity Test");
    // Verify other fields are preserved
    assert_eq!(body["user"]["email"], "integrity@example.com");
    assert_eq!(body["user"]["status"], "active");
    assert_eq!(body["user"]["metadata"]["department"], "Engineering");
    assert!(body["user"]["updated_at"].is_string());
}
