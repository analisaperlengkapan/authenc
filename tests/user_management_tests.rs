// Advanced User Management Tests
// Testing user lifecycle management, profiles, account operations, and user administration

use axum::{
    extract::{Json, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Router,
};
use axum_test::TestServer;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
struct UserMgmtState {
    users: Arc<Mutex<HashMap<String, UserAccount>>>,
    profiles: Arc<Mutex<HashMap<String, UserProfile>>>,
    account_history: Arc<Mutex<HashMap<String, Vec<AccountEvent>>>>,
    invitations: Arc<Mutex<HashMap<String, Invitation>>>,
    groups: Arc<Mutex<HashMap<String, Group>>>,
    user_groups: Arc<Mutex<HashMap<String, Vec<String>>>>, // user_id -> group_ids
}

#[derive(Clone)]
struct UserAccount {
    id: String,
    email: String,
    username: String,
    password_hash: String,
    status: AccountStatus,
    created_at: String,
    updated_at: String,
    last_login: Option<String>,
    login_count: u32,
    failed_login_attempts: u32,
    locked_until: Option<String>,
    email_verified: bool,
    two_factor_enabled: bool,
}

#[derive(Clone)]
enum AccountStatus {
    Active,
    Inactive,
    Suspended,
    Locked,
    PendingVerification,
}

#[derive(Clone)]
struct UserProfile {
    user_id: String,
    first_name: String,
    last_name: String,
    display_name: String,
    avatar_url: Option<String>,
    bio: Option<String>,
    phone: Option<String>,
    department: Option<String>,
    job_title: Option<String>,
    location: Option<String>,
    timezone: String,
    preferences: HashMap<String, serde_json::Value>,
}

#[derive(Clone)]
struct AccountEvent {
    id: String,
    event_type: String,
    description: String,
    timestamp: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    metadata: HashMap<String, String>,
}

#[derive(Clone)]
struct Invitation {
    id: String,
    email: String,
    invited_by: String,
    role: String,
    status: String, // pending, accepted, expired
    expires_at: String,
    created_at: String,
    accepted_at: Option<String>,
}

#[derive(Clone)]
struct Group {
    id: String,
    name: String,
    description: String,
    created_by: String,
    created_at: String,
    member_count: u32,
    is_system_group: bool,
}

impl UserMgmtState {
    fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            profiles: Arc::new(Mutex::new(HashMap::new())),
            account_history: Arc::new(Mutex::new(HashMap::new())),
            invitations: Arc::new(Mutex::new(HashMap::new())),
            groups: Arc::new(Mutex::new(HashMap::new())),
            user_groups: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tokio::test]
async fn test_user_account_lifecycle() {
    let user_state = UserMgmtState::new();

    let app = Router::new()
        .route("/users", post(move |State(state): State<UserMgmtState>, Json(create): Json<serde_json::Value>| async move {
            let mut users = state.users.lock().await;
            let mut profiles = state.profiles.lock().await;
            let mut account_history = state.account_history.lock().await;

            let email = create.get("email").and_then(|e| e.as_str()).unwrap_or("");
            let username = create.get("username").and_then(|u| u.as_str()).unwrap_or("");
            let password = create.get("password").and_then(|p| p.as_str()).unwrap_or("");
            let first_name = create.get("first_name").and_then(|f| f.as_str()).unwrap_or("");
            let last_name = create.get("last_name").and_then(|l| l.as_str()).unwrap_or("");

            // Validation
            if email.is_empty() || username.is_empty() || password.len() < 8 {
                return Err(StatusCode::BAD_REQUEST);
            }

            // Check for existing user
            if users.values().any(|u| u.email == email || u.username == username) {
                return Err(StatusCode::CONFLICT);
            }

            let user_id = format!("user_{}", users.len() + 1);
            let now = "2024-12-01T12:00:00Z".to_string();

            // Create user account
            users.insert(user_id.clone(), UserAccount {
                id: user_id.clone(),
                email: email.to_string(),
                username: username.to_string(),
                password_hash: format!("hash_{}", password),
                status: AccountStatus::PendingVerification,
                created_at: now.clone(),
                updated_at: now.clone(),
                last_login: None,
                login_count: 0,
                failed_login_attempts: 0,
                locked_until: None,
                email_verified: false,
                two_factor_enabled: false,
            });

            // Create user profile
            profiles.insert(user_id.clone(), UserProfile {
                user_id: user_id.clone(),
                first_name: first_name.to_string(),
                last_name: last_name.to_string(),
                display_name: format!("{} {}", first_name, last_name),
                avatar_url: None,
                bio: None,
                phone: None,
                department: None,
                job_title: None,
                location: None,
                timezone: "UTC".to_string(),
                preferences: HashMap::new(),
            });

            let event_count = account_history.len();

            // Log account creation event
            account_history.entry(user_id.clone())
                .or_insert_with(Vec::new)
                .push(AccountEvent {
                    id: format!("event_{}", event_count + 1),
                    event_type: "account_created".to_string(),
                    description: "User account created".to_string(),
                    timestamp: now,
                    ip_address: None,
                    user_agent: None,
                    metadata: HashMap::new(),
                });

            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                "user_id": user_id,
                "email": email,
                "username": username,
                "status": "created",
                "message": "User account created successfully. Please verify your email."
            })))
        }))
        .route("/users/{user_id}", get(move |State(state): State<UserMgmtState>, axum::extract::Path(user_id): axum::extract::Path<String>| async move {
            let users = state.users.lock().await;
            let profiles = state.profiles.lock().await;

            if let Some(user) = users.get(&user_id) {
                if let Some(profile) = profiles.get(&user_id) {
                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "user_id": user.id,
                        "email": user.email,
                        "username": user.username,
                        "status": match user.status {
                            AccountStatus::Active => "active",
                            AccountStatus::Inactive => "inactive",
                            AccountStatus::Suspended => "suspended",
                            AccountStatus::Locked => "locked",
                            AccountStatus::PendingVerification => "pending_verification",
                        },
                        "profile": {
                            "first_name": profile.first_name,
                            "last_name": profile.last_name,
                            "display_name": profile.display_name,
                            "department": profile.department,
                            "job_title": profile.job_title
                        },
                        "stats": {
                            "login_count": user.login_count,
                            "last_login": user.last_login,
                            "created_at": user.created_at
                        }
                    })))
                } else {
                    Err(StatusCode::NOT_FOUND)
                }
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .route("/users/{user_id}/status", put(move |State(state): State<UserMgmtState>, axum::extract::Path(user_id): axum::extract::Path<String>, Json(update): Json<serde_json::Value>| async move {
            let mut users = state.users.lock().await;
            let mut account_history = state.account_history.lock().await;

            let new_status = update.get("status").and_then(|s| s.as_str()).unwrap_or("");

            if let Some(user) = users.get_mut(&user_id) {
                let old_status = match user.status {
                    AccountStatus::Active => "active",
                    AccountStatus::Inactive => "inactive",
                    AccountStatus::Suspended => "suspended",
                    AccountStatus::Locked => "locked",
                    AccountStatus::PendingVerification => "pending_verification",
                };

                user.status = match new_status {
                    "active" => AccountStatus::Active,
                    "inactive" => AccountStatus::Inactive,
                    "suspended" => AccountStatus::Suspended,
                    "locked" => AccountStatus::Locked,
                    _ => return Err(StatusCode::BAD_REQUEST),
                };

                user.updated_at = "2024-12-01T12:30:00Z".to_string();

                let event_count = account_history.len();

                // Log status change
                account_history.entry(user_id.clone())
                    .or_insert_with(Vec::new)
                    .push(AccountEvent {
                        id: format!("event_{}", event_count + 1),
                        event_type: "status_changed".to_string(),
                        description: format!("Account status changed from {} to {}", old_status, new_status),
                        timestamp: "2024-12-01T12:30:00Z".to_string(),
                        ip_address: None,
                        user_agent: None,
                        metadata: HashMap::from([
                            ("old_status".to_string(), old_status.to_string()),
                            ("new_status".to_string(), new_status.to_string()),
                        ]),
                    });

                Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                    "user_id": user_id,
                    "status": new_status,
                    "updated_at": user.updated_at,
                    "message": "User status updated successfully"
                })))
            } else {
                Err(StatusCode::NOT_FOUND)
            }
        }))
        .with_state(user_state);

    let server = TestServer::new(app).unwrap();

    // Test user creation
    let create_data = json!({
        "email": "john.doe@example.com",
        "username": "johndoe",
        "password": "securepassword123",
        "first_name": "John",
        "last_name": "Doe"
    });
    let response = server.post("/users").json(&create_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let user_id = body["user_id"].as_str().unwrap();
    assert_eq!(body["status"], "created");

    // Test getting user details
    let response = server.get(&format!("/users/{}", user_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["email"], "john.doe@example.com");
    assert_eq!(body["username"], "johndoe");
    assert_eq!(body["status"], "pending_verification");

    // Test status update
    let update_data = json!({"status": "active"});
    let response = server
        .put(&format!("/users/{}/status", user_id))
        .json(&update_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "active");

    // Verify status was updated
    let response = server.get(&format!("/users/{}", user_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "active");
}

#[tokio::test]
async fn test_user_profile_management() {
    let user_state = UserMgmtState::new();

    // Pre-populate with a test user
    {
        let mut users = user_state.users.lock().await;
        let mut profiles = user_state.profiles.lock().await;

        let user_id = "user_123".to_string();
        users.insert(
            user_id.clone(),
            UserAccount {
                id: user_id.clone(),
                email: "test@example.com".to_string(),
                username: "testuser".to_string(),
                password_hash: "hash_password".to_string(),
                status: AccountStatus::Active,
                created_at: "2024-12-01T10:00:00Z".to_string(),
                updated_at: "2024-12-01T10:00:00Z".to_string(),
                last_login: None,
                login_count: 0,
                failed_login_attempts: 0,
                locked_until: None,
                email_verified: true,
                two_factor_enabled: false,
            },
        );

        profiles.insert(
            user_id,
            UserProfile {
                user_id: "user_123".to_string(),
                first_name: "Test".to_string(),
                last_name: "User".to_string(),
                display_name: "Test User".to_string(),
                avatar_url: None,
                bio: None,
                phone: None,
                department: None,
                job_title: None,
                location: None,
                timezone: "UTC".to_string(),
                preferences: HashMap::new(),
            },
        );
    }

    let app = Router::new()
        .route(
            "/users/{user_id}/profile",
            get(
                move |State(state): State<UserMgmtState>,
                      axum::extract::Path(user_id): axum::extract::Path<String>| async move {
                    let profiles = state.profiles.lock().await;

                    if let Some(profile) = profiles.get(&user_id) {
                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "user_id": profile.user_id,
                            "first_name": profile.first_name,
                            "last_name": profile.last_name,
                            "display_name": profile.display_name,
                            "avatar_url": profile.avatar_url,
                            "bio": profile.bio,
                            "phone": profile.phone,
                            "department": profile.department,
                            "job_title": profile.job_title,
                            "location": profile.location,
                            "timezone": profile.timezone,
                            "preferences": profile.preferences
                        })))
                    } else {
                        Err(StatusCode::NOT_FOUND)
                    }
                },
            ),
        )
        .route(
            "/users/{user_id}/profile",
            put(
                move |State(state): State<UserMgmtState>,
                      axum::extract::Path(user_id): axum::extract::Path<String>,
                      Json(update): Json<serde_json::Value>| async move {
                    let mut profiles = state.profiles.lock().await;

                    if let Some(profile) = profiles.get_mut(&user_id) {
                        // Update profile fields
                        if let Some(first_name) = update.get("first_name").and_then(|v| v.as_str())
                        {
                            profile.first_name = first_name.to_string();
                        }
                        if let Some(last_name) = update.get("last_name").and_then(|v| v.as_str()) {
                            profile.last_name = last_name.to_string();
                            profile.display_name = format!("{} {}", profile.first_name, last_name);
                        }
                        if let Some(bio) = update.get("bio").and_then(|v| v.as_str()) {
                            profile.bio = Some(bio.to_string());
                        }
                        if let Some(phone) = update.get("phone").and_then(|v| v.as_str()) {
                            profile.phone = Some(phone.to_string());
                        }
                        if let Some(department) = update.get("department").and_then(|v| v.as_str())
                        {
                            profile.department = Some(department.to_string());
                        }
                        if let Some(job_title) = update.get("job_title").and_then(|v| v.as_str()) {
                            profile.job_title = Some(job_title.to_string());
                        }
                        if let Some(location) = update.get("location").and_then(|v| v.as_str()) {
                            profile.location = Some(location.to_string());
                        }
                        if let Some(timezone) = update.get("timezone").and_then(|v| v.as_str()) {
                            profile.timezone = timezone.to_string();
                        }

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "user_id": user_id,
                            "status": "updated",
                            "message": "Profile updated successfully"
                        })))
                    } else {
                        Err(StatusCode::NOT_FOUND)
                    }
                },
            ),
        )
        .route(
            "/users/{user_id}/preferences",
            put(
                move |State(state): State<UserMgmtState>,
                      axum::extract::Path(user_id): axum::extract::Path<String>,
                      Json(preferences): Json<serde_json::Value>| async move {
                    let mut profiles = state.profiles.lock().await;

                    if let Some(profile) = profiles.get_mut(&user_id) {
                        // Update preferences
                        if let Some(theme) = preferences.get("theme").and_then(|v| v.as_str()) {
                            profile
                                .preferences
                                .insert("theme".to_string(), json!(theme));
                        }
                        if let Some(language) = preferences.get("language").and_then(|v| v.as_str())
                        {
                            profile
                                .preferences
                                .insert("language".to_string(), json!(language));
                        }
                        if let Some(notifications) = preferences.get("notifications") {
                            profile
                                .preferences
                                .insert("notifications".to_string(), notifications.clone());
                        }

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "user_id": user_id,
                            "preferences": profile.preferences,
                            "status": "updated"
                        })))
                    } else {
                        Err(StatusCode::NOT_FOUND)
                    }
                },
            ),
        )
        .with_state(user_state);

    let server = TestServer::new(app).unwrap();

    // Test getting user profile
    let response = server.get("/users/user_123/profile").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["first_name"], "Test");
    assert_eq!(body["last_name"], "User");

    // Test updating profile
    let update_data = json!({
        "bio": "Software developer passionate about security",
        "phone": "+1-555-0123",
        "department": "Engineering",
        "job_title": "Senior Developer",
        "location": "San Francisco, CA",
        "timezone": "America/Los_Angeles"
    });
    let response = server
        .put("/users/user_123/profile")
        .json(&update_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Verify profile was updated
    let response = server.get("/users/user_123/profile").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["bio"], "Software developer passionate about security");
    assert_eq!(body["department"], "Engineering");
    assert_eq!(body["job_title"], "Senior Developer");
    assert_eq!(body["timezone"], "America/Los_Angeles");

    // Test updating preferences
    let pref_data = json!({
        "theme": "dark",
        "language": "en",
        "notifications": {
            "email": true,
            "sms": false,
            "push": true
        }
    });
    let response = server
        .put("/users/user_123/preferences")
        .json(&pref_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["preferences"]["theme"], "dark");
    assert_eq!(body["preferences"]["language"], "en");
    assert_eq!(body["preferences"]["notifications"]["email"], true);
}

#[tokio::test]
async fn test_user_groups_and_invitations() {
    let user_state = UserMgmtState::new();

    // Pre-populate with test data
    {
        let mut groups = user_state.groups.lock().await;
        let mut users = user_state.users.lock().await;

        users.insert(
            "user_admin".to_string(),
            UserAccount {
                id: "user_admin".to_string(),
                email: "admin@example.com".to_string(),
                username: "admin".to_string(),
                password_hash: "hash_password".to_string(),
                status: AccountStatus::Active,
                created_at: "2024-12-01T10:00:00Z".to_string(),
                updated_at: "2024-12-01T10:00:00Z".to_string(),
                last_login: None,
                login_count: 0,
                failed_login_attempts: 0,
                locked_until: None,
                email_verified: true,
                two_factor_enabled: false,
            },
        );

        groups.insert(
            "group_engineering".to_string(),
            Group {
                id: "group_engineering".to_string(),
                name: "Engineering Team".to_string(),
                description: "All engineering department members".to_string(),
                created_by: "user_admin".to_string(),
                created_at: "2024-12-01T11:00:00Z".to_string(),
                member_count: 0,
                is_system_group: false,
            },
        );
    }

    let app =
        Router::new()
            .route(
                "/groups",
                post(
                    move |State(state): State<UserMgmtState>,
                          Json(create): Json<serde_json::Value>| async move {
                        let mut groups = state.groups.lock().await;

                        let name = create.get("name").and_then(|n| n.as_str()).unwrap_or("");
                        let description = create
                            .get("description")
                            .and_then(|d| d.as_str())
                            .unwrap_or("");
                        let created_by = create
                            .get("created_by")
                            .and_then(|c| c.as_str())
                            .unwrap_or("");

                        let group_id = format!("group_{}", groups.len() + 1);
                        groups.insert(
                            group_id.clone(),
                            Group {
                                id: group_id.clone(),
                                name: name.to_string(),
                                description: description.to_string(),
                                created_by: created_by.to_string(),
                                created_at: "2024-12-01T12:00:00Z".to_string(),
                                member_count: 0,
                                is_system_group: false,
                            },
                        );

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "group_id": group_id,
                            "status": "created",
                            "message": "Group created successfully"
                        })))
                    },
                ),
            )
            .route(
                "/groups/{group_id}/members",
                post(
                    move |State(state): State<UserMgmtState>,
                          axum::extract::Path(group_id): axum::extract::Path<String>,
                          Json(add): Json<serde_json::Value>| async move {
                        let mut user_groups = state.user_groups.lock().await;
                        let mut groups = state.groups.lock().await;
                        let users = state.users.lock().await;

                        let user_id = add.get("user_id").and_then(|u| u.as_str()).unwrap_or("");

                        // Validate user and group exist
                        if !users.contains_key(user_id) {
                            return Err(StatusCode::NOT_FOUND);
                        }
                        if !groups.contains_key(&group_id) {
                            return Err(StatusCode::NOT_FOUND);
                        }

                        // Add user to group
                        user_groups
                            .entry(user_id.to_string())
                            .or_insert_with(Vec::new)
                            .push(group_id.clone());

                        // Update member count
                        if let Some(group) = groups.get_mut(&group_id) {
                            group.member_count += 1;
                        }

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "group_id": group_id,
                            "user_id": user_id,
                            "status": "added",
                            "message": "User added to group successfully"
                        })))
                    },
                ),
            )
            .route(
                "/invitations",
                post(
                    move |State(state): State<UserMgmtState>,
                          Json(invite): Json<serde_json::Value>| async move {
                        let mut invitations = state.invitations.lock().await;

                        let email = invite.get("email").and_then(|e| e.as_str()).unwrap_or("");
                        let invited_by = invite
                            .get("invited_by")
                            .and_then(|i| i.as_str())
                            .unwrap_or("");
                        let role = invite
                            .get("role")
                            .and_then(|r| r.as_str())
                            .unwrap_or("member");

                        let invitation_id = format!("inv_{}", invitations.len() + 1);
                        invitations.insert(
                            invitation_id.clone(),
                            Invitation {
                                id: invitation_id.clone(),
                                email: email.to_string(),
                                invited_by: invited_by.to_string(),
                                role: role.to_string(),
                                status: "pending".to_string(),
                                expires_at: "2024-12-08T12:00:00Z".to_string(),
                                created_at: "2024-12-01T12:00:00Z".to_string(),
                                accepted_at: None,
                            },
                        );

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "invitation_id": invitation_id,
                            "email": email,
                            "role": role,
                            "expires_at": "2024-12-08T12:00:00Z",
                            "status": "sent",
                            "message": "Invitation sent successfully"
                        })))
                    },
                ),
            )
            .route(
                "/invitations/{invitation_id}/accept",
                post(
                    move |State(state): State<UserMgmtState>,
                          axum::extract::Path(invitation_id): axum::extract::Path<String>,
                          Json(accept): Json<serde_json::Value>| async move {
                        let mut invitations = state.invitations.lock().await;
                        let mut users = state.users.lock().await;
                        let mut profiles = state.profiles.lock().await;

                        if let Some(invitation) = invitations.get_mut(&invitation_id) {
                            if invitation.status != "pending" {
                                return Err(StatusCode::BAD_REQUEST);
                            }

                            invitation.status = "accepted".to_string();
                            invitation.accepted_at = Some("2024-12-01T12:30:00Z".to_string());

                            // Create user account from invitation
                            let user_id = format!("user_{}", users.len() + 1);
                            let password = accept
                                .get("password")
                                .and_then(|p| p.as_str())
                                .unwrap_or("temppassword123");

                            users.insert(
                                user_id.clone(),
                                UserAccount {
                                    id: user_id.clone(),
                                    email: invitation.email.clone(),
                                    username: invitation
                                        .email
                                        .split('@')
                                        .next()
                                        .unwrap_or("user")
                                        .to_string(),
                                    password_hash: format!("hash_{}", password),
                                    status: AccountStatus::Active,
                                    created_at: "2024-12-01T12:30:00Z".to_string(),
                                    updated_at: "2024-12-01T12:30:00Z".to_string(),
                                    last_login: None,
                                    login_count: 0,
                                    failed_login_attempts: 0,
                                    locked_until: None,
                                    email_verified: true,
                                    two_factor_enabled: false,
                                },
                            );

                            // Create basic profile
                            profiles.insert(
                                user_id.clone(),
                                UserProfile {
                                    user_id: user_id.clone(),
                                    first_name: "".to_string(),
                                    last_name: "".to_string(),
                                    display_name: invitation
                                        .email
                                        .split('@')
                                        .next()
                                        .unwrap_or("User")
                                        .to_string(),
                                    avatar_url: None,
                                    bio: None,
                                    phone: None,
                                    department: None,
                                    job_title: None,
                                    location: None,
                                    timezone: "UTC".to_string(),
                                    preferences: HashMap::new(),
                                },
                            );

                            Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                                "user_id": user_id,
                                "invitation_id": invitation_id,
                                "status": "accepted",
                                "message": "Invitation accepted and account created"
                            })))
                        } else {
                            Err(StatusCode::NOT_FOUND)
                        }
                    },
                ),
            )
            .with_state(user_state);

    let server = TestServer::new(app).unwrap();

    // Test group creation
    let group_data = json!({
        "name": "Marketing Team",
        "description": "All marketing department members",
        "created_by": "user_admin"
    });
    let response = server.post("/groups").json(&group_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let group_id = body["group_id"].as_str().unwrap();

    // Test adding user to group
    let add_data = json!({"user_id": "user_admin"});
    let response = server
        .post(&format!("/groups/{}/members", group_id))
        .json(&add_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test sending invitation
    let invite_data = json!({
        "email": "newuser@example.com",
        "invited_by": "user_admin",
        "role": "member"
    });
    let response = server.post("/invitations").json(&invite_data).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    let invitation_id = body["invitation_id"].as_str().unwrap();

    // Test accepting invitation
    let accept_data = json!({"password": "newpassword123"});
    let response = server
        .post(&format!("/invitations/{}/accept", invitation_id))
        .json(&accept_data)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["user_id"].as_str().is_some());
    assert_eq!(body["status"], "accepted");
}

#[tokio::test]
async fn test_account_security_and_audit() {
    let user_state = UserMgmtState::new();

    // Pre-populate with a test user
    {
        let mut users = user_state.users.lock().await;
        let mut account_history = user_state.account_history.lock().await;

        let user_id = "user_security".to_string();
        users.insert(
            user_id.clone(),
            UserAccount {
                id: user_id.clone(),
                email: "security@example.com".to_string(),
                username: "securityuser".to_string(),
                password_hash: "hash_oldpassword".to_string(),
                status: AccountStatus::Active,
                created_at: "2024-12-01T10:00:00Z".to_string(),
                updated_at: "2024-12-01T10:00:00Z".to_string(),
                last_login: Some("2024-12-01T11:00:00Z".to_string()),
                login_count: 5,
                failed_login_attempts: 0,
                locked_until: None,
                email_verified: true,
                two_factor_enabled: false,
            },
        );

        // Add some history events
        account_history.insert(
            user_id,
            vec![
                AccountEvent {
                    id: "event_1".to_string(),
                    event_type: "login".to_string(),
                    description: "Successful login".to_string(),
                    timestamp: "2024-12-01T11:00:00Z".to_string(),
                    ip_address: Some("192.168.1.100".to_string()),
                    user_agent: Some("Mozilla/5.0".to_string()),
                    metadata: HashMap::new(),
                },
                AccountEvent {
                    id: "event_2".to_string(),
                    event_type: "password_change".to_string(),
                    description: "Password changed".to_string(),
                    timestamp: "2024-12-01T10:30:00Z".to_string(),
                    ip_address: Some("192.168.1.100".to_string()),
                    user_agent: Some("Mozilla/5.0".to_string()),
                    metadata: HashMap::new(),
                },
            ],
        );
    }

    let app = Router::new()
        .route(
            "/users/{user_id}/security/enable-2fa",
            post(
                move |State(state): State<UserMgmtState>,
                      axum::extract::Path(user_id): axum::extract::Path<String>| async move {
                    let mut users = state.users.lock().await;
                    let mut account_history = state.account_history.lock().await;

                    if let Some(user) = users.get_mut(&user_id) {
                        user.two_factor_enabled = true;

                        // Log security event
                        let event_count = account_history.len();
                        account_history
                            .entry(user_id.clone())
                            .or_insert_with(Vec::new)
                            .push(AccountEvent {
                                id: format!("event_{}", event_count + 1),
                                event_type: "2fa_enabled".to_string(),
                                description: "Two-factor authentication enabled".to_string(),
                                timestamp: "2024-12-01T12:00:00Z".to_string(),
                                ip_address: None,
                                user_agent: None,
                                metadata: HashMap::new(),
                            });

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "user_id": user_id,
                            "two_factor_enabled": true,
                            "message": "Two-factor authentication enabled successfully"
                        })))
                    } else {
                        Err(StatusCode::NOT_FOUND)
                    }
                },
            ),
        )
        .route(
            "/users/{user_id}/audit",
            get(
                move |State(state): State<UserMgmtState>,
                      axum::extract::Path(user_id): axum::extract::Path<String>| async move {
                    let account_history = state.account_history.lock().await;

                    if let Some(events) = account_history.get(&user_id) {
                        let audit_events: Vec<serde_json::Value> = events
                            .iter()
                            .map(|event| {
                                json!({
                                    "id": event.id,
                                    "event_type": event.event_type,
                                    "description": event.description,
                                    "timestamp": event.timestamp,
                                    "ip_address": event.ip_address,
                                    "user_agent": event.user_agent
                                })
                            })
                            .collect();

                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "user_id": user_id,
                            "events": audit_events,
                            "total_events": audit_events.len()
                        })))
                    } else {
                        Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                            "user_id": user_id,
                            "events": [],
                            "total_events": 0
                        })))
                    }
                },
            ),
        )
        .route(
            "/users/{user_id}/security/sessions",
            get(
                move |State(state): State<UserMgmtState>,
                      axum::extract::Path(user_id): axum::extract::Path<String>| async move {
                    // In a real implementation, this would track active sessions
                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "user_id": user_id,
                        "active_sessions": [
                            {
                                "session_id": "sess_123",
                                "ip_address": "192.168.1.100",
                                "user_agent": "Mozilla/5.0",
                                "created_at": "2024-12-01T11:00:00Z",
                                "last_activity": "2024-12-01T11:30:00Z"
                            }
                        ],
                        "total_sessions": 1
                    })))
                },
            ),
        )
        .route(
            "/users/{user_id}/security/sessions/{session_id}/revoke",
            delete(
                move |State(state): State<UserMgmtState>,
                      axum::extract::Path((user_id, session_id)): axum::extract::Path<(
                    String,
                    String,
                )>| async move {
                    // In a real implementation, this would revoke the specific session
                    Ok::<Json<serde_json::Value>, StatusCode>(Json(json!({
                        "user_id": user_id,
                        "session_id": session_id,
                        "status": "revoked",
                        "message": "Session revoked successfully"
                    })))
                },
            ),
        )
        .with_state(user_state);

    let server = TestServer::new(app).unwrap();

    // Test enabling 2FA
    let response = server
        .post("/users/user_security/security/enable-2fa")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["two_factor_enabled"], true);

    // Test getting audit log
    let response = server.get("/users/user_security/audit").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert!(body["total_events"].as_u64().unwrap() >= 2); // Should include the 2FA enable event

    // Test getting active sessions
    let response = server.get("/users/user_security/security/sessions").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["total_sessions"], 1);

    // Test revoking session
    let response = server
        .delete("/users/user_security/security/sessions/sess_123/revoke")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let body: serde_json::Value = response.json();
    assert_eq!(body["status"], "revoked");
}
