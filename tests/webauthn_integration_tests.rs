use authenc::config::DatabaseConfig;
use authenc::database::Database;
use authenc::models::webauthn::*;
use authenc::services::webauthn::*;
use authenc::utils::crypto::jwt::{generate_jwt_with_claims, Claims};
use base64ct::{Base64UrlUnpadded, Encoding};
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_webauthn_device_binding_integration() {
    // Setup test database
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "test".to_string(),
        password: "test".to_string(),
        database: "test_db".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let database = Arc::new(Database::new(&database_config).await.unwrap());

    // Clean up any existing test user
    if let Ok(Some(existing_user)) = authenc::database::operations::users::get_user_by_username(&database, &Uuid::nil(), "device_binding_user").await {
        let _ = authenc::database::operations::users::delete_user(&database, existing_user.id).await;
        // Hard delete for cleanup
        let _ = database.execute("DELETE FROM users WHERE id = $1", &[&existing_user.id]).await;
    }

    // Create test user
    use authenc::models::user::CreateUserRequest;
    let user_id = Uuid::new_v4();
    let create_user_request = CreateUserRequest {
        username: "device_binding_user".to_string(),
        email: "device_binding@example.com".to_string(),
        password: Some("password123".to_string()),
        first_name: Some("Device".to_string()),
        last_name: Some("Binding".to_string()),
        phone_number: None,
        realm_id: None,
        organization_id: None,
        attributes: None,
    };

    // We need to create user manually to ensure we know the ID (or get it back)
    // Actually create_user returns User
    let user = authenc::database::operations::users::create_user(&database, &create_user_request).await.expect("Failed to create user");

    // 1. Create a device for the user
    use authenc::models::device::DeviceInfo;
    let device_info = DeviceInfo {
        device_name: Some("Test Device".to_string()),
        fingerprint: "test_fingerprint".to_string(),
        trust_score: Some(1.0),
        os: Some("TestOS".to_string()),
        os_version: Some("1.0".to_string()),
        browser: Some("TestBrowser".to_string()),
        browser_version: Some("1.0".to_string()),
        ip_address: Some("127.0.0.1".parse().unwrap()),
        user_agent: Some("TestAgent".to_string()),
        security_features: None, location_data: None,
    };

    let device = authenc::database::operations::devices::register_device(&database, user.id, &device_info).await.expect("Failed to register device");

    // 2. Create a session for the user on this device
    let session_id = Uuid::new_v4();
    let session_identifier = "test_session_id".to_string();

    // Create user session manually in DB to ensure we have control
    // Use the operation we added/verified
    let user_session_json = authenc::database::operations::sessions::create_user_session(
        &database,
        user.id,
        user.realm_id.expect("Realm ID required"),
        None,
        "token_hash", // mock
        None,
        3600,
        Some("127.0.0.1"),
        Some("TestAgent"),
        Some("password"),
        Some("oidc"),
    ).await.expect("Failed to create user session");

    let user_session_id = Uuid::parse_str(user_session_json.get("id").unwrap().as_str().unwrap()).unwrap();

    // Update user session with device_id (if create_user_session didn't take it - it didn't in my reading of code, wait)
    // create_user_session in operations.rs DOES NOT take device_id?
    // Let's check `src/database/operations.rs`.
    // It creates `user_sessions`. The table has `device_id`.
    // `create_user_session` function:
    /*
    pub async fn create_user_session(
        db: &Database,
        user_id: Uuid,
        realm_id: Uuid,
        client_id: Option<Uuid>,
        token: &str,
        refresh_token: Option<&str>,
        expires_in: i64,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        authentication_method: Option<&str>,
        protocol: Option<&str>,
    ) -> Result<serde_json::Value>
    */
    // It does NOT take device_id.
    // So I need to manually update the session to have device_id for this test to work, or update `create_user_session`.
    // Updating `create_user_session` is better but risky.
    // I'll manually update it for the test.

    database.execute("UPDATE user_sessions SET device_id = $1 WHERE id = $2", &[&device.id, &user_session_id]).await.expect("Failed to link session to device");

    // 3. Generate JWT with sid
    let jwt = generate_jwt_with_claims(
        &user.id.to_string(),
        Some(user.email.clone()),
        None,
        Some(user_session_id.to_string())
    ).expect("Failed to generate JWT");

    // 4. Simulate WebAuthn registration verification
    // We need to mock the request/response flow.
    // However, `verify_registration` in `WebAuthnService` takes `device_id` as argument (passed from handler).
    // The handler `register_verify` extracts `device_id` from session using `sid`.

    // So to test the "integration", we should ideally call the handler.
    // But calling handler requires Axum setup.
    // Alternatively, we can verify that:
    // a) JWT generation includes `sid` (Done via unit test in jwt.rs)
    // b) `register_verify` handler logic extracts `sid` and looks up `device_id`.

    // We can test the lookup logic here.

    // Simulate handler logic:
    use authenc::middleware::auth::AuthUser;
    let auth_user = AuthUser {
        id: user.id.to_string(),
        email: user.email.clone(),
        roles: vec![],
        session_id: Some(user_session_id.to_string()),
    };

    // Manually perform lookup
    let mut resolved_device_id = None;
    if let Some(sid_str) = &auth_user.session_id {
        if let Ok(sid) = Uuid::parse_str(sid_str) {
             if let Ok(Some(session_json)) = authenc::database::operations::sessions::get_user_session(&database, sid).await {
                if let Some(did_str) = session_json.get("device_id").and_then(|v| v.as_str()) {
                     if let Ok(did) = Uuid::parse_str(did_str) {
                         resolved_device_id = Some(did);
                     }
                }
            }
        }
    }

    assert_eq!(resolved_device_id, Some(device.id), "Failed to resolve device_id from session");

    // 5. Register credential with resolved device_id
    let webauthn_service = WebAuthnService::new(
        database.clone(),
        "localhost".to_string(),
        "Authenc".to_string(),
        "secret".to_string(),
        None,
    );

    // Create a mock credential to store
    // We need to bypass `verify_registration` signature checks which are hard to mock without valid attestation.
    // But `store_credential_db` is public on `WebAuthnService`?
    // In `src/services/webauthn.rs`:
    // `pub async fn store_credential_db(&self, credential: &WebauthnCredential) -> Result<()>`
    // Wait, the one I modified is `store_credential_db` which calls `webauthn_db::store_credential`.
    // And `store_credential` (private) calls `store_credential_db`.
    // And `verify_registration` calls `store_credential`.

    // Let's call `store_credential_db` directly with a credential that has `device_id` populated (simulating what `verify_registration` would do).

    let credential = WebauthnCredential {
        id: Uuid::new_v4(),
        user_id: user.id,
        credential_id: vec![1, 2, 3, 4],
        public_key: vec![5, 6, 7, 8],
        public_key_algorithm: -7,
        signature_counter: 0,
        attestation_object: Some(vec![1, 2]),
        authenticator_data: Some(vec![3, 4]),
        user_handle: Some(vec![5, 6]),
        credential_type: "public-key".to_string(),
        transports: None,
        aaguid: None,
        attestation_format: None,
        device_id: resolved_device_id,
        created_at: chrono::Utc::now(),
        last_used_at: None,
        enabled: true,
    };

    webauthn_service.store_credential_db(&credential).await.expect("Failed to store credential");

    // 6. Verify in DB
    // We can use `webauthn_db::get_user_credentials`.
    use authenc::database::operations::webauthn as webauthn_db;
    let creds = webauthn_db::get_user_credentials(&database, user.id).await.expect("Failed to get credentials");

    assert!(!creds.is_empty());
    let stored_cred = &creds[0];
    assert_eq!(stored_cred.device_id, Some(device.id), "Stored credential does not have correct device_id");

    // Cleanup
    let _ = database.execute("DELETE FROM user_sessions WHERE id = $1", &[&user_session_id]).await;
    let _ = database.execute("DELETE FROM devices WHERE id = $1", &[&device.id]).await;
    let _ = authenc::database::operations::users::delete_user(&database, user.id).await;
}
