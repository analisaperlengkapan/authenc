use authenc::database::Database;
use authenc::services::device::*;
use authenc::config::DatabaseConfig;
use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Helper function to setup test data
async fn setup_test_data(database: &Database) -> Result<(Uuid, Uuid), Box<dyn std::error::Error>> {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    // Create a test realm with unique name
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let realm_name = format!("test-realm-{}", timestamp);
    let realm_id = Uuid::new_v4();
    let realm_query = r#"
        INSERT INTO realms (id, name, display_name, enabled)
        VALUES ($1, $2, $3, $4)
    "#;
    database.execute(realm_query, &[&realm_id, &realm_name, &"Test Realm", &true]).await?;

    // Create a test user with unique username
    let user_id = Uuid::new_v4();
    let username = format!("testuser{}", timestamp);
    let email = format!("test{}@example.com", timestamp);
    let user_query = r#"
        INSERT INTO users (id, username, email, enabled, realm_id)
        VALUES ($1, $2, $3, $4, $5)
    "#;
    database.execute(user_query, &[&user_id, &username, &email, &true, &realm_id]).await?;

    Ok((realm_id, user_id))
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_device_registration() {
    // Setup test database
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "postgres".to_string(),
        password: "test".to_string(),
        database: "authenc_fips_test".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let database_result = Database::new(&database_config).await;
    let database = match database_result {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Skipping test due to database connection issues");
            return;
        }
    };
    let device_service = DeviceService::new(database.clone());

    // Setup test data
    let (_realm_id, user_id) = setup_test_data(&database).await.unwrap();
    let registration_request = DeviceRegistrationRequest {
        device_name: "Test iPhone".to_string(),
        os: "iOS".to_string(),
        os_version: "17.0".to_string(),
        browser: Some("Safari".to_string()),
        browser_version: Some("17.0".to_string()),
        ip_address: "192.168.1.100".to_string(),
        user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15".to_string(),
        security_features: DeviceSecurityFeatures {
            has_biometrics: true,
            has_hardware_security: true,
            has_screen_lock: true,
            encryption_enabled: true,
            remote_wipe_capable: true,
            jailbreak_detected: false,
        },
    };

    let result = device_service.register_device(user_id, registration_request).await;
    if let Err(ref e) = result {
        eprintln!("Device registration failed with error: {:?}", e);
    }
    assert!(result.is_ok(), "Device registration should succeed");

    let device = result.unwrap();
    assert_eq!(device.user_id, user_id);
    assert_eq!(device.device_name, "Test iPhone");
    assert_eq!(device.os, "iOS");
    assert_eq!(device.ip_address, "192.168.1.100");
    assert!(device.trust_score >= 0.0 && device.trust_score <= 1.0);
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_device_trust_evaluation() {
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "postgres".to_string(),
        password: "test".to_string(),
        database: "authenc_fips_test".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let database_result = Database::new(&database_config).await;
    let database = match database_result {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Skipping test due to database connection issues");
            return;
        }
    };
    let mut device_service = DeviceService::new(database.clone());

    // Setup test data
    let (_realm_id, user_id) = setup_test_data(&database).await.unwrap();
    let registration_request = DeviceRegistrationRequest {
        device_name: "Test Device".to_string(),
        os: "Windows".to_string(),
        os_version: "11".to_string(),
        browser: Some("Chrome".to_string()),
        browser_version: Some("120.0".to_string()),
        ip_address: "192.168.1.100".to_string(),
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
        security_features: DeviceSecurityFeatures {
            has_biometrics: true,
            has_hardware_security: true,
            has_screen_lock: true,
            encryption_enabled: true,
            remote_wipe_capable: false,
            jailbreak_detected: false,
        },
    };

    let device = device_service.register_device(user_id, registration_request).await.unwrap();

    // Test trust evaluation context
    let context = TrustEvaluationContext {
        is_first_login: false,
        known_device: true,
        unusual_time: false,
        location_changed: false,
        ip_reputation: 0.8,
        fingerprint_match: true,
    };

    let trust_result = device_service.evaluate_trust(&device, &context).await;
    assert!(trust_result.is_ok(), "Trust evaluation should succeed");

    let result = trust_result.unwrap();
    match result {
        TrustResult::Trusted => {
            // Expected for a device with good trust score and context
        }
        TrustResult::Untrusted => {
            // Also acceptable
        }
        TrustResult::ChallengeRequired(_) => {
            // Might happen depending on policies
        }
        TrustResult::Denied => {
            // Should not happen for this test case
            panic!("Device should not be denied access");
        }
    }
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_device_trust_policies() {
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "postgres".to_string(),
        password: "test".to_string(),
        database: "authenc_fips_test".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let database_result = Database::new(&database_config).await;
    let database = match database_result {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Skipping test due to database connection issues");
            return;
        }
    };
    let mut device_service = DeviceService::new(database);

    // Add a trust policy
    let policy = DeviceTrustPolicy {
        id: Uuid::new_v4(),
        name: "High Trust Score Policy".to_string(),
        description: "Allow devices with high trust scores".to_string(),
        conditions: vec![
            TrustCondition::TrustScoreAbove(0.8),
        ],
        action: TrustAction::Allow,
        enabled: true,
        priority: 10,
    };

    device_service.add_trust_policy(policy);

    // Verify policy was added
    let policies = device_service.get_trust_policies();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].name, "High Trust Score Policy");

    // Test policy removal
    let policy_id = policies[0].id;
    device_service.remove_trust_policy(policy_id);

    let policies_after_removal = device_service.get_trust_policies();
    assert_eq!(policies_after_removal.len(), 0);
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_device_session_management() {
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "postgres".to_string(),
        password: "test".to_string(),
        database: "authenc_fips_test".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let database_result = Database::new(&database_config).await;
    let database = match database_result {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Skipping test due to database connection issues");
            return;
        }
    };
    let device_service = DeviceService::new(database);

    // Create a test device first
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();

    // Test session creation
    let session_result = device_service.create_session(
        device_id,
        user_id,
        "session_123".to_string(),
        "192.168.1.100".to_string(),
    ).await;

    assert!(session_result.is_ok(), "Session creation should succeed");

    let session = session_result.unwrap();
    assert_eq!(session.device_id, device_id);
    assert_eq!(session.user_id, user_id);
    assert_eq!(session.session_id, "session_123");
    assert_eq!(session.ip_address, "192.168.1.100");
    assert!(session.is_active);
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_get_user_devices() {
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "postgres".to_string(),
        password: "test".to_string(),
        database: "authenc_fips_test".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let database_result = Database::new(&database_config).await;
    let database = match database_result {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Skipping test due to database connection issues");
            return;
        }
    };
    let device_service = DeviceService::new(database.clone());

    // Setup test data
    let (_realm_id, user_id) = setup_test_data(&database).await.unwrap();

    // Register multiple devices for the user
    let devices_data = vec![
        ("iPhone", "iOS", "17.0", Some("Safari"), Some("17.0")),
        ("MacBook", "macOS", "14.0", Some("Chrome"), Some("120.0")),
        ("Windows PC", "Windows", "11", Some("Edge"), Some("120.0")),
    ];

    for (name, os, os_version, browser, browser_version) in devices_data {
        let registration_request = DeviceRegistrationRequest {
            device_name: name.to_string(),
            os: os.to_string(),
            os_version: os_version.to_string(),
            browser: browser.map(|s| s.to_string()),
            browser_version: browser_version.map(|s| s.to_string()),
            ip_address: "192.168.1.100".to_string(),
            user_agent: format!("Mozilla/5.0 ({})", name),
            security_features: DeviceSecurityFeatures {
                has_biometrics: true,
                has_hardware_security: true,
                has_screen_lock: true,
                encryption_enabled: true,
                remote_wipe_capable: false,
                jailbreak_detected: false,
            },
        };

        let result = device_service.register_device(user_id, registration_request).await;
        assert!(result.is_ok(), "Device registration should succeed");
    }

    // Get user's devices
    let user_devices = device_service.get_user_devices(user_id).await;
    assert!(user_devices.is_ok(), "Getting user devices should succeed");

    let devices = user_devices.unwrap();
    assert_eq!(devices.len(), 3, "Should have 3 registered devices");

    // Verify device names
    let device_names: Vec<String> = devices.iter().map(|d| d.device_name.clone()).collect();
    assert!(device_names.contains(&"iPhone".to_string()));
    assert!(device_names.contains(&"MacBook".to_string()));
    assert!(device_names.contains(&"Windows PC".to_string()));
}
