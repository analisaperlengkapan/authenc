// tests/webauthn_integration_tests.rs

use authenc::config::DatabaseConfig;
use authenc::database::operations::{realms, users};
use authenc::database::Database;
use authenc::models::realm::CreateRealmRequest;
use authenc::models::user::CreateUserRequest;
use authenc::services::webauthn::{
    WebAuthnAuthenticationRequest, WebAuthnAuthenticationResponse, WebAuthnAuthenticatorAssertionResponse,
    WebAuthnAuthenticatorAttestationResponse, WebAuthnRegistrationRequest, WebAuthnRegistrationResponse,
    WebAuthnService,
};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

// Common setup function for WebAuthn integration tests
async fn setup_test_environment() -> (Arc<Database>, WebAuthnService, Uuid, String) {
    let db_host = std::env::var("PG_HOST").unwrap_or_else(|_| "localhost".to_string());
    let db_port = std::env::var("PG_PORT")
        .map(|s| s.parse().unwrap_or(5432))
        .unwrap_or(5432);
    let db_user = std::env::var("PG_USER").unwrap_or_else(|_| "test".to_string());
    let db_password = std::env::var("PG_PASSWORD").unwrap_or_else(|_| "test".to_string());

    let db_config = DatabaseConfig {
        host: db_host,
        port: db_port,
        username: db_user,
        password: db_password,
        database: "test_db".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let db = Arc::new(Database::new(&db_config).await.expect("Failed to connect to test_db"));
    let webauthn_service = WebAuthnService::new(
        Arc::clone(&db),
        "localhost".to_string(),
        "Test RP".to_string(),
        "test_jwt_secret".to_string(),
        None,
    );

    let test_realm_name = format!("test-realm-{}", Uuid::new_v4());
    let create_realm_req = CreateRealmRequest {
        name: test_realm_name.clone(),
        display_name: Some("Test Realm".to_string()),
        ..Default::default()
    };
    let realm = realms::create_realm(&db, &create_realm_req).await.expect("Failed to create test realm");

    let test_username = format!("test-user-{}", Uuid::new_v4());
    let create_user_req = CreateUserRequest {
        username: test_username.clone(),
        email: format!("{}@test.com", test_username),
        password: Some("password".to_string()),
        realm_id: Some(realm.id),
        ..Default::default()
    };
    users::create_user(&db, &create_user_req).await.expect("Failed to create test user");

    (db, webauthn_service, realm.id, test_username)
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_full_registration_flow() {
    let (db, service, realm_id, username) = setup_test_environment().await;

    // 1. Generate registration challenge
    let registration_request = WebAuthnRegistrationRequest {
        username: username.clone(),
        display_name: "Test User".to_string(),
        realm_id,
    };
    let challenge_response = service.generate_registration_challenge(registration_request).await.unwrap();
    let challenge_json: serde_json::Value = challenge_response.0;
    let challenge = challenge_json["challenge"].as_str().unwrap().to_string();

    // 2. Simulate client response
    let client_data_json = json!({
        "type": "webauthn.create",
        "challenge": challenge,
        "origin": "http://localhost:3000",
    });
    let client_data_json_b64 = Base64UrlUnpadded::encode_string(&client_data_json.to_string().into_bytes()).into_bytes();
    let attestation_object_b64 = Base64UrlUnpadded::encode_string(b"mock_attestation_object").into_bytes();

    let registration_response = WebAuthnRegistrationResponse {
        id: "test_credential_id".to_string(),
        raw_id: Base64UrlUnpadded::encode_string(b"test_credential_id").into_bytes(),
        ty: "public-key".to_string(),
        response: WebAuthnAuthenticatorAttestationResponse {
            client_data_json: client_data_json_b64,
            attestation_object: attestation_object_b64.clone(),
        },
        extensions: None,
    };

    // 3. Verify registration
    let verification_result = service
        .verify_registration(&realm_id, &username, registration_response, None)
        .await;
    assert!(verification_result.is_ok(), "Verification should succeed");

    // 4. Verify credential in database
    let user = users::get_user_by_username(&db, &realm_id, &username).await.unwrap().unwrap();
    let conn = db.get_connection().await.unwrap();
    let row = conn
        .query_one(
            "SELECT attestation_object FROM webauthn_credentials WHERE user_id = $1",
            &[&user.id],
        )
        .await
        .unwrap();

    let stored_attestation_object: Option<Vec<u8>> = row.get(0);
    assert!(stored_attestation_object.is_some(), "Attestation object should be stored");

    // 5. Verify that the stored object is encrypted
    let stored_data = stored_attestation_object.unwrap();
    // The raw mock data is "mock_attestation_object". If it's stored encrypted, it won't be that.
    assert_ne!(stored_data, attestation_object_b64, "Stored attestation object should be encrypted");
    // A simple check is to see if it's valid JSON, as our encryption service wraps it in a JSON structure.
    assert!(serde_json::from_slice::<serde_json::Value>(&stored_data).is_ok(), "Stored data should be a valid JSON object representing the encrypted data structure");
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_full_registration_flow_with_valid_data() {
    let (db, service, realm_id, username) = setup_test_environment().await;
    let authenticator = test_authenticator::TestAuthenticator::new(0);

    let registration_request = WebAuthnRegistrationRequest {
        username: username.clone(),
        display_name: "Test User".to_string(),
        realm_id,
    };
    let challenge_response = service.generate_registration_challenge(registration_request).await.unwrap();
    let ccr: CreationChallengeResponse = serde_json::from_value(challenge_response.0).unwrap();

    let client_data = json!({
        "type": "webauthn.create",
        "challenge": ccr.public_key.challenge,
        "origin": "https://localhost",
    });
    let client_data_b64 = Base64UrlUnpadded::encode_string(client_data.to_string().as_bytes());
    let client_data_hash = sha2::Sha256::digest(client_data.to_string().as_bytes());
    let attestation_object = authenticator.attestation_object(&client_data_hash);

    let registration_response = WebAuthnRegistrationResponse {
        id: "test_credential_id".to_string(),
        raw_id: base64ct::Base64UrlUnpadded::encode_string(b"test_credential_id").into_bytes(),
        ty: "public-key".to_string(),
        response: WebAuthnAuthenticatorAttestationResponse {
            client_data_json: client_data_b64.into_bytes(),
            attestation_object: base64ct::Base64UrlUnpadded::encode_string(&attestation_object).into_bytes(),
        },
        extensions: None,
    };

    let result = service.verify_registration(&realm_id, &username, registration_response, None).await;
    assert!(result.is_ok(), "Registration should succeed with valid data");

    let credential = webauthn_db::get_credential_by_id(&db, b"test_credential_id").await.unwrap();
    assert!(credential.is_some(), "Credential should be stored in the database");
    assert_eq!(credential.unwrap().signature_counter, 0, "Initial signature counter should be 0");
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_full_authentication_flow() {
    let (db, service, realm_id, username) = setup_test_environment().await;

    // 1. Register a credential first
    let registration_request = WebAuthnRegistrationRequest {
        username: username.clone(),
        display_name: "Test User".to_string(),
        realm_id,
    };
    let reg_challenge_response = service.generate_registration_challenge(registration_request).await.unwrap();
    let reg_challenge_json: serde_json::Value = reg_challenge_response.0;
    let reg_challenge = reg_challenge_json["challenge"].as_str().unwrap().to_string();

    let reg_client_data_json = json!({
        "type": "webauthn.create",
        "challenge": reg_challenge,
        "origin": "http://localhost:3000",
    });
    let reg_client_data_json_b64 = Base64UrlUnpadded::encode_string(&reg_client_data_json.to_string().into_bytes()).into_bytes();
    let reg_attestation_object_b64 = Base64UrlUnpadded::encode_string(b"mock_attestation_object").into_bytes();

    let registration_response = WebAuthnRegistrationResponse {
        id: "test_credential_id".to_string(),
        raw_id: Base64UrlUnpadded::encode_string(b"test_credential_id").into_bytes(),
        ty: "public-key".to_string(),
        response: WebAuthnAuthenticatorAttestationResponse {
            client_data_json: reg_client_data_json_b64,
            attestation_object: reg_attestation_object_b64,
        },
        extensions: None,
    };
    service.verify_registration(&realm_id, &username, registration_response, None).await.unwrap();

    // 2. Generate authentication challenge
    let auth_request = WebAuthnAuthenticationRequest {
        username: username.clone(),
        realm_id,
    };
    let auth_challenge_response = service.generate_authentication_challenge(auth_request).await.unwrap();
    let auth_challenge_json: serde_json::Value = auth_challenge_response.0;
    let auth_challenge = auth_challenge_json["challenge"].as_str().unwrap().to_string();

    // 3. Simulate client authentication
    let auth_client_data_json = json!({
        "type": "webauthn.get",
        "challenge": auth_challenge,
        "origin": "http://localhost:3000",
    });
    let auth_client_data_json_b64 = Base64UrlUnpadded::encode_string(&auth_client_data_json.to_string().into_bytes()).into_bytes();

    let authentication_response = WebauthnAuthenticationResponse {
        id: "test_credential_id".to_string(),
        raw_id: Base64UrlUnpadded::encode_string(b"test_credential_id").into_bytes(),
        ty: "public-key".to_string(),
        response: WebAuthnAuthenticatorAssertionResponse {
            client_data_json: auth_client_data_json_b64,
            authenticator_data: Base64UrlUnpadded::encode_string(b"mock_authenticator_data").into_bytes(),
            signature: Base64UrlUnpadded::encode_string(b"mock_signature").into_bytes(),
            user_handle: None,
        },
        extensions: None,
    };

    // 4. Verify authentication
    let verification_result = service
        .verify_authentication(&realm_id, &username, authentication_response)
        .await;
    assert!(verification_result.is_ok(), "Authentication verification should succeed");

    // 5. Verify signature counter in database
    let user = users::get_user_by_username(&db, &realm_id, &username).await.unwrap().unwrap();
    let conn = db.get_connection().await.unwrap();
    let row = conn
        .query_one(
            "SELECT signature_counter FROM webauthn_credentials WHERE user_id = $1",
            &[&user.id],
        )
        .await
        .unwrap();

    let signature_counter: i64 = row.get(0);
    // The mock authenticator data is 23 bytes long.
    assert_eq!(signature_counter, 23, "Signature counter should be updated");
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_registration_with_mismatched_challenge() {
    let (_db, service, realm_id, username) = setup_test_environment().await;

    let registration_request = WebAuthnRegistrationRequest {
        username: username.clone(),
        display_name: "Test User".to_string(),
        realm_id,
    };
    service.generate_registration_challenge(registration_request).await.unwrap();

    let client_data_json = json!({
        "type": "webauthn.create",
        "challenge": "invalid_challenge",
        "origin": "http://localhost:3000",
    });
    let client_data_json_b64 = Base64UrlUnpadded::encode_string(&client_data_json.to_string().into_bytes()).into_bytes();

    let registration_response = WebAuthnRegistrationResponse {
        id: "test_credential_id".to_string(),
        raw_id: Base64UrlUnpadded::encode_string(b"test_credential_id").into_bytes(),
        ty: "public-key".to_string(),
        response: WebAuthnAuthenticatorAttestationResponse {
            client_data_json: client_data_json_b64,
            attestation_object: Base64UrlUnpadded::encode_string(b"mock_attestation_object").into_bytes(),
        },
        extensions: None,
    };

    let result = service.verify_registration(&realm_id, &username, registration_response, None).await;
    assert!(result.is_err(), "Verification should fail with mismatched challenge");
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_authentication_with_non_existent_credential() {
    let (_db, service, realm_id, username) = setup_test_environment().await;

    // Generate a challenge, but don't register a credential
    let auth_request = WebAuthnAuthenticationRequest {
        username: username.clone(),
        realm_id,
    };
    let auth_challenge_response = service.generate_authentication_challenge(auth_request).await.unwrap();
    let auth_challenge_json: serde_json::Value = auth_challenge_response.0;
    let auth_challenge = auth_challenge_json["challenge"].as_str().unwrap().to_string();

    let client_data_json = json!({
        "type": "webauthn.get",
        "challenge": auth_challenge,
        "origin": "http://localhost:3000",
    });
    let client_data_json_b64 = Base64UrlUnpadded::encode_string(&client_data_json.to_string().into_bytes()).into_bytes();

    let authentication_response = WebAuthnAuthenticationResponse {
        id: "non_existent_credential".to_string(),
        raw_id: Base64UrlUnpadded::encode_string(b"non_existent_credential").into_bytes(),
        ty: "public-key".to_string(),
        response: WebAuthnAuthenticatorAssertionResponse {
            client_data_json: client_data_json_b64,
            authenticator_data: Base64UrlUnpadded::encode_string(b"mock_authenticator_data").into_bytes(),
            signature: Base64UrlUnpadded::encode_string(b"mock_signature").into_bytes(),
            user_handle: None,
        },
        extensions: None,
    };

    let result = service.verify_authentication(&realm_id, &username, authentication_response).await;
    assert!(result.is_err(), "Authentication should fail with a non-existent credential");
}
