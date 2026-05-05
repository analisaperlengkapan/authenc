use authenc::app::AppState;
use authenc::config::AppConfig;
use authenc::models::user::{CreateUserRequest, User};
use authenc::services::stores::user_store::UserStoreTrait;
use authenc::services::stores::session_store::SessionStoreTrait;
use authenc::services::stores::consent_store::ConsentStoreTrait;
use authenc::services::realm::RealmService;
use authenc::services::oauth2::ClientValidator;
use authenc::models::oauth2::OAuth2Client;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use tower::ServiceExt; // for `oneshot`
use std::sync::Arc;
use async_trait::async_trait;

#[path = "mocks/mod.rs"]
mod mocks;
use mocks::user_store::MockUserStore;
use mocks::consent_store::MockConsentStore;
use mocks::session_store::MockSessionStore;
use mocks::realm_service::MockRealmService;

struct MockAuditLogSink;
impl authenc::services::audit::audit_log_sink::AuditLogSink for MockAuditLogSink {
    fn send(&self, _log: &authenc::models::audit_log::AuditLog) {}
}

struct MockClientValidator;

#[async_trait]
impl ClientValidator for MockClientValidator {
    async fn validate_client(&self, client_id: &str, _client_secret: Option<&str>) -> authenc::error::Result<Option<OAuth2Client>> {
        if client_id == "test-client" {
            Ok(Some(OAuth2Client {
                id: uuid::Uuid::new_v4(),
                client_id: "test-client".to_string(),
                client_secret_hash: "secret".to_string(),
                client_name: "Test Client".to_string(),
                client_type: "public".to_string(),
                redirect_uris: vec![],
                scopes: vec![],
                grant_types: vec![],
                response_types: vec![],
                token_endpoint_auth_method: "none".to_string(),
                owner_id: None,
                realm_id: Some(uuid::Uuid::nil()),
                enabled: true,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                deleted_at: None,
            }))
        } else {
            Ok(None)
        }
    }
}

#[tokio::test]
async fn test_account_lockout_logic() {
    // 1. Setup Mocks
    let mock_user_store = Arc::new(MockUserStore::new()); // Concrete type to access internal verify if needed
    let mock_user_store_dyn: Arc<dyn UserStoreTrait> = mock_user_store.clone();

    let mock_consent_store: Arc<dyn ConsentStoreTrait> = Arc::new(MockConsentStore::new());
    let mock_session_store: Arc<dyn SessionStoreTrait> = Arc::new(MockSessionStore::new());
    let mock_realm_service: Arc<dyn RealmService> = Arc::new(MockRealmService::new());

    // 2. Setup AppState
    let config = AppConfig::default();
    let database = Arc::new(authenc::database::Database::mock().await);

    // Helper to create other stores with mock DB
    let auth_flow_store = Arc::new(authenc::services::stores::auth_flow_store::AuthFlowStore::new(database.clone()));
    let totp_store = Arc::new(authenc::services::stores::totp_store::TotpStore::new());
    let brute_force_protector = Arc::new(authenc::services::security::brute_force_protector::BruteForceProtector::new(10, 60));
    let anomaly_detector = Arc::new(authenc::services::security::anomaly_detector::AnomalyDetector::new());
    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());
    let federation_registry = Arc::new(authenc::services::federation_provider::FederationRegistry::new());
    let audit_log_store = Arc::new(authenc::services::stores::pg_audit_log_store::PgAuditLogStore::with_pool(database.get_pool()));
    let realm_store = Arc::new(authenc::services::stores::realm_store::RealmStore::new());
    let role_store = Arc::new(authenc::services::stores::role_store::RoleStore::new());
    let permission_store = Arc::new(authenc::services::stores::permission_store::PermissionStore::new());
    let resource_store = Arc::new(authenc::services::stores::resource_store::ResourceStore::new(database.clone()));
    let resource_server_store = Arc::new(authenc::services::stores::resource_server_store::ResourceServerStore::new(database.clone()));
    let permission_ticket_store = Arc::new(authenc::services::stores::permission_ticket_store::PermissionTicketStore::new(database.clone()));
    let scope_store = Arc::new(authenc::services::stores::scope_store::ScopeStore::new(database.clone()));
    let oidc_client_store = Arc::new(authenc::services::stores::oidc_client_store::OidcClientStore::with_database(database.clone()));
    let social_account_store = Arc::new(authenc::services::stores::social_account_store::SocialAccountStore::new(database.clone()));
    let broker_registry = Arc::new(authenc::services::broker::IdentityBrokerRegistry::new());
    let oid4vc_service = Arc::new(authenc::services::protocols::oid4vc::EnhancedOid4VcManager::new("https://example.com".to_string()));
    let sso_cookie_manager = Arc::new(authenc::services::sso::SsoCookieManager::new(b"secret", "cookie", None, true));
    let sso_session_manager = Arc::new(authenc::services::sso::session::DefaultSsoSessionManager::new());
    let sso_service = Arc::new(authenc::services::sso::DefaultSsoService::new(sso_session_manager.clone(), sso_cookie_manager.clone(), database.clone()));
    let event_manager = authenc::services::events::create_shared_event_manager();
    let event_store = Arc::new(authenc::services::stores::pg_event_store::PgEventStoreProvider::new(database.clone()));
    let event_retention_service = Arc::new(authenc::services::events::event_retention::EventRetentionService::new(config.events.clone(), database.clone(), event_store));
    let spi_manager = Arc::new(authenc::spi::SpiManager::new());
    let observability_service = Arc::new(authenc::services::observability::ObservabilityService::default());
    let compliance_mode_service = Arc::new(authenc::services::compliance_mode::ComplianceModeService::new(event_manager.clone(), Some(mock_consent_store.clone())));
    let oauth2_service = Arc::new(authenc::services::oauth2::OAuth2Service::new(database.clone()));
    let webauthn_service = Arc::new(authenc::services::protocols::webauthn::WebAuthnService::new(
        database.clone(),
        "localhost".to_string(),
        "Authenc Test".to_string(),
        "test-secret".to_string(),
        None,
    ));
    let fips_provider = Arc::new(authenc::services::fips::AdvancedFipsSecurityProvider::new());

    // Initialize Authorization Manager
    let authorization_manager = Arc::new(authenc::services::authorization::AuthorizationManager::new(database.clone()));

    // Initialize Social Login Manager
    let pg_social_store = authenc::services::social::pg_store::PgSocialStateStore::new(database.clone());
    let social_login_manager = Arc::new(authenc::services::social::SocialLoginManager::with_store(Arc::new(pg_social_store)));

    // Initialize JIT Service
    let admin_manager = Arc::new(authenc::services::admin::AdminManager::new(database.clone()));
    let jit_provisioning_service = Arc::new(authenc::services::federation::jit_provisioning::DefaultJITProvisioningService::new(
        database.clone(),
        admin_manager
    ));

    let zero_trust_manager = Arc::new(authenc::services::security::zero_trust::ZeroTrustManager::new());


    let state = AppState {
        config: Arc::new(config),
        database,
        user_store: mock_user_store_dyn.clone(),
        session_store: mock_session_store.clone(),
        totp_store,
        brute_force_protector,
        anomaly_detector,
        zero_trust_manager,
        federation_registry,
        audit_log_store,
        consent_store: mock_consent_store.clone(),
        auth_flow_store,
        realm_store,
        realm_service: mock_realm_service.clone(),
        role_store,
        permission_store,
        resource_store,
        resource_server_store,
        permission_ticket_store,
        scope_store,
        oidc_client_store,
        social_account_store,
        broker_registry,
        oid4vc_service,
        sso_service,
        sso_cookie_manager,
        event_manager,
        event_retention_service,
        audit_log_sink: Arc::new(MockAuditLogSink),
        spi_manager,
        cluster_manager: None,
        observability_service,
        compliance_mode_service,
        oauth2_service,
        webauthn_service,
        fips_provider,
        social_login_manager,
        authorization_manager,
        sso_session_manager,
        jit_provisioning_service,
        client_validator: Arc::new(MockClientValidator),
        password_reset_service: Arc::new(authenc::services::password_reset::PasswordResetService::new(
            mock_user_store_dyn.clone(),
        )),
        password_reset_protector: Arc::new(authenc::services::security::brute_force_protector::BruteForceProtector::new(5, 300)),
        email_verification_service: Arc::new(authenc::services::email_verification::EmailVerificationService::new(
            mock_user_store_dyn.clone(),
        )),


    };

    let router = authenc::handlers::create_router(Arc::new(state.clone()));

    // Create User
    // Use a hash that we know works with the verifier, or assume verify_password returns false for "wrongpassword"
    // and true for "password123" if the hash matches.
    // However, verify_password uses Argon2.
    // For this test, we rely on the fact that `verify_password` will fail for "wrongpassword".
    // We need it to succeed for "password123" at the end.
    // So we need a real hash of "password123".
    let password = "password123";
    let password_hash = authenc_crypto::utils::crypto::password::hash_password(password).await.unwrap();

    let create_user_req = CreateUserRequest {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: Some(password_hash),
        first_name: Some("Test".to_string()),
        last_name: Some("User".to_string()),
        phone_number: None,
        realm_id: Some(uuid::Uuid::nil()),
        organization_id: None,
        attributes: None,
        email_verified: Some(true),
        enabled: Some(true),
        require_password_change: Some(false),
    };

    let user = mock_user_store.add_user(create_user_req).await.expect("Failed to add user");
    let user_id = user.id;

    // 5 Failed Attempts
    for i in 1..=5 {
        println!("Attempt {}", i);
        let login_body = serde_json::json!({
            "grant_type": "password",
            "username": "testuser",
            "password": "wrongpassword",
            "client_id": "test-client"
        });

        let request = Request::builder()
            .uri("/oauth2/token")
            .method("POST")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&login_body).unwrap()))
            .unwrap();

        let response = router.clone().oneshot(request).await.unwrap();

        // Assert status code is NOT success (either 400 or 401)
        assert!(response.status().is_client_error(), "Status was {}", response.status());
    }

    // Verify user is locked in store
    let user_after = mock_user_store.get_user(user_id).await.unwrap().unwrap();
    assert_eq!(user_after.failed_login_attempts, 5);
    assert!(user_after.account_locked);

    // 6th Attempt (Correct password but Locked)
    let login_body = serde_json::json!({
        "grant_type": "password",
        "username": "testuser",
        "password": "password123", // Correct password!
        "client_id": "test-client"
    });

    let request = Request::builder()
        .uri("/oauth2/token")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body).unwrap()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    // Should be locked - returns 400 now as per updated best practice
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Manually unlock
    mock_user_store.unlock_account(user_id).await.unwrap();

    // 7th Attempt (Correct password, unlocked)
    let login_body = serde_json::json!({
        "grant_type": "password",
        "username": "testuser",
        "password": "password123",
        "client_id": "test-client"
    });

    let request = Request::builder()
        .uri("/oauth2/token")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body).unwrap()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    // Expect 500 because token storage fails (mock DB), but record_login should have run
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // Verify user is reset
    let user_final = mock_user_store.get_user(user_id).await.unwrap().unwrap();
    assert_eq!(user_final.failed_login_attempts, 0);
    assert!(!user_final.account_locked);
}
