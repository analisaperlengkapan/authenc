use authenc::app::AppState;
use authenc::config::AppConfig;
use authenc::models::user::{CreateUserRequest, User};
use authenc::models::realm::{CreateRealmRequest, RealmResponse};
use authenc::services::realm::RealmService;
use authenc::services::stores::user_store::UserStoreTrait;
use authenc::services::stores::session_store::SessionStoreTrait;
use authenc::services::stores::consent_store::ConsentStoreTrait;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt; // for `oneshot`

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

#[tokio::test]
async fn test_auth_flow_end_to_end() {
    // 1. Setup Mocks
    let mock_user_store: Arc<dyn UserStoreTrait> = Arc::new(MockUserStore::new());
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
    let federation_registry = Arc::new(authenc::services::federation_provider::FederationRegistry::new());

    // Use with_pool to avoid connecting to real DB
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
    let sso_service = Arc::new(authenc::services::sso::DefaultSsoService::new(sso_session_manager, sso_cookie_manager.clone(), database.clone()));

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
    let social_login_manager = Arc::new(authenc::services::social::SocialLoginManager::new());
    let authorization_manager = Arc::new(authenc::services::authorization::AuthorizationManager::new(database.clone()));
    let admin_service = Arc::new(authenc::services::admin::AdminManager::new(database.clone()));
    let jit_provisioning_service: Arc<dyn authenc::services::federation::jit_provisioning::JITProvisioningService> = Arc::new(
        authenc::services::federation::jit_provisioning::DefaultJITProvisioningService::new(
            database.clone(),
            admin_service,
        ),
    );
    let client_validator: Arc<dyn authenc::services::oauth2::ClientValidator> = Arc::new(
        authenc::services::oauth2::DbClientValidator::new(database.clone()),
    );
    let sso_session_mgr: Arc<dyn authenc::services::sso::SsoSessionManager> = Arc::new(
        authenc::services::sso::session::DefaultSsoSessionManager::new(),
    );

    let state = AppState {
        config: Arc::new(config),
        database,
        user_store: mock_user_store.clone(),
        session_store: mock_session_store.clone(),
        totp_store,
        brute_force_protector,
        anomaly_detector,
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
        sso_session_manager: sso_session_mgr,
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
        jit_provisioning_service,
        client_validator,
    };

    // Create Realm (using mock service)
    let realm_req = CreateRealmRequest {
        name: "test-realm".to_string(),
        display_name: Some("Test Realm".to_string()),
        description: None,
        enabled: Some(true),
        attributes: None,
    };
    let _realm: RealmResponse = mock_realm_service.create_realm(realm_req).await.expect("Failed to create realm");

    // Create Router
    let router = authenc::handlers::create_router(Arc::new(state.clone()));

    // Test 1: Create User
    let create_user_req = CreateUserRequest {
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password: Some("password123".to_string()),
        first_name: Some("Test".to_string()),
        last_name: Some("User".to_string()),
        phone_number: None,
        realm_id: Some(uuid::Uuid::new_v4()),
        organization_id: None,
        attributes: None,
    };

    // Get realm ID
    let realm_opt: Option<RealmResponse> = mock_realm_service.get_realm_by_name("test-realm").await.unwrap();
    let realm_id = realm_opt.unwrap().id;
    let mut req = create_user_req;
    req.realm_id = Some(realm_id);

    let _user: User = mock_user_store.add_user(req).await.expect("Failed to add user to mock store");

    // Test 2: Health Check
    let request = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Test 3: Login
    let login_body = serde_json::json!({
        "username": "testuser",
        "password": "password123",
        "realm": "test-realm"
    });

    let request = Request::builder()
        .uri("/api/v1/auth/login")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body).unwrap()))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
