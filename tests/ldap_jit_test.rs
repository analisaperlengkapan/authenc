use authenc::app::AppState;
use authenc::config::AppConfig;
use authenc::models::user::{User, JITUserProvisioningRequest, JITUserProvisioningResponse, FederatedIdentity};
use authenc::models::user::UserProfile;
use authenc::spi::ldap_federation::LdapFederationProvider;
use authenc::spi::Provider;
use authenc::handlers::federation::{process_ldap_authentication, LdapAuthRequest};
use authenc::services::federation::jit_provisioning::JITProvisioningService;
use authenc::services::oauth2::ClientValidator;
use authenc::models::oauth2::OAuth2Client;
use authenc::error::Result;
use std::any::Any;
use std::sync::Arc;
use uuid::Uuid;
use axum::extract::State;
use axum::Json;
use async_trait::async_trait;

// Mock dependencies
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
    async fn validate_client(&self, _client_id: &str, _client_secret: Option<&str>) -> Result<Option<OAuth2Client>> {
        Ok(Some(OAuth2Client {
            id: Uuid::new_v4(),
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
            realm_id: None,
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            deleted_at: None,
        }))
    }
}

// Mock LDAP Provider
struct MockLdapFederationProvider {
    should_fail: bool,
    user_to_return: Option<User>,
}

#[async_trait]
impl Provider for MockLdapFederationProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[async_trait]
impl LdapFederationProvider for MockLdapFederationProvider {
    async fn authenticate(&self, _username: &str, _password: &str) -> Result<Option<User>> {
        if self.should_fail {
             Ok(None)
        } else {
             Ok(self.user_to_return.clone())
        }
    }

    async fn import_user(&self, _username: &str) -> Result<Option<User>> {
        Ok(None)
    }

    async fn sync_user_attributes(&self, user_id: &str) -> Result<UserProfile> {
        Ok(UserProfile {
            user_id: Uuid::try_parse(user_id).unwrap_or_default(),
            avatar_url: None,
            bio: None,
            website: None,
            location: None,
            timezone: None,
            locale: None,
            theme: None,
            preferences: None,
            updated_at: chrono::Utc::now(),
        })
    }

    async fn search_users(&self, _query: &str, _limit: usize) -> Result<Vec<User>> {
        Ok(vec![])
    }

    async fn user_exists(&self, _username: &str) -> Result<bool> {
        Ok(true)
    }

    async fn is_connected(&self) -> bool {
        true
    }
}

// Mock JIT Service
struct MockJITProvisioningService {
    should_fail: bool,
}

#[async_trait]
impl JITProvisioningService for MockJITProvisioningService {
    async fn provision_user(
        &self,
        request: JITUserProvisioningRequest,
    ) -> Result<JITUserProvisioningResponse> {
        if self.should_fail {
            return Err(authenc::error::AuthencError::AuthenticationFailed);
        }

        // Return a dummy user and success response
        let mut user = User::new(
            request.external_username.unwrap_or("jituser".to_string()),
            request.external_email.unwrap_or("jit@example.com".to_string()),
            None,
            Some(request.realm_id)
        );
        user.first_name = request.first_name;
        user.last_name = request.last_name;
        user.id = Uuid::new_v4();

        let federated_identity = FederatedIdentity {
            id: Uuid::new_v4(),
            user_id: user.id,
            identity_provider_id: request.identity_provider_id,
            external_id: request.external_id,
            external_username: None,
            external_email: None,
            external_attributes: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_login_at: Some(chrono::Utc::now()),
        };

        Ok(JITUserProvisioningResponse {
            user,
            created: true,
            federated_identity,
        })
    }

    async fn link_user(
        &self,
        _user_id: Uuid,
        _identity_provider_id: Uuid,
        _external_id: String,
        _external_attributes: Option<serde_json::Value>,
    ) -> Result<FederatedIdentity> {
        Err(authenc::error::AuthencError::AuthenticationFailed)
    }

    async fn unlink_user(&self, _user_id: Uuid, _identity_provider_id: Uuid) -> Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn test_ldap_jit_provisioning_success() {
    // 1. Setup AppState (simplified)
    let config = AppConfig::default();
    let database = Arc::new(authenc::database::Database::mock().await);

    // Mocks
    let mock_user_store = Arc::new(MockUserStore::new());
    let mock_user_store_dyn: Arc<dyn authenc::services::stores::user_store::UserStoreTrait> = mock_user_store.clone();
    let mock_consent_store = Arc::new(MockConsentStore::new());
    let mock_session_store = Arc::new(MockSessionStore::new());
    let mock_realm_service = Arc::new(MockRealmService::new());

    // Mock JIT Service
    let mock_jit_service = Arc::new(MockJITProvisioningService { should_fail: false });

    // Initialize required services (same as before but simplified where possible)
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
    let authorization_manager = Arc::new(authenc::services::authorization::AuthorizationManager::new(database.clone()));
    let pg_social_store = authenc::services::social::pg_store::PgSocialStateStore::new(database.clone());
    let social_login_manager = Arc::new(authenc::services::social::SocialLoginManager::with_store(Arc::new(pg_social_store)));
    let auth_flow_store = Arc::new(authenc::services::stores::auth_flow_store::AuthFlowStore::new(database.clone()));
    let totp_store = Arc::new(authenc::services::stores::totp_store::TotpStore::new());
    let brute_force_protector = Arc::new(authenc::services::security::brute_force_protector::BruteForceProtector::new(10, 60));
    let anomaly_detector = Arc::new(authenc::services::security::anomaly_detector::AnomalyDetector::new());
    let federation_registry = Arc::new(authenc::services::federation_provider::FederationRegistry::new());
    let audit_log_store = Arc::new(authenc::services::stores::pg_audit_log_store::PgAuditLogStore::with_pool(database.get_pool()));

    let state = AppState {
        config: Arc::new(config),
        database: database.clone(),
        user_store: mock_user_store_dyn.clone(),
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
        jit_provisioning_service: mock_jit_service,
        client_validator: Arc::new(MockClientValidator),
        password_reset_service: Arc::new(authenc::services::password_reset::PasswordResetService::new(
            mock_user_store_dyn.clone(),
        )),
        password_reset_protector: Arc::new(authenc::services::security::brute_force_protector::BruteForceProtector::new(5, 300)),
        email_verification_service: Arc::new(authenc::services::email_verification::EmailVerificationService::new(
            mock_user_store_dyn.clone(),
        )),
    };

    // 2. Setup Mock Provider return value
    let realm_id = Uuid::new_v4();
    let mut user = User::new(
        "ldapuser".to_string(),
        "ldap@example.com".to_string(),
        None,
        Some(realm_id)
    );
    user.first_name = Some("Ldap".to_string());
    user.last_name = Some("User".to_string());

    let mock_provider = MockLdapFederationProvider {
        should_fail: false,
        user_to_return: Some(user),
    };

    // 3. Call process_ldap_authentication
    let request = LdapAuthRequest {
        username: "ldapuser".to_string(),
        password: "password".to_string(),
    };

    let result = process_ldap_authentication(&mock_provider, &state, &request).await;

    // 4. Verify
    assert!(result.is_ok());
    let json = result.unwrap();
    let response = json.0;

    let val = serde_json::to_value(&response).unwrap();

    assert_eq!(val["success"], true);
    assert!(val["user_info"].is_object());
    assert!(val["token"].is_string()); // Ensure token is present
}
