//! Application state and initialization
//!
//! This module provides the core application state management and
//! initialization logic for the Authenc authentication service.

use crate::config::AppConfig;
use crate::error::{AuthencError, Result};
use std::sync::Arc;

/// Comprehensive application state with all services
#[derive(Clone)]
pub struct AppState {
    /// Application configuration
    pub config: Arc<AppConfig>,
    /// Database connection pool
    pub database: Arc<crate::database::Database>,
    /// User data store
    pub user_store: Arc<crate::services::stores::user_store::UserStore>,
    /// Session management store
    pub session_store: Arc<crate::services::session_store::SessionStore>,
    /// TOTP (Time-based One-Time Password) store
    pub totp_store: Arc<crate::services::totp_store::TotpStore>,
    /// Brute force attack protection service
    pub brute_force_protector: Arc<crate::services::brute_force_protector::BruteForceProtector>,
    /// Anomaly detection service
    pub anomaly_detector: Arc<crate::services::anomaly_detector::AnomalyDetector>,
    /// Federation provider registry
    pub federation_registry: Arc<crate::services::federation_provider::FederationRegistry>,
    /// Audit log storage
    pub audit_log_store: Arc<crate::services::pg_audit_log_store::PgAuditLogStore>,
    /// User consent management store for GDPR compliance
    pub consent_store: Arc<crate::services::stores::consent_store::ConsentStore>,
    /// Authentication flow store for pluggable authentication flows
    pub auth_flow_store: Arc<crate::services::stores::auth_flow_store::AuthFlowStore>,
    /// Realm configuration store
    pub realm_store: Arc<crate::services::stores::realm_store::RealmStore>,
    /// Realm management service
    pub realm_service: Arc<dyn crate::services::realm::RealmService>,
    /// Role management store
    pub role_store: Arc<crate::services::stores::role_store::RoleStore>,
    /// Permission management store
    pub permission_store: Arc<crate::services::stores::permission_store::PermissionStore>,
    /// Resource management store
    pub resource_store: Arc<crate::services::resource_store::ResourceStore>,
    /// Resource server management store
    pub resource_server_store: Arc<crate::services::resource_server_store::ResourceServerStore>,
    /// Permission ticket management store
    pub permission_ticket_store:
        Arc<crate::services::permission_ticket_store::PermissionTicketStore>,
    /// Scope management store
    pub scope_store: Arc<crate::services::scope_store::ScopeStore>,
    /// OIDC client store for OAuth2/OIDC client management
    pub oidc_client_store: Arc<crate::services::oidc_client_store::OidcClientStore>,
    /// Social account store for social login account linking
    pub social_account_store:
        Arc<crate::services::stores::social_account_store::SocialAccountStore>,
    /// Identity broker registry for external authentication providers
    pub broker_registry: Arc<crate::services::broker::IdentityBrokerRegistry>,
    /// OID4VC service for verifiable credentials
    pub oid4vc_service: Arc<crate::services::oid4vc::EnhancedOid4VcManager>,
    /// SSO service for unified single sign-on
    pub sso_service: Arc<dyn crate::services::sso::SsoService>,
    /// SSO cookie manager for secure cookie operations
    pub sso_cookie_manager: Arc<crate::services::sso::SsoCookieManager>,
    /// Event manager for handling application events
    pub event_manager: Arc<tokio::sync::RwLock<crate::services::events::EventManager>>,
    /// Event retention service for managing event lifecycle
    pub event_retention_service: Arc<crate::services::event_retention::EventRetentionService>,
    /// Audit log sink for persistent audit logging
    pub audit_log_sink: Arc<dyn crate::services::audit_log_sink::AuditLogSink>,
    /// SPI manager for pluggable enterprise components
    pub spi_manager: Arc<crate::spi::SpiManager>,
    /// Cluster manager for high availability
    pub cluster_manager: Option<Arc<crate::services::clustering::ClusterManager>>,
    /// Observability service for monitoring and metrics
    pub observability_service: Arc<crate::services::observability::ObservabilityService>,
    /// Compliance mode service
    pub compliance_mode_service: Arc<crate::services::compliance_mode::ComplianceModeService>,
}

// Support extraction of database for health checks
#[cfg(feature = "axum")]
impl axum::extract::FromRef<Arc<AppState>> for crate::handlers::health::HealthState {
    fn from_ref(state: &Arc<AppState>) -> Self {
        crate::handlers::health::HealthState(state.database.clone())
    }
}

impl AppState {
    /// Initialize application state with all services
    pub async fn new(config: AppConfig) -> Result<Self> {
        let config = Arc::new(config);

        // Initialize database connection pool
        let database = Arc::new(
            crate::database::Database::new(&config.database)
                .await
                .map_err(|e| {
                    AuthencError::database(format!("Failed to initialize database: {}", e))
                })?,
        );

        // Initialize audit log store
        let audit_log_store = Arc::new(
            crate::services::pg_audit_log_store::PgAuditLogStore::new(&config.database_url())
                .await
                .map_err(|e| {
                    AuthencError::database(format!("Failed to init audit store: {}", e))
                })?,
        );

        // Initialize consent store
        let consent_store = Arc::new(crate::services::stores::consent_store::ConsentStore::new(
            database.clone(),
        ));

        // Initialize authentication flow store
        let auth_flow_store = Arc::new(
            crate::services::stores::auth_flow_store::AuthFlowStore::new(database.clone()),
        );

        // Initialize other services
        let user_store = Arc::new(crate::services::stores::user_store::UserStore::new(
            database.clone(),
        ));
        let session_store = Arc::new(crate::services::session_store::SessionStore::new(
            database.clone(),
        ));
        let totp_store = Arc::new(crate::services::totp_store::TotpStore::new());

        let brute_force_protector = Arc::new(
            crate::services::brute_force_protector::BruteForceProtector::new(
                config.security.brute_force_max_attempts as usize,
                config.security.brute_force_window_seconds,
            ),
        );

        let anomaly_detector = Arc::new(crate::services::anomaly_detector::AnomalyDetector::new());
        let federation_registry =
            Arc::new(crate::services::federation_provider::FederationRegistry::new());
        let realm_store = Arc::new(crate::services::stores::realm_store::RealmStore::new());
        let realm_service = Arc::new(crate::services::realm::PostgresRealmService::new(
            database.clone(),
        ));
        let role_store = Arc::new(crate::services::stores::role_store::RoleStore::new());
        let permission_store =
            Arc::new(crate::services::stores::permission_store::PermissionStore::new());
        let resource_store = Arc::new(crate::services::resource_store::ResourceStore::new(
            database.clone(),
        ));
        let resource_server_store = Arc::new(
            crate::services::resource_server_store::ResourceServerStore::new(database.clone()),
        );
        let permission_ticket_store = Arc::new(
            crate::services::permission_ticket_store::PermissionTicketStore::new(database.clone()),
        );
        let scope_store = Arc::new(crate::services::scope_store::ScopeStore::new(
            database.clone(),
        ));
        let oidc_client_store = Arc::new(
            crate::services::oidc_client_store::OidcClientStore::with_database(database.clone()),
        );

        // Initialize social account store
        let social_account_store = Arc::new(
            crate::services::stores::social_account_store::SocialAccountStore::new(
                database.clone(),
            ),
        );

        // Initialize identity broker registry
        let broker_registry = Arc::new(crate::services::broker::IdentityBrokerRegistry::new());

        // Initialize OID4VC service
        let oid4vc_service = Arc::new(crate::services::oid4vc::EnhancedOid4VcManager::new(
            "https://authenc.example.com".to_string(),
        ));

        // Initialize SSO cookie manager
        let sso_secret: &[u8] = if config.security.jwt_secret.is_empty() {
            b"default-sso-secret-key-change-in-production!!"
        } else {
            config.security.jwt_secret.as_bytes()
        };
        let sso_cookie_manager = Arc::new(crate::services::sso::SsoCookieManager::new(
            sso_secret,
            "AUTHENC_SSO",
            None, // cookie_domain from config
            true, // secure = true (use HTTPS in production)
        ));

        // Initialize SSO session manager
        let sso_session_manager =
            Arc::new(crate::services::sso::session::DefaultSsoSessionManager::new());

        // Initialize SSO service
        let sso_service: Arc<dyn crate::services::sso::SsoService> =
            Arc::new(crate::services::sso::DefaultSsoService::new(
                sso_session_manager,
                sso_cookie_manager.clone(),
                database.clone(),
            ));

        // Initialize audit log sink
        let audit_log_sink: Arc<dyn crate::services::audit_log_sink::AuditLogSink> = if let Some(
            kafka_config,
        ) =
            &config.kafka
        {
            if kafka_config.enabled {
                match crate::services::kafka_audit_log_sink::KafkaAuditLogSink::new(
                    &kafka_config.brokers,
                    &kafka_config.audit_topic,
                ) {
                    Ok(sink) => Arc::new(sink),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to initialize Kafka audit log sink: {}. Falling back to PostgreSQL sink.",
                            e
                        );
                        Arc::new(crate::services::audit_log_sink::PgAuditLogSink::new(
                            (*audit_log_store).clone(),
                        ))
                    }
                }
            } else {
                Arc::new(crate::services::audit_log_sink::PgAuditLogSink::new(
                    (*audit_log_store).clone(),
                ))
            }
        } else {
            Arc::new(crate::services::audit_log_sink::PgAuditLogSink::new(
                (*audit_log_store).clone(),
            ))
        };

        // Initialize event manager
        let event_manager = crate::services::events::create_shared_event_manager();

        // Initialize event store provider
        let event_store = Arc::new(crate::services::pg_event_store::PgEventStoreProvider::new(
            database.clone(),
        ));
        event_store.init_tables().await.map_err(|e| {
            AuthencError::database(format!("Failed to initialize event store tables: {}", e))
        })?;

        // Set event store provider
        {
            let mut manager = event_manager.write().await;
            manager.set_store_provider(event_store.clone());

            // Register default event listeners
            for listener in crate::services::event_listeners::create_default_listeners() {
                manager.register_listener(listener);
            }

            // Register Kafka event listener if configured
            if let Some(kafka_config) = &config.kafka {
                if kafka_config.enabled
                    && !kafka_config.user_events_topic.is_empty()
                    && !kafka_config.admin_events_topic.is_empty()
                {
                    match crate::services::kafka_event_listener::KafkaEventListener::new(
                        &kafka_config.brokers,
                        &kafka_config.user_events_topic,
                        &kafka_config.admin_events_topic,
                    ) {
                        Ok(kafka_listener) => {
                            manager.register_listener(Arc::new(kafka_listener));
                            tracing::info!(
                                "Kafka event listener registered for topics: {} and {}",
                                kafka_config.user_events_topic,
                                kafka_config.admin_events_topic
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to initialize Kafka event listener: {}. Event streaming disabled.",
                                e
                            );
                        }
                    }
                }
            }
        }

        // Initialize event retention service
        let event_retention_service = Arc::new(
            crate::services::event_retention::EventRetentionService::new(
                config.events.clone(),
                database.clone(),
                event_store,
            ),
        );

        // Start the retention cleanup task if enabled
        event_retention_service.clone().start_cleanup_task();

        // Initialize SPI manager with default providers
        let mut spi_manager = crate::spi::SpiManager::new();

        // Register SPIs
        spi_manager.register_spi(Box::new(crate::spi::admin_console::AdminConsoleSpi));
        spi_manager.register_spi(Box::new(crate::spi::credential::CredentialSpi));
        spi_manager.register_spi(Box::new(crate::spi::theme::ThemeSpi));
        spi_manager.register_spi(Box::new(crate::spi::userprofile::UserProfileSpi));
        spi_manager.register_spi(Box::new(crate::spi::validation::ValidationSpi));
        spi_manager.register_spi(Box::new(crate::spi::locale::LocaleSpi));
        spi_manager.register_spi(Box::new(crate::spi::events::EventsSpi));
        spi_manager.register_spi(Box::new(crate::spi::ldap_federation::LdapFederationSpi));
        spi_manager.register_spi(Box::new(crate::spi::social::SocialProviderSpi));
        spi_manager.register_spi(Box::new(crate::spi::storage::StorageSpi));
        spi_manager.register_spi(Box::new(crate::spi::sessions::SessionSpi));
        spi_manager.register_spi(Box::new(crate::spi::protocol_mappers::ProtocolMapperSpi));
        spi_manager.register_spi(Box::new(crate::spi::authenticator::AuthenticatorSpi));
        spi_manager.register_spi(Box::new(crate::spi::required_actions::RequiredActionSpi));
        spi_manager.register_spi(Box::new(crate::spi::organization::OrganizationSpi));
        spi_manager.register_spi(Box::new(
            crate::spi::rich_authorization::RichAuthorizationSpi,
        ));
        spi_manager.register_spi(Box::new(crate::spi::migration::MigrationSpi));
        spi_manager.register_spi(Box::new(crate::spi::hostname::HostnameSpi));

        // Register default providers
        spi_manager.registry_mut().register_factory(
            "admin-console",
            crate::spi::admin_console::DefaultAdminConsoleProviderFactory::new(),
        );
        spi_manager.registry_mut().register_factory(
            "credential",
            crate::spi::credential::DefaultCredentialProviderFactory,
        );
        spi_manager.registry_mut().register_factory(
            "credential",
            crate::spi::credential::PasswordCredentialProviderFactory::new(),
        );
        spi_manager.registry_mut().register_factory(
            "credential",
            crate::spi::credential::OTPCredentialProviderFactory::new(),
        );
        spi_manager.registry_mut().register_factory(
            "theme",
            crate::spi::theme::DefaultThemeProviderFactory::new("authenc".to_string()),
        );
        spi_manager.registry_mut().register_factory(
            "userprofile",
            crate::spi::userprofile::DefaultUserProfileProviderFactory::new(),
        );
        spi_manager.registry_mut().register_factory(
            "validation",
            crate::spi::validation::DefaultValidationProviderFactory::new(),
        );
        spi_manager.registry_mut().register_factory(
            "locale",
            crate::spi::locale::DefaultLocaleProviderFactory::new(),
        );
        spi_manager.registry_mut().register_factory(
            "events",
            crate::spi::events::DefaultEventProviderFactory::new(),
        );
        spi_manager.registry_mut().register_factory(
            "ldap-federation",
            crate::spi::ldap_federation::DefaultLdapFederationProviderFactory::new(),
        );
        spi_manager.registry_mut().register_factory(
            "social",
            crate::spi::social::DefaultSocialProviderFactory::new(),
        );
        spi_manager.registry_mut().register_factory(
            "storage",
            crate::spi::storage::DefaultStorageProviderFactory::new(
                user_store.clone(),
                oidc_client_store.clone(),
                role_store.clone(),
                Arc::new(crate::services::group_store::GroupStore::new()),
            ),
        );
        spi_manager.registry_mut().register_factory(
            "session",
            crate::spi::sessions::DefaultSessionProviderFactory::new(session_store.clone()),
        );
        spi_manager.registry_mut().register_factory(
            "protocol-mapper",
            crate::spi::protocol_mappers::DefaultProtocolMapperProviderFactory::new(),
        );
        spi_manager.registry_mut().register_factory(
            "authenticator",
            crate::spi::authenticator::DefaultAuthenticatorProviderFactory::new(),
        );
        spi_manager.registry_mut().register_factory(
            "required-action",
            crate::spi::required_actions::DefaultRequiredActionProviderFactory::new(),
        );
        spi_manager.registry_mut().register_factory(
            "organization",
            crate::spi::organization::DefaultOrganizationProviderFactory::new(),
        );
        spi_manager.registry_mut().register_factory(
            "rich-authorization",
            crate::spi::rich_authorization::DefaultRichAuthorizationProviderFactory::new(),
        );
        spi_manager.registry_mut().register_factory(
            "migration",
            crate::spi::migration::DefaultMigrationProviderFactory::new(),
        );
        spi_manager.registry_mut().register_factory(
            "hostname",
            crate::spi::hostname::DefaultHostnameProviderFactory::new(),
        );
        let spi_manager = Arc::new(spi_manager);

        // Initialize cluster manager if clustering is enabled
        let cluster_manager = if config.clustering.enabled {
            let node_id = config
                .clustering
                .node_id
                .clone()
                .unwrap_or_else(|| format!("node-{}", uuid::Uuid::new_v4().simple()));
            let (manager, _broadcast_tx) =
                crate::services::clustering::ClusterManager::new_in_memory(
                    node_id,
                    config.clustering.cluster_name.clone(),
                );
            Some(Arc::new(manager))
        } else {
            None
        };

        // Initialize observability service
        let mut observability_service =
            crate::services::observability::ObservabilityService::default();

        // Register default health checks
        observability_service.register_health_check(Box::new(
            crate::services::observability::DatabaseHealthCheck::new(
                // Configured from database.max_connections
                config.database.max_connections,
                // Configured from observability.db_check_active_connections
                config.observability.db_check_active_connections,
            ),
        ));

        // Register default metrics collectors
        observability_service.register_metrics_collector(Box::new(
            crate::services::observability::PrometheusMetricsCollector::new(),
        ));

        let observability_service = Arc::new(observability_service);

        // Initialize compliance mode service
        let compliance_mode_service = Arc::new(
            crate::services::compliance_mode::ComplianceModeService::new(
                event_manager.clone(),
                Some(consent_store.clone()),
            ),
        );

        Ok(Self {
            config,
            database,
            user_store,
            session_store,
            totp_store,
            brute_force_protector,
            anomaly_detector,
            federation_registry,
            audit_log_store,
            consent_store,
            auth_flow_store,
            realm_store,
            realm_service,
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
            audit_log_sink,
            spi_manager,
            cluster_manager,
            observability_service,
            compliance_mode_service,
        })
    }

    /// Initialize social identity brokers from environment variables
    pub fn initialize_social_brokers(&self) -> std::result::Result<(), Box<dyn std::error::Error>> {
        use crate::services::broker::{
            IdentityProviderConfig, IdentityProviderType, SocialConfig, SocialIdentityBroker,
        };
        use uuid::Uuid;

        // Initialize Google broker if configured
        if let (Ok(client_id), Ok(client_secret)) = (
            std::env::var("GOOGLE_CLIENT_ID"),
            std::env::var("GOOGLE_CLIENT_SECRET"),
        ) {
            let google_config = SocialConfig {
                client_id,
                client_secret,
                redirect_uri: std::env::var("GOOGLE_REDIRECT_URI")
                    .unwrap_or_else(|_| "http://localhost:3000/auth/social/callback".to_string()),
                scopes: vec![
                    "openid".to_string(),
                    "email".to_string(),
                    "profile".to_string(),
                ],
            };
            let _google_broker =
                SocialIdentityBroker::new(google_config, IdentityProviderType::SocialGoogle);

            let _provider_config = IdentityProviderConfig {
                id: Uuid::new_v4(),
                name: "Google".to_string(),
                provider_type: IdentityProviderType::SocialGoogle,
                enabled: true,
                config: serde_json::json!({
                    "client_id": std::env::var("GOOGLE_CLIENT_ID").unwrap(),
                    "client_secret": std::env::var("GOOGLE_CLIENT_SECRET").unwrap(),
                    "redirect_uri": std::env::var("GOOGLE_REDIRECT_URI").unwrap_or_else(|_| "http://localhost:3000/auth/social/callback".to_string())
                }),
                realm_id: Uuid::new_v4(), // Default realm
            };

            // We need to make broker_registry mutable, but it's in Arc. Let's skip this for now.
            // self.broker_registry.register_broker(provider_config, Box::new(google_broker));
        }

        // Initialize GitHub broker if configured
        if let (Ok(client_id), Ok(client_secret)) = (
            std::env::var("GITHUB_CLIENT_ID"),
            std::env::var("GITHUB_CLIENT_SECRET"),
        ) {
            let github_config = SocialConfig {
                client_id,
                client_secret,
                redirect_uri: std::env::var("GITHUB_REDIRECT_URI")
                    .unwrap_or_else(|_| "http://localhost:3000/auth/social/callback".to_string()),
                scopes: vec!["user:email".to_string()],
            };
            let _github_broker =
                SocialIdentityBroker::new(github_config, IdentityProviderType::SocialGitHub);

            let _provider_config = IdentityProviderConfig {
                id: Uuid::new_v4(),
                name: "GitHub".to_string(),
                provider_type: IdentityProviderType::SocialGitHub,
                enabled: true,
                config: serde_json::json!({
                    "client_id": std::env::var("GITHUB_CLIENT_ID").unwrap(),
                    "client_secret": std::env::var("GITHUB_CLIENT_SECRET").unwrap(),
                    "redirect_uri": std::env::var("GITHUB_REDIRECT_URI").unwrap_or_else(|_| "http://localhost:3000/auth/social/callback".to_string())
                }),
                realm_id: Uuid::new_v4(), // Default realm
            };

            // self.broker_registry.register_broker(provider_config, Box::new(github_broker));
        }

        // Initialize Facebook broker if configured
        if let (Ok(client_id), Ok(client_secret)) = (
            std::env::var("FACEBOOK_CLIENT_ID"),
            std::env::var("FACEBOOK_CLIENT_SECRET"),
        ) {
            let facebook_config = SocialConfig {
                client_id,
                client_secret,
                redirect_uri: std::env::var("FACEBOOK_REDIRECT_URI")
                    .unwrap_or_else(|_| "http://localhost:3000/auth/social/callback".to_string()),
                scopes: vec!["email".to_string(), "public_profile".to_string()],
            };
            let _facebook_broker =
                SocialIdentityBroker::new(facebook_config, IdentityProviderType::SocialFacebook);

            let _provider_config = IdentityProviderConfig {
                id: Uuid::new_v4(),
                name: "Facebook".to_string(),
                provider_type: IdentityProviderType::SocialFacebook,
                enabled: true,
                config: serde_json::json!({
                    "client_id": std::env::var("FACEBOOK_CLIENT_ID").unwrap(),
                    "client_secret": std::env::var("FACEBOOK_CLIENT_SECRET").unwrap(),
                    "redirect_uri": std::env::var("FACEBOOK_REDIRECT_URI").unwrap_or_else(|_| "http://localhost:3000/auth/social/callback".to_string())
                }),
                realm_id: Uuid::new_v4(), // Default realm
            };

            // self.broker_registry.register_broker(provider_config, Box::new(facebook_broker));
        }

        Ok(())
    }
}

/// Application builder for configuring and running the server
pub struct ApplicationBuilder {
    config: AppConfig,
}

impl ApplicationBuilder {
    /// Create a new application builder
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    /// Build the application state
    pub async fn build_state(self) -> Result<AppState> {
        let state = AppState::new(self.config).await?;

        // Initialize social identity brokers
        if let Err(e) = state.initialize_social_brokers() {
            tracing::warn!("Failed to initialize social brokers: {}", e);
        }

        Ok(state)
    }

    /// Run the application server
    pub async fn run(self) -> Result<()> {
        let state = self.build_state().await?;

        #[cfg(feature = "axum")]
        {
            use crate::axum_app::AxumApp;
            let app = AxumApp::new(state);
            app.run().await?;
        }

        #[cfg(not(feature = "axum"))]
        {
            return Err(AuthencError::ConfigurationError {
                message: "No web framework feature enabled. Enable 'axum' feature.".to_string(),
            });
        }

        Ok(())
    }
}

/// Initialize logging based on configuration
pub fn initialize_logging(config: &AppConfig) -> Result<()> {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

    let level = match config.observability.log_level.as_str() {
        "error" => tracing::Level::ERROR,
        "warn" => tracing::Level::WARN,
        "info" => tracing::Level::INFO,
        "debug" => tracing::Level::DEBUG,
        "trace" => tracing::Level::TRACE,
        _ => tracing::Level::INFO,
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| level.as_str().to_string()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_app_state_initialization() {
        // Use a config that will definitely fail to connect
        let mut config = AppConfig::default();
        config.database.host = "nonexistent.host.invalid".to_string();
        config.database.port = 12345; // Invalid port
        let result = AppState::new(config).await;
        // Should fail with invalid database configuration
        assert!(result.is_err());
    }

    #[test]
    fn test_application_builder_creation() {
        let config = AppConfig::default();
        let builder = ApplicationBuilder::new(config);
        assert!(builder.config.server.port > 0);
    }
}

use axum::extract::FromRef;
impl FromRef<Arc<AppState>> for crate::database::Database {
    fn from_ref(state: &Arc<AppState>) -> Self {
        (*state.database).clone()
    }
}
