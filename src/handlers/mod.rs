// Re-export axum router for convenience
use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

// Database
use crate::app::AppState;

// Handlers
/// Consent UI handlers for user consent management
pub mod consent_ui;
/// Health check handlers for Axum web framework
pub mod health;
/// JWT token handling with Ed25519 signatures for enhanced security
pub mod jwt_ed25519;
/// Comprehensive OAuth2 implementation with PKCE and security features
pub mod oauth2;
/// OIDC identity provider with Ed25519 JWT signing (secure replacement for RSA)
pub mod oidc_ed25519;
pub use health::create_health_routes;

// Migrated handlers (Actix -> Axum)
/// Audit log handlers for querying and exporting audit logs
pub mod audit;
/// Group management handlers
pub mod group;
/// OIDC client management handlers
pub mod oidc_client;
/// Legacy OIDC JWT handlers with RSA (deprecated - use oidc_ed25519)
pub mod oidc_jwt;
/// OIDC cryptographic key management
pub mod oidc_keys;
/// OIDC provider handlers (Legacy RSA-based, for backward compatibility)
pub mod oidc_provider;
/// Session management handlers
pub mod session;
/// TOTP (Time-based One-Time Password) handlers
pub mod totp;
/// TOTP verification handlers
pub mod totp_verify;

// Advanced Services Handlers
/// Administrative API endpoints for system management
pub mod admin;
// Temporarily disabled API module due to Actix-web migration issues
/// REST API handlers for authentication and authorization services
pub mod api; // Uncommented - contains Axum handlers
// Temporarily disabled due to Axum migration issues
// pub mod authorization;
/// Identity broker handlers for external authentication providers
pub mod broker;
/// OAuth 2.0 Dynamic Client Registration (RFC 7591/7592)
pub mod client_registration;
/// Device management handlers
pub mod device;
/// Federated authentication handlers with JIT provisioning
pub mod federated_auth;
/// SPI-based federation handlers for LDAP and social providers
pub mod federation;
/// SPI management handlers for enterprise features
pub mod spi;
// pub mod oauth2; // Commented out - already declared above
// pub mod organization;
/// SAML authentication handlers
pub mod saml;
/// Social login handlers
pub mod social;
// pub mod webauthn;
/// OpenID for Verifiable Credentials (OID4VC) handlers
pub mod oid4vc;
/// Single Sign-On (SSO) handlers and endpoints
pub mod sso;
/// Zero Trust security model handlers and endpoints
pub mod zero_trust;
/// FIPS management handlers
pub mod fips;
/// Password reset handlers
pub mod reset;

/// Create the main application router with all routes
pub fn create_router(state: Arc<AppState>) -> Router {
    // Create OAuth2 stores
    let oauth2_stores = Arc::new(oauth2::OAuth2Stores::new());

    // Create combined OAuth2 state
    let oauth2_state = Arc::new(oauth2::OAuth2AppState {
        app_state: state.clone(),
        oauth2_stores,
    });

    // Create OAuth2 test router without authentication
    let oauth2_test_router = Router::new()
        .route(
            "/oauth2/authorize/test",
            get(oauth2::test_oauth2_authorize),
        )
        .route(
            "/oauth2/token/test",
            post(oauth2::test_oauth2_token),
        )
        .with_state(oauth2_state.clone());

    // Create OAuth2 router with combined state
    let oauth2_router = Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth2::oauth2_discovery),
        )
        .route("/oauth2/token", post(oauth2::oauth2_token))
        .route(
            "/oauth2/introspect",
            post(oauth2::oauth2_introspect),
        )
        .route("/oauth2/revoke", post(oauth2::oauth2_revoke))
        .route("/oauth2/jwks", get(oauth2::oauth2_jwks))
        .route(
            "/oauth2/userinfo",
            get(oauth2::oauth2_userinfo),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(crate::middleware::auth::AuthState {
                jwt_secret: state.config.security.jwt_secret.clone(),
            }),
            crate::middleware::auth::auth_middleware,
        ))
        .with_state(oauth2_state.clone());

    // Create composite router for /api/v1/auth to avoid route overwrites
    let auth_api_router = Router::new()
        // Core auth routes
        .merge(api::auth::create_auth_routes().with_state(state.clone()))
        // Realm, User, Role, Permission routes
        .merge(api::realm::create_realm_routes().with_state(state.clone()))
        .merge(group::create_group_routes().with_state(state.clone()))
        .merge(api::user::create_user_routes().with_state(state.clone()))
        .merge(api::user_role::create_user_role_routes().with_state(state.clone()))
        .merge(api::user_permission::create_user_permission_routes().with_state(state.clone()))
        .merge(api::role::create_role_routes().with_state(state.clone()))
        .merge(api::permission::create_permission_routes().with_state(state.clone()))
        .merge(api::client::create_client_routes().with_state(state.clone()))
        // Auth flow routes
        .merge(api::auth_flow::create_auth_flow_routes().with_state(state.clone()))
        // Audit routes
        .merge(api::audit::create_audit_routes().with_state(state.audit_log_store.clone()))
        // Permission check routes
        .merge(api::permission_check::create_permission_check_routes().with_state(state.clone()))
        // Resource routes
        .merge(api::resource::create_resource_routes().with_state((
            state.resource_store.clone(),
            state.permission_ticket_store.clone(),
            state.scope_store.clone(),
            state.user_store.clone(),
        )))
        .merge(api::resources::create_resources_routes().with_state((
            state.resource_store.clone(),
            state.permission_ticket_store.clone(),
        )))
        // Account routes
        .merge(api::account::create_account_routes().with_state(
            api::account::AccountState {
                user_store: state.user_store.clone(),
                session_store: state.session_store.clone(),
                oidc_client_store: state.oidc_client_store.clone(),
                totp_store: state.totp_store.clone(),
                audit_log_store: state.audit_log_store.clone(),
                social_account_store: state.social_account_store.clone(),
                consent_store: state.consent_store.clone(),
                oauth2_service: state.oauth2_service.clone(),
                webauthn_service: state.webauthn_service.clone(),
            }
        ))
        .merge(api::account::create_consent_routes().with_state(state.clone()))
        .merge(api::account_credentials::create_account_credentials_routes().with_state(
            api::account_credentials::AccountCredentialsState {
                user_store: state.user_store.clone(),
                totp_store: state.totp_store.clone(),
                session_store: state.session_store.clone(),
            },
        ))
        // WebAuthn routes
        .merge(api::webauthn::create_webauthn_routes().with_state(state.clone()))
        // Nested sub-routes
        .nest(
            "/social",
            social::create_social_routes().with_state(state.clone()),
        )
        .nest(
            "/zero-trust",
            zero_trust::create_zero_trust_routes(),
        )
        .nest(
            "/broker",
            broker::create_identity_broker_routes(),
        )
        .nest(
            "/federated",
            federated_auth::create_federated_auth_routes(),
        )
        .nest(
            "/federation",
            federation::create_federation_routes().with_state(state.clone()),
        );

    let router = Router::new()
        .merge(health::create_health_routes().with_state(state.database.clone()))
        // OAuth2 authorization endpoint (accessible without auth)
        .nest(
            "/oauth2",
            Router::new()
                .route("/authorize", get(oauth2::oauth2_authorize))
                .with_state(oauth2_state.clone()),
        )
        // Legacy OIDC Endpoints with Ed25519 security
        .route(
            "/.well-known/openid_configuration",
            get(oidc_ed25519::oidc_discovery_ed25519),
        )
        .route("/oidc/authorize", get(oidc_ed25519::oidc_authorize_ed25519))
        .route("/oidc/token", post(oidc_ed25519::oidc_token_ed25519))
        .route("/oidc/jwks", get(oidc_ed25519::oidc_jwks_ed25519))
        .route("/oidc/userinfo", get(oidc_ed25519::oidc_userinfo_ed25519))
        // Password reset routes
        .route("/auth/forgot-password", post(reset::request_password_reset))
        .route("/auth/reset-password", post(reset::reset_password))
        // Merge OAuth2 test router (without auth)
        .merge(oauth2_test_router)
        // Merge OAuth2 router (with auth for token/userinfo endpoints)
        .merge(oauth2_router)
        // Test consent routes (without auth)
        .merge(consent_ui::create_test_consent_routes().with_state(state.clone()))
        // Consent UI routes (with auth)
        .merge(
            consent_ui::create_consent_routes()
                .layer(axum::middleware::from_fn_with_state(
                    Arc::new(crate::middleware::auth::AuthState {
                        jwt_secret: state.config.security.jwt_secret.clone(),
                    }),
                    crate::middleware::auth::auth_middleware,
                ))
                .with_state(state.clone()),
        )
        // OAuth 2.0 Dynamic Client Registration (RFC 7591/7592)
        .nest(
            "/oauth2",
            client_registration::create_client_registration_routes().with_state(state.clone()),
        )
        // Main Auth API Nest
        .nest("/api/v1/auth", auth_api_router)
        // Authorization API
        .nest("/api/v1", api::create_authorization_routes().with_state(state.clone()))
        // FIPS management routes
        .nest(
            "/api/v1/admin/fips",
            fips::create_fips_routes()
                .layer(axum::middleware::from_fn_with_state(
                    Arc::new(crate::middleware::auth::AuthState {
                        jwt_secret: state.config.security.jwt_secret.clone(),
                    }),
                    crate::middleware::auth::auth_middleware,
                ))
                .with_state(state.clone()),
        )
        // SSO (Single Sign-On) routes
        .merge(sso::create_sso_router().with_state(state.clone()))
        // SPI management routes for enterprise features
        .nest(
            "/api/v1/admin/spi",
            spi::create_spi_routes()
                .layer(axum::middleware::from_fn_with_state(
                    Arc::new(crate::middleware::auth::AuthState {
                        jwt_secret: state.config.security.jwt_secret.clone(),
                    }),
                    crate::middleware::auth::auth_middleware,
                ))
                .with_state(state.clone()),
        )
        .nest(
            "/api/v1/admin",
            admin::create_admin_routes()
                .layer(axum::middleware::from_fn_with_state(
                    Arc::new(crate::middleware::auth::AuthState {
                        jwt_secret: state.config.security.jwt_secret.clone(),
                    }),
                    crate::middleware::auth::auth_middleware,
                ))
                .with_state(state.clone()),
        )
        .nest(
            "/api/v1",
            api::events::create_event_routes().with_state(state.clone()),
        )
        // Session 5: Event Listener System API
        .nest(
            "/api/v1/realms",
            api::event_listeners::create_event_listener_routes().with_state(state.clone()),
        )
        // Session 5: Protocol Mapper API
        .nest(
            "/api/v1/realms",
            api::protocol_mappers::create_protocol_mapper_routes().with_state(state.clone()),
        )
        // Session 5: Custom Authenticator API
        .nest(
            "/api/v1/realms",
            api::authenticators::create_authenticator_routes().with_state(state.clone()),
        )
        // Temporarily disabled organization routes due to Axum migration
        // .nest(
        //     "/api/v1/organizations",
        //     organization::create_organization_routes(),
        // )
        // Device management routes
        .nest("/api/v1/devices", device::create_device_routes().with_state(state.clone()))
        // Temporarily disabled SAML routes due to Axum migration
        // .nest("/saml", saml::create_saml_routes())
        .nest(
            "/oid4vc",
            oid4vc::create_oid4vc_router().with_state(state.clone()),
        )
        .nest("/vp", oid4vc::create_vp_router().with_state(state.clone()));

    router.with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use authenc_core::config::AppConfig;
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;
    use serde_json::Value;

    #[tokio::test]
    async fn test_health_endpoint() {
        use crate::handlers::health::health;

        let response = health().await;

        // Convert response to JSON for testing
        let json_response = response.into_response();
        let body = json_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "healthy");
        assert!(json["version"].is_string());
        assert!(json["timestamp"].is_string());
    }
}
