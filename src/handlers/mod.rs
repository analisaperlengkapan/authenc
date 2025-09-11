// Re-export axum router for convenience
use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

// Database
use crate::app::AppState;

// Handlers
pub mod health_axum;
pub mod jwt_ed25519;
pub mod oauth2_comprehensive;
pub mod oidc_ed25519;
pub use health_axum::create_health_routes;

// Legacy Actix handlers (temporarily disabled during migration)
// mod audit;
// mod group;
mod health;
// mod oidc_client;
pub mod oidc_jwt;
pub mod oidc_keys;
// mod oidc_provider;
// mod session;
// mod totp;
// mod totp_verify;

// Advanced Services Handlers
pub mod admin;
// Temporarily disabled API module due to Actix-web migration issues
pub mod api; // Uncommented - contains Axum handlers
// Temporarily disabled due to Axum migration issues
// pub mod authorization;
// pub mod broker;
// pub mod device;
// pub mod oauth2_comprehensive; // Commented out - already declared above
// pub mod organization;
// pub mod saml;
// pub mod social;
// pub mod webauthn;
pub mod oid4vc;
pub mod zero_trust;

/// Create the main application router with all routes
pub fn create_router(state: Arc<AppState>) -> Router {
    // For backward compatibility, extract database from state
    // TODO: Gradually migrate handlers to use AppState directly
    let db_state = state.database.clone();

    // Create OAuth2 stores
    let oauth2_stores = Arc::new(oauth2_comprehensive::OAuth2Stores::new());

    // Create combined OAuth2 state
    let oauth2_state = Arc::new(oauth2_comprehensive::OAuth2AppState {
        database: db_state.clone(),
        oauth2_stores,
    });

    // Create OAuth2 router with combined state
    let oauth2_router = Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth2_comprehensive::oauth2_discovery),
        )
        .route(
            "/oauth2/authorize",
            get(oauth2_comprehensive::oauth2_authorize),
        )
        .route("/oauth2/token", post(oauth2_comprehensive::oauth2_token))
        .route(
            "/oauth2/introspect",
            post(oauth2_comprehensive::oauth2_introspect),
        )
        .route("/oauth2/revoke", post(oauth2_comprehensive::oauth2_revoke))
        .route("/oauth2/jwks", get(oauth2_comprehensive::oauth2_jwks))
        .route(
            "/oauth2/userinfo",
            get(oauth2_comprehensive::oauth2_userinfo),
        )
        .with_state(oauth2_state);

    Router::new()
        .route("/health", get(health_axum::health))
        .route("/ready", get(health_axum::ready))
        .route("/live", get(health_axum::live))
        // Legacy OIDC Endpoints with Ed25519 security
        .route(
            "/.well-known/openid_configuration",
            get(oidc_ed25519::oidc_discovery_ed25519),
        )
        .route("/oidc/authorize", get(oidc_ed25519::oidc_authorize_ed25519))
        .route("/oidc/token", post(oidc_ed25519::oidc_token_ed25519))
        .route("/oidc/jwks", get(oidc_ed25519::oidc_jwks_ed25519))
        .route("/oidc/userinfo", get(oidc_ed25519::oidc_userinfo_ed25519))
        // Merge OAuth2 router
        .merge(oauth2_router)
        // Advanced Services API routes
        // Temporarily disabled social routes due to Axum migration
        // .nest("/api/v1/auth/social", social::create_social_routes())
        // Temporarily disabled authorization routes due to Axum migration
        // .nest(
        //     "/api/v1/auth/authorization",
        //     authorization::create_authorization_routes(),
        // )
        .nest(
            "/api/v1/auth/zero-trust",
            zero_trust::create_zero_trust_routes(),
        )
        // Temporarily disabled broker routes due to Axum migration
        // .nest(
        //     "/api/v1/auth/broker",
        //     broker::create_identity_broker_routes(),
        // )
        .nest("/api/v1/admin", admin::create_admin_routes())
        // API routes for realms, users, roles, permissions
        .nest("/api/v1/auth", api::realm::create_realm_routes().with_state(state.realm_store.clone()))
        .nest("/api/v1/auth", api::user::create_user_routes().with_state(state.user_store.clone()))
        .nest("/api/v1/auth", api::role::create_role_routes().with_state(state.role_store.clone()))
        .nest("/api/v1/auth", api::permission::create_permission_routes().with_state(state.permission_store.clone()))
        .nest("/api/v1/auth", api::audit::create_audit_routes().with_state(state.audit_log_store.clone()))
        .nest("/api/v1/auth", api::auth::create_auth_routes().with_state(state.user_store.clone()))
        .nest("/api/v1/auth", api::permission_check::create_permission_check_routes().with_state((state.user_store.clone(), state.role_store.clone())))
        // Temporarily disabled organization routes due to Axum migration
        // .nest(
        //     "/api/v1/organizations",
        //     organization::create_organization_routes(),
        // )
        // Temporarily disabled device routes due to Axum migration
        // .nest("/api/v1/devices", device::create_device_routes())
        // Temporarily disabled SAML routes due to Axum migration
        // .nest("/saml", saml::create_saml_routes())
        .nest("/oid4vc", oid4vc::create_oid4vc_router())
        .nest("/vp", oid4vc::create_vp_router())
        .with_state(db_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppState;
    use crate::config::AppConfig;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_health_endpoint() {
        use crate::handlers::health_axum::health;

        let response = health().await;

        // Convert response to JSON for testing
        let json_response = response.into_response();
        let body = json_response.into_body().collect().await.unwrap().to_bytes();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["status"], "healthy");
        assert!(json["version"].is_string());
        assert!(json["timestamp"].is_string());
    }
}
