// Health and monitoring handlers
pub mod health;

// Audit handlers
pub mod audit;

// Group management handlers  
pub mod group;

// Session management handlers
pub mod session;

// TOTP authentication handlers
pub mod totp;
pub mod totp_verify;

// OIDC handlers
pub mod oidc_client;
pub mod oidc_jwt;
pub mod oidc_keys;
pub mod oidc_provider;

use actix_web::web;

/// Configure all API routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/health")
            .configure(health::configure_routes)
    )
    .service(
        web::scope("/audit")
            .configure(audit::configure_routes)
    );
}
