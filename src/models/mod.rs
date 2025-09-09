// Core data models
pub mod audit;
pub mod device;
pub mod group;
pub mod oauth2;
pub mod organization;
pub mod permission;
pub mod realm;
pub mod role;
pub mod saml;
pub mod user;
pub mod webauthn;

// Authentication models
pub mod session;
pub mod token;

// Legacy audit models (keeping for compatibility)
pub mod audit_log;

// Legacy OIDC models (keeping for compatibility)
pub mod oidc_client;

// Re-exports for convenience
pub use audit::*;
pub use device::*;
pub use oauth2::*;
pub use organization::*;
pub use permission::Permission;
pub use realm::Realm;
pub use role::Role;
pub use saml::*;
pub use user::User;
pub use webauthn::*;

// Legacy re-exports
pub use audit_log::AuditLog;
pub use oidc_client::OidcClient;
