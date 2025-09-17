// Core data models
/// Audit logging and compliance models
pub mod audit;
/// Device management and trust models
pub mod device;
/// Group membership and hierarchy models
pub mod group;
/// OAuth 2.0 and OpenID Connect models
pub mod oauth2;
/// Organization and tenant models
pub mod organization;
/// Permission and access control models
pub mod permission;
/// Security realm and domain models
pub mod realm;
/// Role-based access control models
pub mod role;
/// SAML authentication models
pub mod saml;
/// User account and profile models
pub mod user;
/// WebAuthn authentication models
pub mod webauthn;

// Authentication models
/// Session management models
pub mod session;
/// Token handling and validation models
pub mod token;

// Legacy audit models (keeping for compatibility)
/// Legacy audit log models for backward compatibility
pub mod audit_log;

// Legacy OIDC models (keeping for compatibility)
/// Legacy OIDC client models for backward compatibility
///
/// This module contains legacy OIDC client model definitions that are maintained
/// for backward compatibility with older versions of the authentication platform.
/// New implementations should use the updated OIDC models in the main modules.
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
