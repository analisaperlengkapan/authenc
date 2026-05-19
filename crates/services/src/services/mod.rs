pub mod security;

/// Data access layer for persistence
pub mod stores;

/// Audit logging service and sinks
pub mod audit;

/// Event management and retention
pub mod events;

/// Authentication protocols (SAML, WebAuthn, OID4VC)
pub mod protocols;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::services::stores::realm_store::RealmStore;
use crate::services::stores::role_store::RoleStore;
use crate::services::stores::user_store::UserStore;
use authenc_models::models::realm::Realm;
use authenc_models::models::role::Role;
use authenc_models::models::user::User;

// Re-export services
pub mod admin;
pub mod auth_flow;
pub mod authorization;
pub mod advanced_federation;
pub mod device;
pub mod password_reset;
pub mod email_verification;
// pub mod saml; // Located in protocols::saml
pub mod social;
pub mod sso;
pub mod token;
// pub mod zero_trust; // Located in security::zero_trust
pub mod oauth2;
pub mod broker;
pub mod realm;
pub mod client_registration;
pub mod fips;
pub mod vault;
pub mod federation_provider;
pub mod clustering;
pub mod observability;
pub mod compliance_mode;
pub mod compliance;
pub mod federation;
pub mod organization;

pub use admin::AdminManager;
pub use auth_flow::AuthenticationManager as AuthFlowManager;
pub use authorization::AuthorizationManager;
pub use device::DeviceService as DeviceManager;
pub use password_reset::PasswordResetService;
pub use protocols::saml::SamlService;
pub use social::SocialLoginManager;
pub use sso::SsoSessionManager;
pub use security::zero_trust::ZeroTrustManager;
