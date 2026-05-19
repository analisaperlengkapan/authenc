// Core entity storage services
/// Audit log storage service
pub mod audit_log_store;
/// Authentication flow storage service
pub mod auth_flow_store;
/// Consent storage service for GDPR compliance
pub mod consent_store;
/// Permission storage service
pub mod permission_store;
/// Realm storage service
pub mod realm_store;
/// Role storage service
pub mod role_store;
/// Social account storage service
pub mod social_account_store;
/// User storage service
pub mod user_store;
/// Redis session store implementation
#[cfg(feature = "redis-store")]
pub mod redis_session_store;

// Moved from services/
/// Group data storage and management
pub mod group_store;
/// OIDC client storage and management
pub mod oidc_client_store;
/// OIDC authorization code storage
pub mod oidc_code_store;
/// Permission ticket storage and management
pub mod permission_ticket_store;
/// Resource server storage and management
pub mod resource_server_store;
/// Resource data storage and management
pub mod resource_store;
/// Scope storage and management
pub mod scope_store;
/// Session storage and management
pub mod session_store;
/// TOTP secret storage and management
pub mod totp_store;
/// PostgreSQL audit log storage
pub mod pg_audit_log_store;
/// PostgreSQL event storage
pub mod pg_event_store;

// Re-export commonly used types from sub-modules
pub use consent_store::{ConsentStore, ConsentStoreTrait};
pub use group_store::GroupStore;
pub use session_store::SessionStore;
pub use totp_store::TotpStore;
