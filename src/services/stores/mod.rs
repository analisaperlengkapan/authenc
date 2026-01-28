// Business logic and service layer
pub mod user_store;
pub mod realm_store;
pub mod role_store;
pub mod permission_store;
pub mod audit_log_store;
pub mod consent_store;
pub mod auth_flow_store;
pub mod social_account_store;
pub mod redis_session_store;

// Re-export commonly used types
pub use consent_store::{ConsentStore, ConsentStoreTrait};
