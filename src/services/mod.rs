// Security and protection services
pub mod anomaly_detector;
pub mod brute_force_protector;
pub mod password_policy;

// Storage services
pub mod group_store;
pub mod oidc_client_store;
pub mod oidc_code_store;
pub mod session_store;
pub mod totp_store;

// Core entity stores from services/services/
pub mod services {
    pub mod audit_log_store;
    pub mod permission_store;
    pub mod realm_store;
    pub mod role_store;
    pub mod user_store;
}

// Re-export for convenience
pub use services::*;

// Audit and logging services
pub mod audit_log_sink;
pub mod kafka_audit_log_sink;
pub mod pg_audit_log_store;

// Federation services
pub mod federation_provider;
pub mod federation;
pub mod broker;

// Authorization services
pub mod authorization;

// Zero Trust services
pub mod zero_trust;

// Social login services
pub mod social;

// Admin services
pub mod admin;

// WebAuthn services
pub mod webauthn;

// Organization services
pub mod organization;

// SAML services
pub mod saml;

// Device management services
pub mod device;

// Enterprise-grade services
pub mod vault;
pub mod fips;
pub mod observability;
pub mod clustering;
pub mod compliance;

// Re-exports for convenience
pub use anomaly_detector::AnomalyDetector;
pub use brute_force_protector::BruteForceProtector;
pub use group_store::GroupStore;
pub use session_store::SessionStore;
pub use totp_store::TotpStore;
