// Security and protection services
/// Advanced federation protocols and identity bridging
pub mod advanced_federation;
/// Advanced authentication protocols implementation
pub mod advanced_protocols;
/// Anomaly detection and threat intelligence
pub mod anomaly_detector;
/// Authentication flow management and orchestration
pub mod auth_flow;
/// Brute force attack prevention and detection
pub mod brute_force_protector;
/// Client policy enforcement and validation
pub mod client_policy;
/// OAuth 2.0 Dynamic Client Registration (RFC 7591/7592)
pub mod client_registration;
/// Service managers for coordinating complex operations
pub mod managers;
/// Pushed Authorization Requests (PAR) implementation
pub mod par;
/// Password policy enforcement and validation
pub mod password_policy;

// Storage abstraction layer
// pub mod storage;

// Storage services
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

// Core entity stores from services/stores/
/// Core entity storage services
pub mod stores {
    /// Audit log storage service
    pub mod audit_log_store;
    /// Consent storage service for GDPR compliance
    pub mod consent_store;
    /// Permission storage service
    pub mod permission_store;
    /// Realm storage service
    pub mod realm_store;
    /// Role storage service
    pub mod role_store;
    /// User storage service
    pub mod user_store;
}

// Re-export for convenience
pub use stores::*;

// Audit and logging services
/// Audit log sink interface and implementations
pub mod audit_log_sink;
/// Elasticsearch-based audit log streaming for SIEM integration
pub mod elasticsearch_audit_log_sink;
/// Event listener implementations
pub mod event_listeners;
/// Event retention and lifecycle management
pub mod event_retention;
#[cfg(test)]
mod event_retention_tests;
/// Event system and listener management
pub mod events;
/// Kafka-based audit log streaming
pub mod kafka_audit_log_sink;
/// Kafka-based event streaming
pub mod kafka_event_listener;
/// PostgreSQL audit log storage
pub mod pg_audit_log_store;
/// PostgreSQL event storage
pub mod pg_event_store;

// Federation services
/// Identity broker and federation management
pub mod broker;
/// Federation protocol implementations
pub mod federation;
/// Federation provider integrations
pub mod federation_provider;

// Authorization services
/// Authorization policy engine and enforcement
pub mod authorization;

// Zero Trust services
/// Zero Trust security model implementation
pub mod zero_trust;

// Social login services
/// Social identity provider integrations
pub mod social;

// Admin services
/// Administrative operations and management
pub mod admin;

// WebAuthn services
/// WebAuthn/FIDO2 authentication services
pub mod webauthn;

// Organization services
/// Organization management and multi-tenancy
pub mod organization;

/// Realm services
/// Multi-tenant realm management and isolation
pub mod realm;

// SAML services
/// SAML 2.0 protocol implementation
pub mod saml;

// OID4VC services
/// OpenID for Verifiable Credentials
pub mod oid4vc;

// Kubernetes operator services
/// Kubernetes operator for Authenc
pub mod kubernetes;

// Device management services
/// Device trust and management
pub mod device;

// Enterprise-grade services
/// Clustering and high availability
pub mod clustering;
/// Compliance and regulatory services
pub mod compliance;
/// FIPS compliance and cryptographic modules
pub mod fips;
/// Observability and monitoring
pub mod observability;
/// Secret management and vault integration
pub mod vault;

// Re-exports for convenience
pub use anomaly_detector::AnomalyDetector;
pub use auth_flow::AuthenticationManager;
pub use brute_force_protector::BruteForceProtector;
pub use client_registration::{ClientRegistrationService, DefaultClientRegistrationService};
pub use group_store::GroupStore;
pub use session_store::SessionStore;
pub use totp_store::TotpStore;
