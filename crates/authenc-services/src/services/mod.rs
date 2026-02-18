// Security and protection services
pub mod security;

// Storage services
pub mod stores;

// Audit and logging services
pub mod audit;

// Event system
pub mod events;

// Protocols
pub mod protocols;

// Remaining services
/// Administrative operations and management
pub mod admin;
/// Advanced federation protocols and identity bridging
pub mod advanced_federation;
/// Advanced authentication protocols implementation
pub mod advanced_protocols;
/// Authentication flow management and orchestration
pub mod auth_flow;
/// Authorization policy engine and enforcement
pub mod authorization;
/// Identity broker and federation management
pub mod broker;
/// OAuth 2.0 Dynamic Client Registration (RFC 7591/7592)
pub mod client_registration;
/// Clustering and high availability
pub mod clustering;
/// Compliance checking and validation services
pub mod compliance;
/// Compliance mode management
pub mod compliance_mode;
/// Delegated administration
pub mod delegated_admin;
/// Device trust and management
pub mod device;
/// Federation protocol implementations
pub mod federation;
/// Federation provider integrations
pub mod federation_provider;
/// FIPS compliance and cryptographic modules
pub mod fips;
/// Kubernetes operator for Authenc
pub mod kubernetes;
/// Service managers for coordinating complex operations
pub mod managers;
/// OAuth2 Service for token persistence
pub mod oauth2;
/// Observability and monitoring
pub mod observability;
/// Organization management and multi-tenancy
pub mod organization;
/// Pushed Authorization Requests (PAR) implementation
pub mod par;
/// Realm services
pub mod realm;
/// Social identity provider integrations
pub mod social;
/// Single Sign-On (SSO) orchestration
pub mod sso;
/// Token management and validation
pub mod token;
/// Secret management and vault integration
pub mod vault;

// Re-exports for convenience
pub use auth_flow::AuthenticationManager;
pub use client_registration::{ClientRegistrationService, DefaultClientRegistrationService};
pub use stores::group_store::GroupStore;
pub use stores::session_store::SessionStore;
pub use stores::totp_store::TotpStore;
pub use security::anomaly_detector::AnomalyDetector;
pub use security::brute_force_protector::BruteForceProtector;
