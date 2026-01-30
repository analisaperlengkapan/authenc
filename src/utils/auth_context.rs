use crate::services::security::anomaly_detector::AnomalyDetector;
use crate::services::security::brute_force_protector::BruteForceProtector;
use crate::services::federation_provider::FederationRegistry;
use crate::services::stores::session_store::SessionStore;
use crate::services::stores::totp_store::TotpStore;
use crate::services::stores::user_store::UserStore;
use std::sync::Arc;

/// Aggregates all dependencies for the login handler.
///
/// This struct is injected as a single dependency to simplify handler signatures and improve maintainability.
#[derive(Clone)]
pub struct AuthContext {
    /// Store for user data and authentication
    pub user_store: Arc<UserStore>,
    /// Store for TOTP secrets
    pub totp_store: Arc<TotpStore>,
    /// Store for session tokens
    pub session_store: Arc<SessionStore>,
    /// Brute-force protection logic
    pub brute_force: Arc<BruteForceProtector>,
    /// Anomaly detection (e.g., new IPs)
    pub anomaly_detector: Arc<AnomalyDetector>,
    /// Federation registry for external user sources
    pub federation_registry: Arc<FederationRegistry>,
}
