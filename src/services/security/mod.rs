/// Anomaly detection and threat intelligence
pub mod anomaly_detector;
/// Brute force attack prevention and detection
pub mod brute_force_protector;
/// Client policy enforcement and validation
pub mod client_policy;
/// Forever unknown secrets service (never persisted, auto-rotating)
pub mod forever_unknown_secrets;
/// Password policy enforcement and validation
pub mod password_policy;
/// Comprehensive security testing framework
pub mod security_testing;
/// Zero Trust security model implementation
pub mod zero_trust;

// Re-exports
pub use anomaly_detector::AnomalyDetector;
pub use brute_force_protector::BruteForceProtector;
