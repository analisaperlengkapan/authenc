use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

/// Zero Trust security levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum TrustLevel {
    /// No trust established
    None = 0,
    /// Low level of trust
    Low = 1,
    /// Medium level of trust
    Medium = 2,
    /// High level of trust
    High = 3,
    /// Maximum level of trust
    Maximum = 4,
}

/// Device trust information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTrust {
    /// Unique identifier for the device
    pub device_id: String,
    /// Cryptographic fingerprint of the device
    pub device_fingerprint: String,
    /// Current trust level of the device
    pub trust_level: TrustLevel,
    /// Timestamp when the device was last seen
    pub last_seen: DateTime<Utc>,
    /// Timestamp when the device was first seen
    pub first_seen: DateTime<Utc>,
    /// Detailed information about the device
    pub device_info: DeviceInfo,
    /// Compliance status of the device
    pub compliance_status: ComplianceStatus,
}

/// Device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// User agent string from the device
    pub user_agent: String,
    /// IP address of the device
    pub ip_address: String,
    /// Geographic location of the device
    pub location: Option<Location>,
    /// Operating system of the device
    pub os: String,
    /// Browser used on the device
    pub browser: String,
    /// Screen resolution of the device
    pub screen_resolution: Option<String>,
    /// Timezone of the device
    pub timezone: Option<String>,
    /// Client-provided device fingerprint for stable identity across IP changes
    #[serde(default)]
    pub fingerprint: Option<String>,
}

/// Location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    /// Country where the device is located
    pub country: String,
    /// Region/state where the device is located
    pub region: String,
    /// City where the device is located
    pub city: String,
    /// Latitude coordinate
    pub latitude: f64,
    /// Longitude coordinate
    pub longitude: f64,
}

/// Device compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceStatus {
    /// Device is compliant with security policies
    Compliant,
    /// Device is not compliant with security policies
    NonCompliant,
    /// Compliance status is unknown
    Unknown,
    /// Compliance is currently being checked
    Checking,
}

/// Risk assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Risk score from 0.0 to 1.0, higher values indicate higher risk
    pub score: f64,
    /// Risk level based on the score
    pub level: RiskLevel,
    /// Factors contributing to the risk assessment
    pub factors: Vec<RiskFactor>,
    /// Recommendations to mitigate the risk
    pub recommendations: Vec<String>,
    /// Timestamp when the assessment was performed
    pub assessed_at: DateTime<Utc>,
}

/// Risk levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Low risk level
    Low,
    /// Medium risk level
    Medium,
    /// High risk level
    High,
    /// Critical risk level
    Critical,
}

/// Risk factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Type of risk factor
    pub factor_type: String,
    /// Description of the risk factor
    pub description: String,
    /// Weight of the risk factor in the assessment
    pub weight: f64,
    /// Severity level of the risk factor
    pub severity: RiskLevel,
}

/// Authentication context for continuous verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    /// Session identifier
    pub session_id: String,
    /// User identifier
    pub user_id: Uuid,
    /// Device trust information
    pub device_trust: DeviceTrust,
    /// Risk assessment for the session
    pub risk_assessment: RiskAssessment,
    /// Timestamp of last activity
    pub last_activity: DateTime<Utc>,
    /// Adaptive security controls
    pub adaptive_controls: AdaptiveControls,
}

/// Adaptive security controls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveControls {
    /// Whether MFA is required
    pub require_mfa: bool,
    /// Whether device verification is required
    pub require_device_verification: bool,
    /// Session timeout in seconds
    pub session_timeout: u64,
    /// Maximum number of concurrent sessions allowed
    pub max_concurrent_sessions: u32,
    /// List of allowed geographic locations
    pub allowed_locations: Vec<String>,
    /// List of blocked actions
    pub blocked_actions: Vec<String>,
}

/// Zero Trust Policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroTrustPolicy {
    /// Unique identifier for the policy
    pub id: Uuid,
    /// Name of the policy
    pub name: String,
    /// Description of the policy
    pub description: String,
    /// Conditions that must be met for the policy to apply
    pub conditions: Vec<PolicyCondition>,
    /// Actions to take when the policy conditions are met
    pub actions: Vec<PolicyAction>,
    /// Whether the policy is enabled
    pub enabled: bool,
    /// ID of the realm the policy belongs to
    pub realm_id: Uuid,
}

/// Policy condition for zero trust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    /// Type of condition to evaluate
    pub condition_type: String,
    /// Parameters for the condition evaluation
    pub parameters: HashMap<String, String>,
}

/// Policy action for zero trust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAction {
    /// Type of action to perform
    pub action_type: String,
    /// Parameters for the action execution
    pub parameters: HashMap<String, String>,
}

/// Continuous Authentication Service
#[async_trait]
pub trait ContinuousAuthService: Send + Sync {
    /// Evaluate device trust
    async fn evaluate_device_trust(&self, device_info: &DeviceInfo) -> Result<DeviceTrust, String>;

    /// Perform risk assessment
    async fn assess_risk(&self, context: &AuthContext) -> Result<RiskAssessment, String>;

    /// Update adaptive controls based on risk
    async fn update_adaptive_controls(&self, context: &mut AuthContext) -> Result<(), String>;

    /// Verify session integrity by looking up the device trust entry.
    ///
    /// `device_id` is the server-generated fingerprint (returned as `device_id`
    /// by `evaluate_device_trust`), **not** the application-level session ID.
    async fn verify_session(&self, device_id: &str) -> Result<bool, String>;

    /// Handle suspicious activity
    async fn handle_suspicious_activity(&self, activity: &SuspiciousActivity)
    -> Result<(), String>;
}

/// Suspicious activity report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousActivity {
    /// Type of suspicious activity detected
    pub activity_type: String,
    /// ID of the user associated with the activity
    pub user_id: Uuid,
    /// Session ID where the activity occurred
    pub session_id: String,
    /// Device ID where the activity occurred
    pub device_id: String,
    /// Additional details about the activity
    pub details: HashMap<String, String>,
    /// Timestamp when the activity was detected
    pub timestamp: DateTime<Utc>,
    /// Risk score associated with the activity
    pub risk_score: f64,
}

/// Maximum number of entries in the device trust store before eviction kicks in.
/// This prevents unbounded memory growth from unique fingerprints.
const MAX_DEVICE_TRUST_ENTRIES: usize = 10_000;

/// Zero Trust Manager - main service
///
/// # Note on `std::sync::RwLock`
/// `device_trust_store` uses `std::sync::RwLock` (not `tokio::sync::RwLock`).
/// This is safe **only** because no `RwLockReadGuard` or `RwLockWriteGuard` is
/// held across an `.await` point.  If a future change introduces an `.await`
/// while a guard is alive, it will either fail to compile (due to `Send` bounds
/// from `#[async_trait]`) or block the tokio runtime thread under contention.
/// If that becomes necessary, migrate to `tokio::sync::RwLock`.
pub struct ZeroTrustManager {
    // Internal storage for device trust information (wrapped in RwLock for interior mutability behind Arc)
    device_trust_store: RwLock<HashMap<String, DeviceTrust>>,
    // Risk assessment policies
    risk_policies: Vec<ZeroTrustPolicy>,
    // Adaptive control policies
    adaptive_policies: Vec<ZeroTrustPolicy>,
    // Anomaly detector for detecting unusual patterns
    anomaly_detector: Option<Box<dyn crate::services::security::anomaly_detector::AnomalyDetectorTrait>>,
}

impl Default for ZeroTrustManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ZeroTrustManager {
    /// Create a new zero trust manager with default configuration
    ///
    /// This constructor initializes a zero trust manager that enforces
    /// continuous verification and least privilege access principles.
    /// The manager starts with empty device trust store, risk policies,
    /// and adaptive policies, allowing for dynamic configuration.
    ///
    /// # Returns
    /// A new `ZeroTrustManager` instance with default empty state
    ///
    /// # Security Considerations
    /// - Device trust store starts empty - configure trusted devices explicitly
    /// - Risk policies should be configured based on organizational requirements
    /// - Adaptive policies enable dynamic security responses to threats
    /// - Anomaly detector can be optionally configured for enhanced detection
    ///
    /// # Zero Trust Principles
    /// - Never trust, always verify - continuous authentication required
    /// - Least privilege access - minimal permissions granted by default
    /// - Assume breach - network segmentation and monitoring always active
    /// - Micro-segmentation - granular access controls enforced
    ///
    /// # Example
    /// ```rust,no_run
    /// use authenc::services::zero_trust::ZeroTrustManager;
    ///
    /// let mut manager = ZeroTrustManager::new();
    /// // Configure policies and detectors as needed
    /// // manager.set_anomaly_detector(detector);
    /// // manager.add_risk_policy(policy);
    /// ```
    pub fn new() -> Self {
        Self {
            device_trust_store: RwLock::new(HashMap::new()),
            risk_policies: Vec::new(),
            adaptive_policies: Vec::new(),
            anomaly_detector: None,
        }
    }

    /// Set anomaly detector for enhanced risk assessment
    pub fn set_anomaly_detector(
        &mut self,
        detector: Box<dyn crate::services::security::anomaly_detector::AnomalyDetectorTrait>,
    ) {
        self.anomaly_detector = Some(detector);
    }

    /// Add risk policy
    pub fn add_risk_policy(&mut self, policy: ZeroTrustPolicy) {
        self.risk_policies.push(policy);
    }

    /// Add adaptive policy
    pub fn add_adaptive_policy(&mut self, policy: ZeroTrustPolicy) {
        self.adaptive_policies.push(policy);
    }

    /// Calculate risk score based on multiple factors
    pub async fn calculate_risk_score(&self, context: &AuthContext) -> f64 {
        let mut total_score = 0.0;
        let mut factors = Vec::new();

        // Device trust factor
        let device_score = match context.device_trust.trust_level {
            TrustLevel::Maximum => 0.0,
            TrustLevel::High => 0.1,
            TrustLevel::Medium => 0.3,
            TrustLevel::Low => 0.6,
            TrustLevel::None => 1.0,
        };
        total_score += device_score * 0.4; // 40% weight
        factors.push(RiskFactor {
            factor_type: "device_trust".to_string(),
            description: format!("Device trust level: {:?}", context.device_trust.trust_level),
            weight: 0.4,
            severity: if device_score > 0.5 {
                RiskLevel::High
            } else {
                RiskLevel::Low
            },
        });

        // Location anomaly factor
        let location_score = self.calculate_location_risk(context).await;
        total_score += location_score * 0.2; // 20% weight
        factors.push(RiskFactor {
            factor_type: "location".to_string(),
            description: "Location-based risk assessment".to_string(),
            weight: 0.2,
            severity: if location_score > 0.5 {
                RiskLevel::Medium
            } else {
                RiskLevel::Low
            },
        });

        // Time-based factor
        let time_score = self.calculate_time_risk(context);
        total_score += time_score * 0.15; // 15% weight
        factors.push(RiskFactor {
            factor_type: "time".to_string(),
            description: "Time-based access patterns".to_string(),
            weight: 0.15,
            severity: if time_score > 0.5 {
                RiskLevel::Medium
            } else {
                RiskLevel::Low
            },
        });

        // Behavioral factor (using anomaly detector if available)
        if let Some(detector) = &self.anomaly_detector {
            let behavioral_score = self
                .calculate_behavioral_risk(context, detector.as_ref())
                .await;
            total_score += behavioral_score * 0.25; // 25% weight
            factors.push(RiskFactor {
                factor_type: "behavioral".to_string(),
                description: "Behavioral anomaly detection".to_string(),
                weight: 0.25,
                severity: if behavioral_score > 0.5 {
                    RiskLevel::High
                } else {
                    RiskLevel::Low
                },
            });
        }

        // Clamp score between 0 and 1
        total_score.clamp(0.0, 1.0)
    }

    /// Calculate location-based risk
    async fn calculate_location_risk(&self, context: &AuthContext) -> f64 {
        let mut risk_score = 0.0;

        // Get device location if available
        if let Some(location) = &context.device_trust.device_info.location {
            // List of high-risk countries (simplified example)
            let high_risk_countries = ["XX", "YY", "ZZ"]; // Placeholder country codes

            // Check if location is from high-risk country
            if high_risk_countries.contains(&location.country.as_str()) {
                risk_score += 0.5;
            }

            // Check for unusual access patterns (e.g., impossible travel)
            // If user was in different country recently, flag as suspicious
            // For now, we'll check based on location being too far from expected patterns

            // Check if accessing from unusual region for this user
            // This would normally check against user's historical locations
            // For now, return medium risk if location is available but unknown
            if location.country != "US" && location.country != "CA" && location.country != "GB" {
                // Non-common location, slight risk increase
                risk_score += 0.2;
            }

            // Check for VPN/Proxy indicators (private IP ranges)
            let ip = &context.device_trust.device_info.ip_address;
            if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("172.") {
                // Private IP - could indicate VPN or corporate network
                // Low risk if corporate, but we can't determine that here
                risk_score += 0.1;
            }
        } else {
            // No location data available - medium risk
            risk_score = 0.3;
        }

        // Explicit type annotation for clamp
        let final_score: f64 = risk_score;
        final_score.clamp(0.0, 1.0)
    }

    /// Calculate time-based risk
    fn calculate_time_risk(&self, context: &AuthContext) -> f64 {
        let now = Utc::now();
        let time_since_last_activity = now.signed_duration_since(context.last_activity);

        // High risk if no activity for more than 30 minutes
        if time_since_last_activity.num_minutes() > 30 {
            0.8
        } else if time_since_last_activity.num_minutes() > 10 {
            0.4
        } else {
            0.1
        }
    }

    /// Calculate behavioral risk using anomaly detector
    async fn calculate_behavioral_risk(
        &self,
        context: &AuthContext,
        detector: &dyn crate::services::security::anomaly_detector::AnomalyDetectorTrait,
    ) -> f64 {
        // Check if IP is new for this user
        let user_id_str = context.user_id.to_string();
        let ip_address = &context.device_trust.device_info.ip_address;
        let is_new_ip = detector
            .is_new_ip(&user_id_str, ip_address)
            .unwrap_or(false);

        // Calculate risk based on anomaly detection
        let mut risk_score: f64 = 0.0;

        // New IP from unknown location increases risk
        if is_new_ip {
            risk_score += 0.4;
        }

        // Check for unusual login times (late night/early morning)
        use chrono::Timelike;
        let hour = Utc::now().hour();
        if !(6..=22).contains(&hour) {
            risk_score += 0.2;
        }

        // Additional risk factors can be added here based on device trust level
        match context.device_trust.trust_level {
            TrustLevel::None | TrustLevel::Low => risk_score += 0.3,
            _ => {}
        }

        risk_score.clamp(0.0, 1.0)
    }

    /// Determine risk level from score
    pub fn determine_risk_level(score: f64) -> RiskLevel {
        if score >= 0.8 {
            RiskLevel::Critical
        } else if score >= 0.6 {
            RiskLevel::High
        } else if score >= 0.4 {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }

    /// Generate adaptive controls based on risk
    pub fn generate_adaptive_controls(&self, risk_score: f64) -> AdaptiveControls {
        let mut controls = AdaptiveControls {
            require_mfa: false,
            require_device_verification: false,
            session_timeout: 3600, // 1 hour default
            max_concurrent_sessions: 5,
            allowed_locations: vec![],
            blocked_actions: vec![],
        };

        if risk_score >= 0.8 {
            // Critical risk - maximum controls
            controls.require_mfa = true;
            controls.require_device_verification = true;
            controls.session_timeout = 900; // 15 minutes
            controls.max_concurrent_sessions = 1;
            controls.blocked_actions = vec!["admin".to_string(), "delete".to_string()];
        } else if risk_score >= 0.6 {
            // High risk
            controls.require_mfa = true;
            controls.session_timeout = 1800; // 30 minutes
            controls.max_concurrent_sessions = 2;
        } else if risk_score >= 0.4 {
            // Medium risk
            controls.require_mfa = true;
            controls.session_timeout = 2700; // 45 minutes
        }

        controls
    }

    /// Check if device is trusted
    pub fn is_device_trusted(&self, device_id: &str) -> bool {
        let store = match self.device_trust_store.read() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[SECURITY] Device trust store lock poisoned during read: {}", e);
                return false;
            }
        };
        if let Some(device_trust) = store.get(device_id) {
            matches!(
                device_trust.trust_level,
                TrustLevel::High | TrustLevel::Maximum
            )
        } else {
            false
        }
    }

    /// Register device trust, evicting the oldest entry if the store exceeds its capacity.
    pub fn register_device_trust(&self, device_trust: DeviceTrust) {
        let mut store = match self.device_trust_store.write() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[SECURITY] Device trust store lock poisoned during write: {}", e);
                return;
            }
        };

        // Evict the oldest entry (by last_seen) when the store is at capacity
        if store.len() >= MAX_DEVICE_TRUST_ENTRIES {
            if let Some(oldest_key) = store
                .iter()
                .min_by_key(|(_, v)| v.last_seen)
                .map(|(k, _)| k.clone())
            {
                store.remove(&oldest_key);
            }
        }

        store.insert(device_trust.device_id.clone(), device_trust);
    }

    /// Update device trust level
    pub fn update_device_trust(&self, device_id: &str, new_level: TrustLevel) {
        let mut store = match self.device_trust_store.write() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[SECURITY] Device trust store lock poisoned during write: {}", e);
                return;
            }
        };
        if let Some(device_trust) = store.get_mut(device_id) {
            device_trust.trust_level = new_level;
            device_trust.last_seen = Utc::now();
        }
    }

    /// Get the last_seen timestamp for a device, if it exists in the store
    pub fn get_device_last_seen(&self, device_id: &str) -> Option<DateTime<Utc>> {
        let store = match self.device_trust_store.read() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[SECURITY] Device trust store lock poisoned during read: {}", e);
                return None;
            }
        };
        store.get(device_id).map(|d| d.last_seen)
    }

    /// Verify a session/device and return the combined risk score.
    ///
    /// Unlike the trait method `verify_session` (which returns `Result<bool, String>`),
    /// this method exposes the actual computed risk score so callers can feed it into
    /// `generate_adaptive_controls` without losing precision.
    ///
    /// Returns `(is_valid, combined_risk_score)`.
    pub fn verify_session_with_score(&self, device_id: &str) -> Result<(bool, f64), String> {
        let store = self.device_trust_store.read()
            .map_err(|e| format!("Failed to read device trust store: {}", e))?;
        let device_trust = store.get(device_id);

        let device_risk = if let Some(trust) = device_trust {
            match trust.trust_level {
                TrustLevel::Maximum => 0.0,
                TrustLevel::High => 0.1,
                TrustLevel::Medium => 0.3,
                TrustLevel::Low => 0.6,
                TrustLevel::None => 0.9,
            }
        } else {
            0.5
        };

        // When no anomaly detector is configured we have zero behavioural
        // visibility, so assume a higher baseline risk (0.7).  With a detector
        // present we cannot run the full `calculate_behavioral_risk` (no
        // AuthContext available), so use a moderate baseline (0.3).
        let behavioral_risk = if self.anomaly_detector.is_some() { 0.3 } else { 0.7 };
        let location_risk = 0.2;

        let combined_risk = (device_risk * 0.4) + (behavioral_risk * 0.3) + (location_risk * 0.3);

        if combined_risk > 0.6 {
            // High risk — session is invalid
            Ok((false, combined_risk))
        } else {
            // Valid (possibly with elevated risk)
            Ok((true, combined_risk))
        }
    }

    /// Compute the server-side device fingerprint from device characteristics.
    ///
    /// This is the single source of truth for fingerprint generation.  Both
    /// `evaluate_device_trust` and any handler that needs to look up a device
    /// before calling `evaluate_device_trust` (e.g. to fetch `last_seen`)
    /// **must** use this method to avoid format divergence.
    pub fn compute_device_fingerprint(device_info: &DeviceInfo) -> String {
        format!(
            "fp_{}_{}_{}",
            device_info.user_agent, device_info.ip_address, device_info.os
        )
    }
}

#[async_trait]
impl ContinuousAuthService for ZeroTrustManager {
    async fn evaluate_device_trust(&self, device_info: &DeviceInfo) -> Result<DeviceTrust, String> {
        // Always generate the fingerprint server-side from device characteristics.
        // Never trust a client-provided fingerprint as the cache key — a malicious
        // client could send another device's fingerprint and inherit its trust level.
        let device_fingerprint = Self::compute_device_fingerprint(device_info);

        // Calculate trust level based on device characteristics (done before locking
        // so we don't hold the write lock longer than necessary for the insert).
        let mut trust_score = 0;
        let mut compliance_status = ComplianceStatus::Compliant;

        // Check operating system security
        if device_info.os.contains("Windows") || device_info.os.contains("macOS") {
            trust_score += 30;
        } else if device_info.os.contains("Linux") {
            trust_score += 25;
        } else if device_info.os.contains("iOS") || device_info.os.contains("Android") {
            trust_score += 20;
        } else {
            trust_score += 10;
            compliance_status = ComplianceStatus::NonCompliant;
        }

        // Check browser security (from user agent)
        if device_info.user_agent.contains("Chrome/") || device_info.user_agent.contains("Firefox/")
        {
            trust_score += 20;
        } else if device_info.user_agent.contains("Safari/") {
            trust_score += 15;
        }

        // Check if device has location info (indicates permission granted)
        if device_info.location.is_some() {
            trust_score += 10;
        }

        // Check user agent for legitimate browser indicators
        if device_info.user_agent.len() > 50 {
            // Detailed user agent suggests real browser, not bot
            trust_score += 10;
        }

        // Check if IP is from known safe range
        if !device_info.ip_address.starts_with("10.")
            && !device_info.ip_address.starts_with("192.168.")
            && !device_info.ip_address.starts_with("172.")
        {
            // Public IP, slightly higher risk
            trust_score += 5;
        } else {
            // Private IP, likely corporate network
            trust_score += 15;
        }

        // Determine trust level from score
        let trust_level = if trust_score >= 80 {
            TrustLevel::Maximum
        } else if trust_score >= 60 {
            TrustLevel::High
        } else if trust_score >= 40 {
            TrustLevel::Medium
        } else if trust_score >= 20 {
            TrustLevel::Low
        } else {
            compliance_status = ComplianceStatus::NonCompliant;
            TrustLevel::None
        };

        // Atomically check-then-insert under a single write lock to prevent the
        // TOCTOU race where two concurrent first-time requests for the same
        // fingerprint could both observe "not found" and overwrite each other.
        let mut store = self.device_trust_store.write()
            .map_err(|e| format!("Failed to write device trust store: {}", e))?;

        // If the fingerprint already exists, update in-place and return
        if let Some(existing) = store.get_mut(&device_fingerprint) {
            existing.last_seen = Utc::now();
            existing.device_info = device_info.clone();
            return Ok(existing.clone());
        }

        // Evict the oldest entry (by last_seen) when the store is at capacity
        if store.len() >= MAX_DEVICE_TRUST_ENTRIES {
            if let Some(oldest_key) = store
                .iter()
                .min_by_key(|(_, v)| v.last_seen)
                .map(|(k, _)| k.clone())
            {
                store.remove(&oldest_key);
            }
        }

        // Use the fingerprint as the device_id for stable lookups
        let device_trust = DeviceTrust {
            device_id: device_fingerprint.clone(),
            device_fingerprint,
            trust_level,
            last_seen: Utc::now(),
            first_seen: Utc::now(),
            device_info: device_info.clone(),
            compliance_status,
        };

        store.insert(device_trust.device_id.clone(), device_trust.clone());

        Ok(device_trust)
    }

    async fn assess_risk(&self, context: &AuthContext) -> Result<RiskAssessment, String> {
        let score = self.calculate_risk_score(context).await;
        let level = Self::determine_risk_level(score);

        let factors = vec![RiskFactor {
            factor_type: "device".to_string(),
            description: format!("Device trust: {:?}", context.device_trust.trust_level),
            weight: 0.4,
            severity: level.clone(),
        }];

        let recommendations = match level {
            RiskLevel::Critical => vec![
                "Require immediate MFA verification".to_string(),
                "Limit session to 15 minutes".to_string(),
                "Block administrative actions".to_string(),
            ],
            RiskLevel::High => vec![
                "Require MFA verification".to_string(),
                "Reduce session timeout".to_string(),
            ],
            RiskLevel::Medium => vec![
                "Monitor session closely".to_string(),
                "Require additional verification for sensitive actions".to_string(),
            ],
            _ => vec![],
        };

        Ok(RiskAssessment {
            score,
            level,
            factors,
            recommendations,
            assessed_at: Utc::now(),
        })
    }

    async fn update_adaptive_controls(&self, context: &mut AuthContext) -> Result<(), String> {
        let risk_score = context.risk_assessment.score;
        context.adaptive_controls = self.generate_adaptive_controls(risk_score);
        Ok(())
    }

    async fn verify_session(&self, device_id: &str) -> Result<bool, String> {
        // Integration 20: Zero Trust Session Verification
        // This integrates device trust evaluation, anomaly detection, and geolocation risk assessment
        // Note: In production, this would query session from database. Here we demonstrate
        // the risk assessment integration logic using the existing zero trust components.

        // Step 1: Check if we have cached device trust for this device
        let store = self.device_trust_store.read()
            .map_err(|e| format!("Failed to read device trust store: {}", e))?;
        let device_trust = store.get(device_id);

        // Step 2: Evaluate device trust
        let device_risk = if let Some(trust) = device_trust {
            match trust.trust_level {
                TrustLevel::Maximum => 0.0,
                TrustLevel::High => 0.1,
                TrustLevel::Medium => 0.3,
                TrustLevel::Low => 0.6,
                TrustLevel::None => 0.9,
            }
        } else {
            // No device trust info - elevated risk
            0.5
        };

        // Step 3: Calculate behavioral risk using anomaly detector if available
        let behavioral_risk = if let Some(ref _detector) = self.anomaly_detector {
            // In production, would use detector.is_new_ip() and other checks
            // For now, use medium risk when detector is available
            0.3
        } else {
            // No anomaly detector — no behavioural visibility, so assume
            // elevated risk.  This ensures untrusted devices can actually
            // exceed the 0.6 rejection threshold.
            0.7
        };

        // Step 4: Calculate location risk (placeholder - would use IP geolocation in production)
        let location_risk = 0.2; // Default low-medium risk

        // Step 5: Combine risk scores with weighted average
        // Weights: device 40%, behavioral 30%, location 30%
        let combined_risk = (device_risk * 0.4) + (behavioral_risk * 0.3) + (location_risk * 0.3);

        // Step 6: Verify based on risk threshold
        // Risk threshold: 0.0-0.3 = safe, 0.3-0.6 = elevated, 0.6-1.0 = high risk
        if combined_risk > 0.6 {
            Err(format!(
                "Session verification failed: high risk detected (score: {:.2})",
                combined_risk
            ))
        } else if combined_risk > 0.3 {
            // Elevated risk - may require additional verification
            // Returning Ok(false) indicates verification passed but with caution
            Ok(false) // Indicates additional verification recommended
        } else {
            // Low risk - session is valid
            Ok(true)
        }
    }

    async fn handle_suspicious_activity(
        &self,
        activity: &SuspiciousActivity,
    ) -> Result<(), String> {
        // Integration 21: Zero Trust Suspicious Activity Handler
        // This implements automated security response based on activity risk scores

        // Step 1: Categorize severity based on risk score
        let severity = match activity.risk_score {
            score if score >= 0.8 => "CRITICAL",
            score if score >= 0.6 => "HIGH",
            score if score >= 0.3 => "MEDIUM",
            _ => "LOW",
        };

        // Step 2: Log suspicious activity with detailed information
        eprintln!(
            "[SECURITY ALERT - {}] Suspicious activity detected:\n\
             Type: {}\n\
             User ID: {}\n\
             Session ID: {}\n\
             Device ID: {}\n\
             Risk Score: {:.2}\n\
             Timestamp: {}\n\
             Details: {:?}",
            severity,
            activity.activity_type,
            activity.user_id,
            activity.session_id,
            activity.device_id,
            activity.risk_score,
            activity.timestamp,
            activity.details
        );

        // Step 3: Update device trust based on severity
        {
            let mut store = self.device_trust_store.write()
                .map_err(|e| format!("Failed to write device trust store: {}", e))?;
            if let Some(device_trust) = store.get_mut(&activity.device_id) {
                let old_trust_level = device_trust.trust_level.clone();

                // Downgrade trust level based on risk score
                let new_trust_level = match activity.risk_score {
                    score if score >= 0.8 => TrustLevel::None,
                    score if score >= 0.6 => TrustLevel::Low,
                    score if score >= 0.3 => {
                        // Downgrade by one level
                        match old_trust_level {
                            TrustLevel::Maximum => TrustLevel::High,
                            TrustLevel::High => TrustLevel::Medium,
                            TrustLevel::Medium => TrustLevel::Low,
                            TrustLevel::Low => TrustLevel::None,
                            TrustLevel::None => TrustLevel::None,
                        }
                    }
                    _ => old_trust_level.clone(), // Keep current level for low risk
                };

                device_trust.trust_level = new_trust_level.clone();
                device_trust.last_seen = Utc::now();

                eprintln!(
                    "[SECURITY ACTION] Device trust updated for session {}: {:?} -> {:?}",
                    activity.session_id, old_trust_level, new_trust_level
                );
            }
        }

        // Step 4: Take action based on severity level
        match severity {
            "CRITICAL" => {
                // Critical: Immediate action required
                eprintln!(
                    "[SECURITY ACTION - CRITICAL] Recommended actions:\n\
                     1. REVOKE session {} immediately\n\
                     2. BLOCK user {} temporarily (24 hours)\n\
                     3. NOTIFY security team for investigation\n\
                     4. REQUIRE MFA on next login\n\
                     5. FLAG account for manual review",
                    activity.session_id, activity.user_id
                );
                // In production: Actually revoke session, block user, send alerts
                Err(format!(
                    "Critical security threat detected (risk: {:.2}). Session must be terminated.",
                    activity.risk_score
                ))
            }
            "HIGH" => {
                // High: Strong response needed
                eprintln!(
                    "[SECURITY ACTION - HIGH] Recommended actions:\n\
                     1. REQUIRE re-authentication for session {}\n\
                     2. ENABLE step-up authentication\n\
                     3. NOTIFY security team\n\
                     4. MONITOR user activity closely",
                    activity.session_id
                );
                // In production: Force re-auth, enable monitoring
                Ok(())
            }
            "MEDIUM" => {
                // Medium: Increased monitoring
                eprintln!(
                    "[SECURITY ACTION - MEDIUM] Recommended actions:\n\
                     1. INCREASE monitoring for user {}\n\
                     2. LOG activity for audit trail\n\
                     3. CONSIDER additional verification on sensitive operations",
                    activity.user_id
                );
                Ok(())
            }
            _ => {
                // Low: Log only
                eprintln!(
                    "[SECURITY ACTION - LOW] Activity logged for user {}. Monitoring continues.",
                    activity.user_id
                );
                Ok(())
            }
        }
    }
}

// Helper functions for session verification

/// Extract operating system from user agent string
pub fn extract_os(user_agent: &str) -> String {
    let ua_lower = user_agent.to_lowercase();
    if ua_lower.contains("windows") {
        "Windows".to_string()
    } else if ua_lower.contains("mac os") || ua_lower.contains("macos") {
        "macOS".to_string()
    } else if ua_lower.contains("linux") {
        "Linux".to_string()
    } else if ua_lower.contains("android") {
        "Android".to_string()
    } else if ua_lower.contains("iphone") || ua_lower.contains("ipad") {
        "iOS".to_string()
    } else {
        "Unknown".to_string()
    }
}

/// Extract browser from user agent string
pub fn extract_browser(user_agent: &str) -> String {
    let ua_lower = user_agent.to_lowercase();
    if ua_lower.contains("firefox") {
        "Firefox".to_string()
    } else if ua_lower.contains("chrome") && !ua_lower.contains("edge") {
        "Chrome".to_string()
    } else if ua_lower.contains("safari") && !ua_lower.contains("chrome") {
        "Safari".to_string()
    } else if ua_lower.contains("edge") {
        "Edge".to_string()
    } else if ua_lower.contains("opera") {
        "Opera".to_string()
    } else {
        "Unknown".to_string()
    }
}
