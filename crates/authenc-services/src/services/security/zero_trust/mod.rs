use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
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
    /// Whether the trust level was explicitly downgraded by `handle_suspicious_activity`.
    /// When `true`, `evaluate_device_trust` will **never** upgrade the trust level —
    /// only an explicit call to `update_device_trust` can clear this flag.
    #[serde(default)]
    pub security_downgraded: bool,
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    ///
    /// **Note:** This uses a simplified fixed risk model (see
    /// `verify_session_with_score` docs).  Scores are not directly comparable
    /// to those from `assess_risk` / `calculate_risk_score`.
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
///
/// # Persistence
/// When constructed with `new_with_database`, security-critical state
/// (`security_downgraded` flag and the frozen trust level) is persisted to the
/// `device_security_downgrades` table.  This ensures that a server restart
/// cannot silently undo a trust demotion applied by `handle_suspicious_activity`.
/// Non-security fields (full `DeviceTrust` entries) remain in-memory only and
/// are re-evaluated on the next `assess_risk` call after a restart.
pub struct ZeroTrustManager {
    // Internal storage for device trust information (wrapped in RwLock for interior mutability behind Arc)
    device_trust_store: RwLock<HashMap<String, DeviceTrust>>,
    // Risk assessment policies
    risk_policies: Vec<ZeroTrustPolicy>,
    // Adaptive control policies
    adaptive_policies: Vec<ZeroTrustPolicy>,
    // Anomaly detector for detecting unusual patterns
    anomaly_detector: Option<Box<dyn crate::services::security::anomaly_detector::AnomalyDetectorTrait>>,
    // Optional database for persisting security downgrades across restarts.
    // When `None`, the manager is purely in-memory (test/dev mode).
    database: Option<Arc<authenc_database::database::Database>>,
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
            database: None,
        }
    }

    /// Create a new zero trust manager backed by a database for persistence.
    ///
    /// Security downgrades applied by `handle_suspicious_activity` will be
    /// persisted to the `device_security_downgrades` table and survive server
    /// restarts.  Call `load_security_downgrades` after construction to seed
    /// the in-memory store from the database.
    pub fn new_with_database(database: Arc<authenc_database::database::Database>) -> Self {
        Self {
            device_trust_store: RwLock::new(HashMap::new()),
            risk_policies: Vec::new(),
            adaptive_policies: Vec::new(),
            anomaly_detector: None,
            database: Some(database),
        }
    }

    /// Ensure the `device_security_downgrades` table exists.
    ///
    /// This is idempotent (`CREATE TABLE IF NOT EXISTS`) and should be called
    /// once during application startup before any other zero-trust operations.
    pub async fn ensure_table(&self) -> Result<(), String> {
        let db = match &self.database {
            Some(db) => db,
            None => return Ok(()), // No database — nothing to create
        };

        db.execute(
            r#"
            CREATE TABLE IF NOT EXISTS device_security_downgrades (
                device_fingerprint TEXT PRIMARY KEY,
                trust_level        INTEGER NOT NULL DEFAULT 0,
                downgraded_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            "#,
            &[],
        )
        .await
        .map_err(|e| format!("Failed to create device_security_downgrades table: {}", e))?;

        Ok(())
    }

    /// Load persisted security downgrades from the database into the in-memory
    /// store so that `evaluate_device_trust` honours them after a restart.
    ///
    /// Each loaded entry is inserted with `security_downgraded: true` and the
    /// frozen `trust_level`.  The remaining fields (`device_info`, `compliance_status`,
    /// etc.) are set to safe defaults — they will be refreshed on the next
    /// `evaluate_device_trust` call for that device.
    pub async fn load_security_downgrades(&self) -> Result<usize, String> {
        let db = match &self.database {
            Some(db) => db,
            None => return Ok(0),
        };

        let rows = db
            .query_raw(
                "SELECT device_fingerprint, trust_level, downgraded_at FROM device_security_downgrades \
                 ORDER BY downgraded_at DESC LIMIT $1",
                &[&(MAX_DEVICE_TRUST_ENTRIES as i64)],
            )
            .await
            .map_err(|e| format!("Failed to load security downgrades: {}", e))?;

        let mut store = self.device_trust_store.write()
            .map_err(|e| format!("Lock poisoned during load_security_downgrades: {}", e))?;

        let mut count = 0usize;
        for row in &rows {
            let fingerprint: String = row.try_get(0)
                .map_err(|e| format!("Failed to read device_fingerprint: {}", e))?;
            let trust_level_int: i32 = row.try_get(1)
                .map_err(|e| format!("Failed to read trust_level: {}", e))?;
            let downgraded_at: DateTime<Utc> = row.try_get(2)
                .map_err(|e| format!("Failed to read downgraded_at: {}", e))?;

            let trust_level = match trust_level_int {
                0 => TrustLevel::None,
                1 => TrustLevel::Low,
                2 => TrustLevel::Medium,
                3 => TrustLevel::High,
                4 => TrustLevel::Maximum,
                _ => TrustLevel::None,
            };

            // Only insert if not already present (in-memory state takes precedence
            // if somehow populated before this call).
            if !store.contains_key(&fingerprint) && store.len() < MAX_DEVICE_TRUST_ENTRIES {
                store.insert(fingerprint.clone(), DeviceTrust {
                    device_id: fingerprint.clone(),
                    device_fingerprint: fingerprint,
                    trust_level,
                    last_seen: downgraded_at,
                    first_seen: downgraded_at,
                    device_info: DeviceInfo {
                        user_agent: String::new(),
                        ip_address: String::new(),
                        location: None,
                        os: String::new(),
                        browser: String::new(),
                        screen_resolution: None,
                        timezone: None,
                        fingerprint: None,
                    },
                    compliance_status: ComplianceStatus::Unknown,
                    security_downgraded: true,
                });
                count += 1;
            }
        }

        if count > 0 {
            eprintln!(
                "[SECURITY] Loaded {} persisted security downgrades from database",
                count
            );
        }

        Ok(count)
    }

    /// Persist a security downgrade to the database (upsert).
    ///
    /// This is a fire-and-forget best-effort write — if the DB is unavailable
    /// the in-memory flag is still set, and the downgrade will be lost on
    /// restart.  The `eprintln!` ensures operators are alerted.
    async fn persist_security_downgrade(
        &self,
        device_fingerprint: &str,
        trust_level: &TrustLevel,
    ) {
        let db = match &self.database {
            Some(db) => db,
            None => return,
        };

        let trust_level_int = match trust_level {
            TrustLevel::None => 0i32,
            TrustLevel::Low => 1,
            TrustLevel::Medium => 2,
            TrustLevel::High => 3,
            TrustLevel::Maximum => 4,
        };

        let now = Utc::now();

        let fp = device_fingerprint.to_string();
        if let Err(e) = db
            .execute(
                r#"
                INSERT INTO device_security_downgrades
                    (device_fingerprint, trust_level, downgraded_at, updated_at)
                VALUES ($1, $2, $3, $3)
                ON CONFLICT (device_fingerprint)
                DO UPDATE SET trust_level = $2, updated_at = $3
                "#,
                &[&fp, &trust_level_int, &now],
            )
            .await
        {
            eprintln!(
                "[SECURITY WARNING] Failed to persist security downgrade for '{}': {}. \
                 The downgrade is active in-memory but will be lost on restart.",
                device_fingerprint, e
            );
        }
    }

    /// Remove a persisted security downgrade from the database.
    ///
    /// Called by `update_device_trust` (explicit admin action) to clear the
    /// persisted flag so it does not resurrect after a restart.
    async fn remove_persisted_security_downgrade(&self, device_fingerprint: &str) {
        let db = match &self.database {
            Some(db) => db,
            None => return,
        };

        let fp = device_fingerprint.to_string();
        if let Err(e) = db
            .execute(
                "DELETE FROM device_security_downgrades WHERE device_fingerprint = $1",
                &[&fp],
            )
            .await
        {
            eprintln!(
                "[SECURITY WARNING] Failed to remove persisted security downgrade for '{}': {}. \
                 The downgrade was cleared in-memory but may resurrect on restart.",
                device_fingerprint, e
            );
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

    /// Calculate risk score and contributing factors based on multiple signals.
    ///
    /// Returns `(score, factors)` where `score` is in `[0, 1]` and `factors`
    /// contains per-component breakdowns.  `assess_risk` uses both to build
    /// the full `RiskAssessment`.
    pub async fn calculate_risk_score(&self, context: &AuthContext) -> (f64, Vec<RiskFactor>) {
        let mut total_score = 0.0;
        let mut total_weight = 0.0;
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
        total_weight += 0.4;
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
        total_weight += 0.2;
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
        total_weight += 0.15;
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
            total_weight += 0.25;
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

        // Normalize by the sum of active weights so that the score stays in
        // [0, 1] even when the anomaly detector is absent (total_weight = 0.75).
        // Without normalization the maximum possible score would be ~0.66,
        // making RiskLevel::Critical unreachable.
        if total_weight > 0.0 {
            total_score /= total_weight;

            // Also normalize factor weights so they sum to 1.0 and reflect
            // each component's actual contribution ratio.  Without this,
            // consumers of `RiskAssessment.factors` would see raw weights
            // summing to 0.75 when the anomaly detector is absent.
            for factor in &mut factors {
                factor.weight /= total_weight;
            }
        }

        // Clamp score between 0 and 1
        (total_score.clamp(0.0, 1.0), factors)
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

    /// Evict the oldest entry (by `last_seen`) from the given store if it is at
    /// or above `MAX_DEVICE_TRUST_ENTRIES`.  This is the single source of truth
    /// for eviction policy — used by both `register_device_trust` and
    /// `evaluate_device_trust` to avoid divergence.
    ///
    /// # Performance
    ///
    /// This performs an O(n) scan of the entire HashMap to find the oldest entry.
    /// The scan runs under the caller's write lock, so it blocks all concurrent
    /// readers and writers while iterating.  At `MAX_DEVICE_TRUST_ENTRIES` (10,000)
    /// this is acceptable for typical workloads, but if contention becomes an issue
    /// consider migrating to a `BTreeMap<(DateTime, String), DeviceTrust>` or an
    /// LRU cache for O(1) / O(log n) eviction.
    fn evict_oldest_if_at_capacity(store: &mut HashMap<String, DeviceTrust>) {
        if store.len() >= MAX_DEVICE_TRUST_ENTRIES {
            // Prefer evicting entries that are NOT security-downgraded.
            // Evicting a downgraded entry would silently clear the flag on
            // the next `evaluate_device_trust` call (which creates a fresh
            // entry with `security_downgraded: false`), effectively undoing
            // a trust demotion applied by `handle_suspicious_activity`.
            if let Some(oldest_key) = store
                .iter()
                .filter(|(_, v)| !v.security_downgraded)
                .min_by_key(|(_, v)| v.last_seen)
                .map(|(k, _)| k.clone())
            {
                store.remove(&oldest_key);
            } else {
                // All entries are security-downgraded — refuse to evict any of
                // them.  Evicting a downgraded entry would allow the device to
                // reconnect and receive a fresh entry with
                // `security_downgraded: false`, silently undoing the trust
                // demotion applied by `handle_suspicious_activity`.
                //
                // The caller will fail to insert the new entry (the store is
                // full).  This is the safe default: the new device simply won't
                // get a trust entry and will be treated as unknown (high risk).
                //
                // This degraded state should not occur in practice (it would
                // require 10,000 distinct devices all flagged as suspicious).
                // For high-security deployments, consider persisting security
                // downgrades externally (e.g. in the database) so they survive
                // eviction and normal entries can be evicted instead.
                eprintln!(
                    "[SECURITY WARNING] Device trust store at capacity ({}) with ALL entries \
                     security-downgraded.  Refusing to evict to preserve trust demotions.  \
                     New device entry will not be stored.",
                    MAX_DEVICE_TRUST_ENTRIES
                );
            }
        }
    }

    /// Check if device is trusted.
    ///
    /// Returns `Err` if the internal lock is poisoned.  Callers should treat
    /// an error as "not trusted" (fail closed).
    pub fn is_device_trusted(&self, device_id: &str) -> Result<bool, String> {
        let store = self.device_trust_store.read()
            .map_err(|e| format!("[SECURITY] Device trust store lock poisoned during read: {}", e))?;
        if let Some(device_trust) = store.get(device_id) {
            Ok(matches!(
                device_trust.trust_level,
                TrustLevel::High | TrustLevel::Maximum
            ))
        } else {
            Ok(false)
        }
    }

    /// Register device trust, evicting the oldest entry if the store exceeds its capacity.
    ///
    /// Returns `Err` if the internal lock is poisoned — callers should treat
    /// this as a degraded security state (the device trust entry was NOT stored).
    pub fn register_device_trust(&self, device_trust: DeviceTrust) -> Result<(), String> {
        let mut store = self.device_trust_store.write()
            .map_err(|e| format!("[SECURITY] Device trust store lock poisoned during write: {}", e))?;

        // If the device already exists, update it in-place (no eviction needed).
        // We must preserve the `security_downgraded` flag set by
        // `handle_suspicious_activity` — a blind insert would reset it to
        // `false`, silently undoing a trust demotion.
        if let Some(existing) = store.get_mut(&device_trust.device_id) {
            existing.last_seen = device_trust.last_seen;
            existing.device_info = device_trust.device_info;
            existing.compliance_status = device_trust.compliance_status;
            // When the device has been security-downgraded, freeze the trust
            // level.  Otherwise, apply the new trust level in both directions
            // (mirrors the guard in `evaluate_device_trust`).
            if !existing.security_downgraded {
                existing.trust_level = device_trust.trust_level;
            }
            return Ok(());
        }

        Self::evict_oldest_if_at_capacity(&mut store);

        // If the store is still at capacity after eviction (all entries are
        // security-downgraded), skip the insert to avoid exceeding the cap.
        if store.len() >= MAX_DEVICE_TRUST_ENTRIES {
            eprintln!(
                "[SECURITY] Cannot register device trust entry for '{}': \
                 store at capacity with all entries security-downgraded.",
                device_trust.device_id
            );
            return Ok(());
        }

        store.insert(device_trust.device_id.clone(), device_trust);
        Ok(())
    }

    /// Update device trust level (explicit administrative action).
    ///
    /// This also clears the `security_downgraded` flag so that future
    /// `evaluate_device_trust` calls can upgrade the trust level again
    /// based on device characteristics.  The persisted downgrade (if any)
    /// is also removed from the database.
    ///
    /// Returns `Err` if the internal lock is poisoned.
    pub async fn update_device_trust(&self, device_id: &str, new_level: TrustLevel) -> Result<(), String> {
        let was_downgraded = {
            let mut store = self.device_trust_store.write()
                .map_err(|e| format!("[SECURITY] Device trust store lock poisoned during write: {}", e))?;
            if let Some(device_trust) = store.get_mut(device_id) {
                let was = device_trust.security_downgraded;
                device_trust.trust_level = new_level;
                device_trust.security_downgraded = false;
                device_trust.last_seen = Utc::now();
                was
            } else {
                false
            }
        }; // write lock dropped here — safe to .await below

        // Remove the persisted downgrade so it doesn't resurrect on restart.
        if was_downgraded {
            self.remove_persisted_security_downgrade(device_id).await;
        }

        Ok(())
    }

    /// Get the last_seen timestamp for a device, if it exists in the store.
    ///
    /// Returns `Err` if the internal lock is poisoned.
    pub fn get_device_last_seen(&self, device_id: &str) -> Result<Option<DateTime<Utc>>, String> {
        let store = self.device_trust_store.read()
            .map_err(|e| format!("[SECURITY] Device trust store lock poisoned during read: {}", e))?;
        Ok(store.get(device_id).map(|d| d.last_seen))
    }

    /// Verify a session/device and return the combined risk score.
    ///
    /// Unlike the trait method `verify_session` (which returns `Result<bool, String>`),
    /// this method exposes the actual computed risk score so callers can feed it into
    /// `generate_adaptive_controls` without losing precision.
    ///
    /// # Scoring model divergence from `calculate_risk_score`
    ///
    /// This method uses a **simplified fixed model** (40% device / 30% behavioral /
    /// 30% location with hardcoded `behavioral_risk=0.7`, `location_risk=0.2`)
    /// because it lacks an `AuthContext` and cannot run the full dynamic analysis.
    /// In contrast, `calculate_risk_score` (used by `assess_risk`) uses a dynamic
    /// model (40/20/15/25 weights, with normalization and real anomaly detection).
    ///
    /// This means scores from `assess_risk` and `verify_session` are **not directly
    /// comparable**.  The conservative fixed baseline ensures `verify_session` errs
    /// on the side of caution (higher scores) when full context is unavailable.
    ///
    /// Returns `(is_valid, combined_risk_score)` where `is_valid` is `false`
    /// when `combined_risk_score >= 0.6` (aligned with `determine_risk_level`
    /// and `generate_adaptive_controls`).
    pub fn verify_session_with_score(&self, device_id: &str) -> Result<(bool, f64), String> {
        // Extract the device risk score under the read lock, then drop the guard
        // immediately so we don't hold it during the subsequent arithmetic.
        // This reduces write-lock contention from concurrent callers of
        // `evaluate_device_trust`, `handle_suspicious_activity`, etc.
        let device_risk = {
            let store = self.device_trust_store.read()
                .map_err(|e| format!("Failed to read device trust store: {}", e))?;
            if let Some(trust) = store.get(device_id) {
                match trust.trust_level {
                    TrustLevel::Maximum => 0.0,
                    TrustLevel::High => 0.1,
                    TrustLevel::Medium => 0.3,
                    TrustLevel::Low => 0.6,
                    TrustLevel::None => 1.0,
                }
            } else {
                // Unknown device — no entry in the trust store.  This should only
                // happen if: (a) the device was never assessed via `assess_risk`,
                // (b) the entry was evicted due to capacity limits, or (c) the
                // server restarted (in-memory store).
                //
                // In all cases, the device has no established trust and should be
                // treated as invalid.  Using 1.0 (same as TrustLevel::None) ensures
                // unknown devices are always rejected, forcing the client to call
                // `assess_risk` first to establish a trust entry.
                1.0
            }
        };

        // Conservative baseline for behavioural risk.  We cannot run the full
        // `calculate_behavioral_risk` here (no AuthContext available), so we use
        // a fixed value regardless of whether an anomaly detector is configured.
        // 0.7 is high enough that untrusted devices (device_risk >= 1.0) can
        // still exceed the 0.6 rejection threshold (>= 0.6):
        //
        // With behavioral_risk = 0.7 and device_risk = 1.0 (TrustLevel::None or unknown):
        //   combined = 1.0*0.4 + 0.7*0.3 + 0.2*0.3 = 0.67 >= 0.6 ✓ (rejected)
        // With behavioral_risk = 0.7 and device_risk = 0.6 (TrustLevel::Low):
        //   combined = 0.6*0.4 + 0.7*0.3 + 0.2*0.3 = 0.51 (elevated, not rejected) ✓
        let behavioral_risk = 0.7;
        let location_risk = 0.2;

        let combined_risk = (device_risk * 0.4) + (behavioral_risk * 0.3) + (location_risk * 0.3);

        if combined_risk >= 0.6 {
            // High risk — session is invalid.
            // Uses `>= 0.6` to align with `determine_risk_level` which
            // classifies 0.6 as `RiskLevel::High`, and `generate_adaptive_controls`
            // which applies high-risk controls (MFA, 30min timeout) at `>= 0.6`.
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
    ///
    /// # Known limitation: IP-based fingerprint instability
    ///
    /// The fingerprint includes `ip_address`, so any IP change (WiFi→cellular,
    /// DHCP renewal, VPN toggle) produces a new fingerprint and a new device
    /// trust entry.  The `verify_session` handler correctly rejects mismatches
    /// with `device_mismatch` so the client can re-assess.  This is the secure
    /// default (never trust client-provided fingerprints as cache keys), but
    /// causes frequent re-assessments for mobile clients.  A future improvement
    /// could incorporate a server-issued opaque device token (stored in a
    /// secure cookie) to provide stable identity across IP changes.
    pub fn compute_device_fingerprint(device_info: &DeviceInfo) -> String {
        // Use length-prefixed fields to prevent ambiguity between inputs.
        // Without length prefixes, UA="a_b" + IP="c" produces the same
        // pre-hash string as UA="a" + IP="b_c" when using `_` as delimiter.
        // SHA-256 makes accidental collision negligible, but length-prefixing
        // eliminates the theoretical class entirely at near-zero cost.
        let raw = format!(
            "fp:{}:{}:{}:{}:{}:{}",
            device_info.user_agent.len(),
            device_info.user_agent,
            device_info.ip_address.len(),
            device_info.ip_address,
            device_info.os.len(),
            device_info.os,
        );
        let hash = Sha256::digest(raw.as_bytes());
        format!("fp_{}", hex::encode(hash))
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

        // Before acquiring the write lock, check the database for a persisted
        // security downgrade that may have been evicted from the in-memory store.
        // This prevents the scenario where:
        //   1. Device is flagged → persisted to DB + in-memory
        //   2. In-memory entry is evicted (capacity pressure)
        //   3. Device reconnects → evaluate_device_trust sees "not found" in memory
        //   4. Without this check, a fresh entry with security_downgraded=false is created
        //
        // The DB read happens before the write lock to avoid holding the lock across .await.
        let persisted_downgrade: Option<(TrustLevel, DateTime<Utc>)> = if let Some(db) = &self.database {
            match db
                .query_raw(
                    "SELECT trust_level, downgraded_at FROM device_security_downgrades WHERE device_fingerprint = $1",
                    &[&device_fingerprint],
                )
                .await
            {
                Ok(rows) if !rows.is_empty() => {
                    let tl: i32 = rows[0].try_get(0).unwrap_or(0);
                    let da: DateTime<Utc> = rows[0].try_get(1).unwrap_or_else(|_| Utc::now());
                    let level = match tl {
                        0 => TrustLevel::None,
                        1 => TrustLevel::Low,
                        2 => TrustLevel::Medium,
                        3 => TrustLevel::High,
                        4 => TrustLevel::Maximum,
                        _ => TrustLevel::None,
                    };
                    Some((level, da))
                }
                Ok(_) => None,
                Err(e) => {
                    // DB read failed — fail closed (reject the request).
                    // A previously-flagged device whose in-memory entry was evicted
                    // could bypass its security downgrade if we silently treat a DB
                    // error as "no persisted downgrade".  Returning an error forces
                    // the caller to retry when the DB is available again.
                    return Err(format!(
                        "[SECURITY] Cannot evaluate device trust for '{}': \
                         failed to check persisted security downgrades: {}. \
                         Failing closed to prevent potential trust bypass.",
                        device_fingerprint, e
                    ));
                }
            }
        } else {
            None
        };

        // Atomically check-then-insert under a single write lock to prevent the
        // TOCTOU race where two concurrent first-time requests for the same
        // fingerprint could both observe "not found" and overwrite each other.
        let mut store = self.device_trust_store.write()
            .map_err(|e| format!("Failed to write device trust store: {}", e))?;

        // If the fingerprint already exists, update in-place and return.
        // We must never overwrite a security downgrade applied by
        // `handle_suspicious_activity`.  The `security_downgraded` flag
        // is set when suspicious activity triggers a trust demotion;
        // while it is set, we skip trust-level changes entirely so that
        // repeated `assess_risk` calls cannot silently rehabilitate a
        // device that was flagged as suspicious.
        if let Some(existing) = store.get_mut(&device_fingerprint) {
            existing.last_seen = Utc::now();
            existing.device_info = device_info.clone();
            // When the device has been security-downgraded by
            // `handle_suspicious_activity`, freeze the trust level until an
            // administrator explicitly clears it via `update_device_trust`.
            //
            // Otherwise, apply the freshly-computed trust level in both
            // directions (upgrade *and* downgrade).  The old code only
            // upgraded, which meant a device whose characteristics degraded
            // (e.g. switched to an unknown OS or lost location data) would
            // keep its previous high-water-mark trust level indefinitely.
            if !existing.security_downgraded {
                existing.trust_level = trust_level;
            }
            // Compliance may degrade independently of trust level (e.g. an
            // unknown OS), so always apply the freshly-computed status.
            existing.compliance_status = compliance_status;
            return Ok(existing.clone());
        }

        // If the device is not in memory but has a persisted security downgrade,
        // re-create the entry with the downgraded flag set.  This covers the case
        // where the in-memory entry was evicted but the DB record survives.
        //
        // TOCTOU mitigation: the `persisted_downgrade` was read from the DB
        // *before* we acquired the write lock.  A concurrent `update_device_trust`
        // could have cleared the downgrade (both in-memory and DB) in between.
        // To avoid resurrecting a stale downgrade, we drop the write lock,
        // re-query the DB, and re-acquire the lock.  The second DB read is
        // authoritative because `update_device_trust` deletes the DB row
        // *after* clearing the in-memory flag, so if the row still exists the
        // downgrade is genuinely active.
        if persisted_downgrade.is_some() {
            // Drop the write lock before the async DB re-check.
            drop(store);

            // Re-query the DB to confirm the downgrade is still active.
            let confirmed_downgrade: Option<(TrustLevel, DateTime<Utc>)> = if let Some(db) = &self.database {
                match db
                    .query_raw(
                        "SELECT trust_level, downgraded_at FROM device_security_downgrades WHERE device_fingerprint = $1",
                        &[&device_fingerprint],
                    )
                    .await
                {
                    Ok(rows) if !rows.is_empty() => {
                        let tl: i32 = rows[0].try_get(0).unwrap_or(0);
                        let da: DateTime<Utc> = rows[0].try_get(1).unwrap_or_else(|_| Utc::now());
                        let level = match tl {
                            0 => TrustLevel::None,
                            1 => TrustLevel::Low,
                            2 => TrustLevel::Medium,
                            3 => TrustLevel::High,
                            4 => TrustLevel::Maximum,
                            _ => TrustLevel::None,
                        };
                        Some((level, da))
                    }
                    Ok(_) => None, // Row was deleted — downgrade was cleared
                    Err(e) => {
                        return Err(format!(
                            "[SECURITY] Cannot evaluate device trust for '{}': \
                             failed to re-check persisted security downgrade: {}. \
                             Failing closed to prevent potential trust bypass.",
                            device_fingerprint, e
                        ));
                    }
                }
            } else {
                None
            };

            // Re-acquire the write lock and re-check the in-memory store.
            // Another thread may have inserted an entry while we were awaiting.
            let mut store = self.device_trust_store.write()
                .map_err(|e| format!("Failed to write device trust store: {}", e))?;

            // Re-check: if the entry appeared in memory while we re-queried,
            // update it in-place (same logic as the primary check above).
            if let Some(existing) = store.get_mut(&device_fingerprint) {
                existing.last_seen = Utc::now();
                existing.device_info = device_info.clone();
                if !existing.security_downgraded {
                    existing.trust_level = trust_level;
                }
                existing.compliance_status = compliance_status;
                return Ok(existing.clone());
            }

            // If the DB re-check confirmed the downgrade is still active,
            // restore the entry with the downgraded flag.
            if let Some((persisted_level, downgraded_at)) = confirmed_downgrade {
                Self::evict_oldest_if_at_capacity(&mut store);
                if store.len() < MAX_DEVICE_TRUST_ENTRIES {
                    let restored = DeviceTrust {
                        device_id: device_fingerprint.clone(),
                        device_fingerprint: device_fingerprint.clone(),
                        trust_level: persisted_level,
                        last_seen: Utc::now(),
                        first_seen: downgraded_at,
                        device_info: device_info.clone(),
                        compliance_status,
                        security_downgraded: true,
                    };
                    store.insert(device_fingerprint.clone(), restored.clone());
                    return Ok(restored);
                }
                // Store full — return transient entry with downgrade honoured.
                return Ok(DeviceTrust {
                    device_id: device_fingerprint.clone(),
                    device_fingerprint,
                    trust_level: persisted_level,
                    last_seen: Utc::now(),
                    first_seen: downgraded_at,
                    device_info: device_info.clone(),
                    compliance_status,
                    security_downgraded: true,
                });
            }

            // The downgrade was cleared between our first and second DB reads.
            // Fall through to create a fresh (non-downgraded) entry below.
            // `store` is the re-acquired write guard — used by the code below.
            Self::evict_oldest_if_at_capacity(&mut store);

            if store.len() >= MAX_DEVICE_TRUST_ENTRIES {
                eprintln!(
                    "[SECURITY] Cannot store new device trust entry for '{}': \
                     store at capacity with all entries security-downgraded.",
                    device_fingerprint
                );
                return Ok(DeviceTrust {
                    device_id: device_fingerprint.clone(),
                    device_fingerprint,
                    trust_level,
                    last_seen: Utc::now(),
                    first_seen: Utc::now(),
                    device_info: device_info.clone(),
                    compliance_status,
                    security_downgraded: false,
                });
            }

            let device_trust = DeviceTrust {
                device_id: device_fingerprint.clone(),
                device_fingerprint,
                trust_level,
                last_seen: Utc::now(),
                first_seen: Utc::now(),
                device_info: device_info.clone(),
                compliance_status,
                security_downgraded: false,
            };

            store.insert(device_trust.device_id.clone(), device_trust.clone());
            return Ok(device_trust);
        }

        Self::evict_oldest_if_at_capacity(&mut store);

        // If the store is still at capacity after eviction (all entries are
        // security-downgraded), skip the insert to avoid exceeding the cap.
        // The device will be treated as unknown (high risk) by verify_session.
        if store.len() >= MAX_DEVICE_TRUST_ENTRIES {
            eprintln!(
                "[SECURITY] Cannot store new device trust entry for '{}': \
                 store at capacity with all entries security-downgraded.",
                device_fingerprint
            );
            // Return a transient entry so the caller still gets a DeviceTrust,
            // but it won't be persisted or looked up on subsequent calls.
            return Ok(DeviceTrust {
                device_id: device_fingerprint.clone(),
                device_fingerprint,
                trust_level,
                last_seen: Utc::now(),
                first_seen: Utc::now(),
                device_info: device_info.clone(),
                compliance_status,
                security_downgraded: false,
            });
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
            security_downgraded: false,
        };

        store.insert(device_trust.device_id.clone(), device_trust.clone());

        Ok(device_trust)
    }

    async fn assess_risk(&self, context: &AuthContext) -> Result<RiskAssessment, String> {
        let (score, factors) = self.calculate_risk_score(context).await;
        let level = Self::determine_risk_level(score);

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

        // Step 1+2: Extract device risk under a scoped read lock, then drop the
        // guard immediately so we don't hold it during the subsequent arithmetic.
        let device_risk = {
            let store = self.device_trust_store.read()
                .map_err(|e| format!("Failed to read device trust store: {}", e))?;
            if let Some(trust) = store.get(device_id) {
                match trust.trust_level {
                    TrustLevel::Maximum => 0.0,
                    TrustLevel::High => 0.1,
                    TrustLevel::Medium => 0.3,
                    TrustLevel::Low => 0.6,
                    TrustLevel::None => 1.0,
                }
            } else {
                // No device trust info — unknown device has no established trust.
                // Using 1.0 (same as TrustLevel::None) ensures unknown devices are
                // always rejected, matching verify_session_with_score.
                1.0
            }
        };

        // Step 3: Conservative baseline for behavioral risk.
        // We cannot run full behavioral analysis without an AuthContext, so use
        // a fixed value regardless of anomaly detector presence.  0.7 ensures
        // untrusted devices (device_risk >= 1.0) can exceed the 0.6 rejection
        // threshold (matches verify_session_with_score and calculate_risk_score).
        //
        // With behavioral_risk = 0.7 and device_risk = 1.0 (TrustLevel::None or unknown):
        //   combined = 1.0*0.4 + 0.7*0.3 + 0.2*0.3 = 0.67 >= 0.6 ✓
        let behavioral_risk = 0.7;

        // Step 4: Calculate location risk (placeholder - would use IP geolocation in production)
        let location_risk = 0.2; // Default low-medium risk

        // Step 5: Combine risk scores with weighted average
        // Weights: device 40%, behavioral 30%, location 30%
        let combined_risk = (device_risk * 0.4) + (behavioral_risk * 0.3) + (location_risk * 0.3);

        // Step 6: Verify based on risk threshold
        // Risk threshold: 0.0-0.3 = safe, 0.3-0.6 = elevated, 0.6-1.0 = high risk
        //
        // Semantics aligned with `verify_session_with_score`:
        //   Ok(true)  — low or elevated risk (combined_risk < 0.6), session valid
        //   Ok(false) — high risk (combined_risk >= 0.6), session invalid
        //   Err(...)  — internal/lock error only (never for risk-based rejection)
        //
        // Uses `>= 0.6` to align with `determine_risk_level` which classifies
        // 0.6 as `RiskLevel::High`, and `generate_adaptive_controls` which
        // applies high-risk controls (MFA, 30min timeout) at `>= 0.6`.
        //
        // Callers that need the actual score should use `verify_session_with_score`.
        if combined_risk >= 0.6 {
            // High risk — session invalid, but return Ok(false) so callers can
            // handle it gracefully (e.g. step-up auth) instead of treating it as
            // an internal error.
            Ok(false)
        } else {
            // Low or elevated risk — session is valid.
            // Callers that need to distinguish elevated (0.3-0.6) from low (<= 0.3)
            // should use `verify_session_with_score` instead.
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

        // Step 3: Update device trust based on severity.
        // Capture the final trust level for DB persistence after the lock is dropped.
        let downgrade_to_persist: Option<(String, TrustLevel)> = {
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

                // Mark the device as security-downgraded so that
                // `evaluate_device_trust` will not silently undo this
                // demotion on the next `assess_risk` call.
                //
                // We guard on `risk_score >= 0.3` (not `new < old`) because
                // the device may already be at or below the target level
                // (e.g. TrustLevel::None receiving a CRITICAL alert where
                // new == old == None).  Without the flag in that case, a
                // subsequent `evaluate_device_trust` could upgrade the
                // device despite the active security alert.  The `_ =>`
                // branch (risk_score < 0.3) keeps the current level and
                // should not lock the device.
                if activity.risk_score >= 0.3 {
                    device_trust.security_downgraded = true;
                    // Never upgrade the trust level during a suspicious-activity
                    // response.  The risk-score-to-level mapping above can
                    // produce a level *higher* than the current one (e.g.
                    // TrustLevel::Low for a HIGH alert on a device already at
                    // TrustLevel::None).  The guard below guarantees we only
                    // downgrade or stay the same.
                    if new_trust_level < old_trust_level {
                        device_trust.trust_level = new_trust_level.clone();
                    }
                    // else: keep current (already at or below target)
                }
                device_trust.last_seen = Utc::now();

                if device_trust.trust_level != old_trust_level {
                    eprintln!(
                        "[SECURITY ACTION] Device trust updated for device {}: {:?} -> {:?}",
                        activity.device_id, old_trust_level, device_trust.trust_level
                    );
                } else {
                    eprintln!(
                        "[SECURITY ACTION] Device trust unchanged for device {} (remains {:?}, security_downgraded={})",
                        activity.device_id, device_trust.trust_level, device_trust.security_downgraded
                    );
                }

                // If we set the security_downgraded flag, schedule a DB persist.
                if device_trust.security_downgraded {
                    Some((activity.device_id.clone(), device_trust.trust_level.clone()))
                } else {
                    None
                }
            } else {
                // Device not found in the in-memory store.  This can happen if:
                //   (a) the device was never assessed via `assess_risk`,
                //   (b) the entry was evicted due to capacity limits, or
                //   (c) the server restarted and the entry was not a persisted downgrade.
                //
                // For cases (b) and (c), the suspicious activity report would be
                // silently lost — the device could reconnect and receive a fresh
                // entry with `security_downgraded: false`.  To prevent this, we
                // persist the downgrade to the database directly so that
                // `evaluate_device_trust`'s DB-check path can pick it up later.
                if activity.risk_score >= 0.3 {
                    let trust_level = match activity.risk_score {
                        score if score >= 0.8 => TrustLevel::None,
                        score if score >= 0.6 => TrustLevel::Low,
                        _ => TrustLevel::Low, // Conservative: cap at Low for evicted devices
                    };
                    eprintln!(
                        "[SECURITY WARNING] Device '{}' not found in trust store during \
                         suspicious activity handling (risk: {:.2}).  Persisting downgrade \
                         to database so it is honoured when the device reconnects.",
                        activity.device_id, activity.risk_score
                    );
                    Some((activity.device_id.clone(), trust_level))
                } else {
                    None
                }
            }
        }; // write lock dropped here — safe to .await below

        // Persist the security downgrade to the database so it survives restarts.
        if let Some((fingerprint, trust_level)) = downgrade_to_persist {
            self.persist_security_downgrade(&fingerprint, &trust_level).await;
        }

        // Step 4: Take action based on severity level
        match severity {
            "CRITICAL" => {
                // Critical: Immediate action required
                //
                // NOTE: The trust demotion and `security_downgraded` flag have
                // **already been committed** to the device trust store above.
                // The `Err` returned here signals to the caller that the session
                // must be terminated — it does NOT mean "no action was taken".
                // Callers should NOT retry on this error; the security response
                // is already in effect.
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
                    "Critical security threat detected (risk: {:.2}). Session must be terminated. \
                     Device trust has been downgraded.",
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
    } else if ua_lower.contains("android") {
        "Android".to_string()
    } else if ua_lower.contains("linux") {
        "Linux".to_string()
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
