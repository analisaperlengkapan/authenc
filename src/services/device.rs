use crate::database::Database;
use crate::error::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Device information and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Unique identifier for the device
    pub id: Uuid,
    /// User ID that owns this device
    pub user_id: Uuid,
    /// Human-readable device name
    pub device_name: String,
    /// Type of device
    pub device_type: DeviceType,
    /// Operating system name
    pub os: String,
    /// Operating system version
    pub os_version: String,
    /// Browser name (if applicable)
    pub browser: Option<String>,
    /// Browser version (if applicable)
    pub browser_version: Option<String>,
    /// IP address of the device
    pub ip_address: String,
    /// User agent string
    pub user_agent: String,
    /// Device fingerprint for identification
    pub fingerprint: String,
    /// Trust score (0.0 to 1.0)
    pub trust_score: f64,
    /// Whether the device is trusted
    pub is_trusted: bool,
    /// Last time the device was seen
    pub last_seen: DateTime<Utc>,
    /// When the device was first registered
    pub created_at: DateTime<Utc>,
    /// Geographic location of the device
    pub location: Option<DeviceLocation>,
    /// Security features available on the device
    pub security_features: DeviceSecurityFeatures,
}

/// Device type classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceType {
    /// Desktop computer
    Desktop,
    /// Mobile phone or smartphone
    Mobile,
    /// Tablet device
    Tablet,
    /// Internet of Things device
    IoT,
    /// Server machine
    Server,
    /// Unknown device type
    Unknown,
}

/// Device location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceLocation {
    /// Country code or name
    pub country: Option<String>,
    /// Region or state
    pub region: Option<String>,
    /// City name
    pub city: Option<String>,
    /// Latitude coordinate
    pub latitude: Option<f64>,
    /// Longitude coordinate
    pub longitude: Option<f64>,
}

/// Device security features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSecurityFeatures {
    /// Whether the device has biometric authentication
    pub has_biometrics: bool,
    /// Whether the device has hardware security features
    pub has_hardware_security: bool,
    /// Whether the device has screen lock enabled
    pub has_screen_lock: bool,
    /// Whether encryption is enabled on the device
    pub encryption_enabled: bool,
    /// Whether the device supports remote wipe
    pub remote_wipe_capable: bool,
    /// Whether jailbreak/root has been detected
    pub jailbreak_detected: bool,
}

/// Device trust policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTrustPolicy {
    /// Unique identifier for the policy
    pub id: Uuid,
    /// Human-readable name of the policy
    pub name: String,
    /// Description of what the policy does
    pub description: String,
    /// Conditions that must be met for the policy to apply
    pub conditions: Vec<TrustCondition>,
    /// Action to take when conditions are met
    pub action: TrustAction,
    /// Whether the policy is currently enabled
    pub enabled: bool,
    /// Priority of the policy (higher numbers = higher priority)
    pub priority: i32,
}

/// Trust condition for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustCondition {
    /// Trust score is above the specified threshold
    TrustScoreAbove(f64),
    /// Trust score is below the specified threshold
    TrustScoreBelow(f64),
    /// Device type matches the specified type
    DeviceTypeEquals(DeviceType),
    /// Device location is in the specified list
    LocationIn(Vec<String>),
    /// Device location is not in the specified list
    LocationNotIn(Vec<String>),
    /// IP address is within the specified range
    IpInRange(String, String),
    /// Device has the specified security feature
    HasSecurityFeature(String),
    /// Device does not have the specified security feature
    NoSecurityFeature(String),
    /// This is the first login from this device
    FirstTimeLogin,
    /// Device is known and previously trusted
    KnownDevice,
    /// Device is unknown
    UnknownDevice,
    /// Time since last login exceeds specified minutes
    TimeSinceLastLogin(i64), // minutes
}

/// Action to take when policy matches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustAction {
    /// Allow the access
    Allow,
    /// Deny the access
    Deny,
    /// Require additional authentication challenge
    Challenge(String), // Additional authentication method
    /// Put device in quarantine
    Quarantine,
    /// Notify administrator
    NotifyAdmin,
}

/// Device session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSession {
    /// Unique identifier for the session
    pub id: Uuid,
    /// Device ID associated with the session
    pub device_id: Uuid,
    /// User ID associated with the session
    pub user_id: Uuid,
    /// Session identifier
    pub session_id: String,
    /// When the session started
    pub started_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
    /// IP address of the device during session
    pub ip_address: String,
    /// Geographic location during session
    pub location: Option<DeviceLocation>,
    /// Risk score for the session
    pub risk_score: f64,
    /// Whether the session is currently active
    pub is_active: bool,
}

/// Device management service
pub struct DeviceService {
    /// Database connection
    db: Arc<Database>,
    /// List of active trust policies
    trust_policies: Vec<DeviceTrustPolicy>,
}

impl DeviceService {
    /// Create new device service
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            trust_policies: Vec::new(),
        }
    }

    /// Register a new device
    pub async fn register_device(
        &self,
        user_id: Uuid,
        device_info: DeviceRegistrationRequest,
    ) -> Result<DeviceInfo> {
        let device = DeviceInfo {
            id: Uuid::new_v4(),
            user_id,
            device_name: device_info.device_name.clone(),
            device_type: self.detect_device_type(&device_info.user_agent),
            os: device_info.os.clone(),
            os_version: device_info.os_version.clone(),
            browser: device_info.browser.clone(),
            browser_version: device_info.browser_version.clone(),
            ip_address: device_info.ip_address.clone(),
            user_agent: device_info.user_agent.clone(),
            fingerprint: self.generate_device_fingerprint(&device_info),
            trust_score: self.calculate_initial_trust_score(&device_info),
            is_trusted: false,
            last_seen: Utc::now(),
            created_at: Utc::now(),
            location: None, // Would be populated by geolocation service
            security_features: device_info.security_features.clone(),
        };

        // Store device in database
        self.store_device(&device).await?;

        Ok(device)
    }

    /// Update device information
    pub async fn update_device(&self, device_id: Uuid, updates: DeviceUpdateRequest) -> Result<()> {
        use crate::database::operations::devices;

        if let Some(trust_score) = updates.trust_score {
            let factors = serde_json::json!({
                "manual_update": true,
                "reason": "Administrative update"
            });
            devices::update_trust_score(&self.db, device_id, trust_score, factors).await?;
        }

        // TODO: Implement other update fields (device_name, etc.)
        // Currently only trust score updates are supported
        Ok(())
    }

    /// Get device by ID
    pub async fn get_device(&self, device_id: Uuid) -> Result<Option<DeviceInfo>> {
        use crate::database::operations::devices;

        match devices::get_device_by_id(&self.db, device_id).await? {
            Some(model_device) => {
                // Convert model Device to service DeviceInfo
                let device_info = DeviceInfo {
                    id: model_device.id,
                    user_id: model_device.user_id,
                    device_name: model_device
                        .device_name
                        .unwrap_or_else(|| "Unknown Device".to_string()),
                    device_type: self.detect_device_type(
                        model_device.user_agent.as_ref().unwrap_or(&"".to_string()),
                    ),
                    os: model_device.os.unwrap_or_default(),
                    os_version: model_device.os_version.unwrap_or_default(),
                    browser: model_device.browser,
                    browser_version: model_device.browser_version,
                    ip_address: model_device
                        .ip_address
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "0.0.0.0".to_string()),
                    user_agent: model_device
                        .user_agent
                        .as_ref()
                        .unwrap_or(&"".to_string())
                        .clone(),
                    fingerprint: model_device.device_fingerprint,
                    trust_score: model_device.trust_score,
                    is_trusted: model_device.trust_score > 0.7,
                    last_seen: model_device.last_seen_at,
                    created_at: model_device.created_at,
                    location: model_device
                        .location_data
                        .and_then(|d| serde_json::from_value(d).ok()),
                    security_features: DeviceSecurityFeatures {
                        has_biometrics: false, // TODO: Store in database - requires biometrics detection implementation
                        has_hardware_security: false,
                        has_screen_lock: false,
                        encryption_enabled: false,
                        remote_wipe_capable: false,
                        jailbreak_detected: false,
                    },
                };
                Ok(Some(device_info))
            }
            None => Ok(None),
        }
    }

    /// Get user's devices
    pub async fn get_user_devices(&self, user_id: Uuid) -> Result<Vec<DeviceInfo>> {
        use crate::database::operations::devices;

        let model_devices = devices::list_user_devices(&self.db, user_id).await?;

        let mut service_devices = Vec::new();
        for model_device in model_devices {
            let device_info = DeviceInfo {
                id: model_device.id,
                user_id: model_device.user_id,
                device_name: model_device
                    .device_name
                    .unwrap_or_else(|| "Unknown Device".to_string()),
                device_type: self.detect_device_type(
                    model_device.user_agent.as_ref().unwrap_or(&"".to_string()),
                ),
                os: model_device.os.unwrap_or_default(),
                os_version: model_device.os_version.unwrap_or_default(),
                browser: model_device.browser,
                browser_version: model_device.browser_version,
                ip_address: model_device
                    .ip_address
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "0.0.0.0".to_string()),
                user_agent: model_device
                    .user_agent
                    .as_ref()
                    .unwrap_or(&"".to_string())
                    .clone(),
                fingerprint: model_device.device_fingerprint,
                trust_score: model_device.trust_score,
                is_trusted: model_device.trust_score > 0.7,
                last_seen: model_device.last_seen_at,
                created_at: model_device.created_at,
                location: model_device
                    .location_data
                    .and_then(|d| serde_json::from_value(d).ok()),
                security_features: DeviceSecurityFeatures {
                    has_biometrics: false, // TODO: Store in database - requires biometrics detection implementation
                    has_hardware_security: false,
                    has_screen_lock: false,
                    encryption_enabled: false,
                    remote_wipe_capable: false,
                    jailbreak_detected: false,
                },
            };
            service_devices.push(device_info);
        }

        Ok(service_devices)
    }

    /// Evaluate device trust
    pub async fn evaluate_trust(
        &self,
        device: &DeviceInfo,
        context: &TrustEvaluationContext,
    ) -> Result<TrustResult> {
        let mut risk_score = device.trust_score;
        let mut challenges = Vec::new();
        let mut should_deny = false;

        // Evaluate against trust policies
        for policy in &self.trust_policies {
            if !policy.enabled {
                continue;
            }

            if self
                .evaluate_conditions(&policy.conditions, device, context)
                .await?
            {
                match &policy.action {
                    TrustAction::Allow => {
                        // Policy allows, continue evaluation
                    }
                    TrustAction::Deny => {
                        should_deny = true;
                        break;
                    }
                    TrustAction::Challenge(method) => {
                        challenges.push(method.clone());
                    }
                    TrustAction::Quarantine => {
                        risk_score *= 0.5; // Reduce trust score
                    }
                    TrustAction::NotifyAdmin => {
                        // In production, send notification
                    }
                }
            }
        }

        // Calculate final risk score based on context
        risk_score = self.adjust_risk_score(risk_score, context);

        let result = if should_deny {
            TrustResult::Denied
        } else if !challenges.is_empty() {
            TrustResult::ChallengeRequired(challenges)
        } else if risk_score > 0.7 {
            TrustResult::Trusted
        } else {
            TrustResult::Untrusted
        };

        Ok(result)
    }

    /// Create device session
    pub async fn create_session(
        &self,
        device_id: Uuid,
        user_id: Uuid,
        session_id: String,
        ip_address: String,
    ) -> Result<DeviceSession> {
        let session = DeviceSession {
            id: Uuid::new_v4(),
            device_id,
            user_id,
            session_id,
            started_at: Utc::now(),
            last_activity: Utc::now(),
            ip_address,
            location: None,
            risk_score: 0.5, // Initial risk score
            is_active: true,
        };

        // Store session in database
        self.store_session(&session).await?;

        Ok(session)
    }

    /// Update device session activity
    pub async fn update_session_activity(&self, _session_id: Uuid) -> Result<()> {
        // In production, update last_activity in database
        Ok(())
    }

    /// End device session
    pub async fn end_session(&self, _session_id: Uuid) -> Result<()> {
        // In production, mark session as inactive
        Ok(())
    }

    /// Get device sessions
    pub async fn get_device_sessions(&self, _device_id: Uuid) -> Result<Vec<DeviceSession>> {
        // In production, retrieve from database
        Ok(vec![])
    }

    /// Add trust policy
    pub fn add_trust_policy(&mut self, policy: DeviceTrustPolicy) {
        self.trust_policies.push(policy);
        // Sort by priority
        self.trust_policies
            .sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Remove trust policy
    pub fn remove_trust_policy(&mut self, policy_id: Uuid) {
        self.trust_policies.retain(|p| p.id != policy_id);
    }

    /// Get trust policies
    pub fn get_trust_policies(&self) -> &[DeviceTrustPolicy] {
        &self.trust_policies
    }

    /// Detect device type from user agent
    fn detect_device_type(&self, user_agent: &str) -> DeviceType {
        let ua = user_agent.to_lowercase();
        if ua.contains("mobile") || ua.contains("android") || ua.contains("iphone") {
            DeviceType::Mobile
        } else if ua.contains("tablet") || ua.contains("ipad") {
            DeviceType::Tablet
        } else if ua.contains("iot") || ua.contains("raspberry") {
            DeviceType::IoT
        } else if ua.contains("server") || ua.contains("linux") && ua.contains("headless") {
            DeviceType::Server
        } else {
            DeviceType::Desktop
        }
    }

    /// Generate device fingerprint
    fn generate_device_fingerprint(&self, device_info: &DeviceRegistrationRequest) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();

        hasher.update(&device_info.user_agent);
        hasher.update(&device_info.ip_address);
        hasher.update(&device_info.os);
        hasher.update(&device_info.os_version);

        if let Some(browser) = &device_info.browser {
            hasher.update(browser);
        }

        format!("{:x}", hasher.finalize())
    }

    /// Calculate initial trust score
    fn calculate_initial_trust_score(&self, device_info: &DeviceRegistrationRequest) -> f64 {
        let mut score: f64 = 0.5; // Base score

        // Increase score for known browsers
        if let Some(browser) = &device_info.browser {
            if ["chrome", "firefox", "safari", "edge"].contains(&browser.to_lowercase().as_str()) {
                score += 0.1;
            }
        }

        // Increase score for security features
        if device_info.security_features.has_biometrics {
            score += 0.2;
        }
        if device_info.security_features.has_hardware_security {
            score += 0.2;
        }
        if device_info.security_features.encryption_enabled {
            score += 0.1;
        }

        // Decrease score for potential risks
        if device_info.security_features.jailbreak_detected {
            score -= 0.3;
        }

        score.clamp(0.0, 1.0)
    }

    /// Evaluate trust conditions
    async fn evaluate_conditions(
        &self,
        conditions: &[TrustCondition],
        device: &DeviceInfo,
        context: &TrustEvaluationContext,
    ) -> Result<bool> {
        for condition in conditions {
            let matches = match condition {
                TrustCondition::TrustScoreAbove(threshold) => device.trust_score > *threshold,
                TrustCondition::TrustScoreBelow(threshold) => device.trust_score < *threshold,
                TrustCondition::DeviceTypeEquals(device_type) => {
                    std::mem::discriminant(&device.device_type)
                        == std::mem::discriminant(device_type)
                }
                TrustCondition::LocationIn(countries) => {
                    if let Some(location) = &device.location {
                        location
                            .country
                            .as_ref()
                            .is_some_and(|c| countries.contains(c))
                    } else {
                        false
                    }
                }
                TrustCondition::LocationNotIn(countries) => {
                    if let Some(location) = &device.location {
                        location
                            .country
                            .as_ref()
                            .is_none_or(|c| !countries.contains(c))
                    } else {
                        true
                    }
                }
                TrustCondition::IpInRange(_start, _end) => {
                    // In production, implement IP range checking
                    false
                }
                TrustCondition::HasSecurityFeature(feature) => match feature.as_str() {
                    "biometrics" => device.security_features.has_biometrics,
                    "hardware_security" => device.security_features.has_hardware_security,
                    "screen_lock" => device.security_features.has_screen_lock,
                    "encryption" => device.security_features.encryption_enabled,
                    "remote_wipe" => device.security_features.remote_wipe_capable,
                    _ => false,
                },
                TrustCondition::NoSecurityFeature(feature) => match feature.as_str() {
                    "biometrics" => !device.security_features.has_biometrics,
                    "hardware_security" => !device.security_features.has_hardware_security,
                    "screen_lock" => !device.security_features.has_screen_lock,
                    "encryption" => !device.security_features.encryption_enabled,
                    "remote_wipe" => !device.security_features.remote_wipe_capable,
                    _ => true,
                },
                TrustCondition::FirstTimeLogin => context.is_first_login,
                TrustCondition::KnownDevice => context.known_device,
                TrustCondition::UnknownDevice => !context.known_device,
                TrustCondition::TimeSinceLastLogin(minutes) => {
                    let time_since = Utc::now()
                        .signed_duration_since(device.last_seen)
                        .num_minutes();
                    time_since > *minutes
                }
            };

            if !matches {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Adjust risk score based on context
    fn adjust_risk_score(&self, base_score: f64, context: &TrustEvaluationContext) -> f64 {
        let mut score = base_score;

        // Adjust based on login time patterns
        if context.unusual_time {
            score -= 0.1;
        }

        // Adjust based on location change
        if context.location_changed {
            score -= 0.1;
        }

        // Adjust based on IP reputation
        score += context.ip_reputation * 0.2 - 0.1;

        // Adjust based on device fingerprint match
        if context.fingerprint_match {
            score += 0.1;
        }

        score.clamp(0.0, 1.0)
    }

    // Database operations
    /// Store device information in the database
    async fn store_device(&self, device: &DeviceInfo) -> Result<()> {
        use crate::database::operations::devices;
        use crate::models::device::DeviceInfo as ModelDeviceInfo;

        // Convert service DeviceInfo to model DeviceInfo
        let model_device_info = ModelDeviceInfo {
            device_name: Some(device.device_name.clone()),
            fingerprint: device.fingerprint.clone(),
            os: Some(device.os.clone()),
            os_version: Some(device.os_version.clone()),
            browser: device.browser.clone(),
            browser_version: device.browser_version.clone(),
            ip_address: device.ip_address.parse().ok(),
            user_agent: Some(device.user_agent.clone()),
        };

        devices::register_device(&self.db, device.user_id, &model_device_info).await?;
        Ok(())
    }

    /// Store device session information in the database
    async fn store_session(&self, session: &DeviceSession) -> Result<()> {
        use crate::database::operations as db_ops;

        // Convert location to JSON if present
        let location_json = session.location.as_ref().map(|loc| {
            serde_json::json!({
                "country": loc.country,
                "city": loc.city,
                "latitude": loc.latitude,
                "longitude": loc.longitude
            })
        });

        db_ops::sessions::create_device_session(
            &self.db,
            session.device_id,
            session.user_id,
            None, // user_session_id - could be linked if available
            &session.session_id,
            Some(&session.ip_address),
            location_json,
            session.risk_score,
        )
        .await?;

        Ok(())
    }
}

/// Device registration request
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceRegistrationRequest {
    /// Human-readable name for the device
    pub device_name: String,
    /// Operating system name (e.g., "Windows", "macOS", "Linux")
    pub os: String,
    /// Operating system version
    pub os_version: String,
    /// Browser name if applicable (e.g., "Chrome", "Firefox")
    pub browser: Option<String>,
    /// Browser version if applicable
    pub browser_version: Option<String>,
    /// IP address of the device during registration
    pub ip_address: String,
    /// Full user agent string from the device
    pub user_agent: String,
    /// Security features detected on the device
    pub security_features: DeviceSecurityFeatures,
}

/// Device update request
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceUpdateRequest {
    /// Optional new name for the device
    pub device_name: Option<String>,
    /// Optional updated trust score (0.0 to 1.0)
    pub trust_score: Option<f64>,
    /// Optional trust status override
    pub is_trusted: Option<bool>,
    /// Optional updated security features
    pub security_features: Option<DeviceSecurityFeatures>,
}

/// Trust evaluation context
#[derive(Debug, Serialize, Deserialize)]
pub struct TrustEvaluationContext {
    /// Whether this is the first login for this user
    pub is_first_login: bool,
    /// Whether this device has been seen before
    pub known_device: bool,
    /// Whether the login time is unusual for this user
    pub unusual_time: bool,
    /// Whether the login location has changed significantly
    pub location_changed: bool,
    /// IP reputation score (0.0 to 1.0, higher is better)
    pub ip_reputation: f64,
    /// Whether the device fingerprint matches known patterns
    pub fingerprint_match: bool,
}

/// Trust evaluation result
#[derive(Debug, Serialize, Deserialize)]
pub enum TrustResult {
    /// Device is trusted and login can proceed
    Trusted,
    /// Device is untrusted but login may still be allowed with additional verification
    Untrusted,
    /// Additional challenges are required before login can proceed
    ChallengeRequired(Vec<String>),
    /// Login is denied for this device
    Denied,
}
