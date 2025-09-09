use crate::database::Database;
use crate::error::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

/// Device information and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_name: String,
    pub device_type: DeviceType,
    pub os: String,
    pub os_version: String,
    pub browser: Option<String>,
    pub browser_version: Option<String>,
    pub ip_address: String,
    pub user_agent: String,
    pub fingerprint: String,
    pub trust_score: f64,
    pub is_trusted: bool,
    pub last_seen: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub location: Option<DeviceLocation>,
    pub security_features: DeviceSecurityFeatures,
}

/// Device type classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeviceType {
    Desktop,
    Mobile,
    Tablet,
    IoT,
    Server,
    Unknown,
}

/// Device location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceLocation {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

/// Device security features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSecurityFeatures {
    pub has_biometrics: bool,
    pub has_hardware_security: bool,
    pub has_screen_lock: bool,
    pub encryption_enabled: bool,
    pub remote_wipe_capable: bool,
    pub jailbreak_detected: bool,
}

/// Device trust policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTrustPolicy {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub conditions: Vec<TrustCondition>,
    pub action: TrustAction,
    pub enabled: bool,
    pub priority: i32,
}

/// Trust condition for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustCondition {
    TrustScoreAbove(f64),
    TrustScoreBelow(f64),
    DeviceTypeEquals(DeviceType),
    LocationIn(Vec<String>),
    LocationNotIn(Vec<String>),
    IpInRange(String, String),
    HasSecurityFeature(String),
    NoSecurityFeature(String),
    FirstTimeLogin,
    KnownDevice,
    UnknownDevice,
    TimeSinceLastLogin(i64), // minutes
}

/// Action to take when policy matches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrustAction {
    Allow,
    Deny,
    Challenge(String), // Additional authentication method
    Quarantine,
    NotifyAdmin,
}

/// Device session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSession {
    pub id: Uuid,
    pub device_id: Uuid,
    pub user_id: Uuid,
    pub session_id: String,
    pub started_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub ip_address: String,
    pub location: Option<DeviceLocation>,
    pub risk_score: f64,
    pub is_active: bool,
}

/// Device management service
pub struct DeviceService {
    db: Arc<Database>,
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
                    device_name: model_device.device_name.unwrap_or_else(|| "Unknown Device".to_string()),
                    device_type: self.detect_device_type(&model_device.user_agent.as_ref().unwrap_or(&"".to_string())),
                    os: model_device.os.unwrap_or_default(),
                    os_version: model_device.os_version.unwrap_or_default(),
                    browser: model_device.browser,
                    browser_version: model_device.browser_version,
                    ip_address: model_device.ip_address.unwrap_or_default(),
                    user_agent: model_device.user_agent.as_ref().unwrap_or(&"".to_string()).clone(),
                    fingerprint: model_device.device_fingerprint,
                    trust_score: model_device.trust_score,
                    is_trusted: model_device.trust_score > 0.7,
                    last_seen: model_device.last_seen_at,
                    created_at: model_device.created_at,
                    location: None, // TODO: Parse from location_data JSON
                    security_features: DeviceSecurityFeatures {
                        has_biometrics: false, // TODO: Store in database
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
                device_name: model_device.device_name.unwrap_or_else(|| "Unknown Device".to_string()),
                device_type: self.detect_device_type(&model_device.user_agent.as_ref().unwrap_or(&"".to_string())),
                os: model_device.os.unwrap_or_default(),
                os_version: model_device.os_version.unwrap_or_default(),
                browser: model_device.browser,
                browser_version: model_device.browser_version,
                ip_address: model_device.ip_address.unwrap_or_default(),
                user_agent: model_device.user_agent.as_ref().unwrap_or(&"".to_string()).clone(),
                fingerprint: model_device.device_fingerprint,
                trust_score: model_device.trust_score,
                is_trusted: model_device.trust_score > 0.7,
                last_seen: model_device.last_seen_at,
                created_at: model_device.created_at,
                location: None, // TODO: Parse from location_data JSON
                security_features: DeviceSecurityFeatures {
                    has_biometrics: false, // TODO: Store in database
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
    pub async fn update_session_activity(&self, session_id: Uuid) -> Result<()> {
        // In production, update last_activity in database
        Ok(())
    }

    /// End device session
    pub async fn end_session(&self, session_id: Uuid) -> Result<()> {
        // In production, mark session as inactive
        Ok(())
    }

    /// Get device sessions
    pub async fn get_device_sessions(&self, device_id: Uuid) -> Result<Vec<DeviceSession>> {
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

        score.max(0.0).min(1.0)
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
                            .map_or(false, |c| countries.contains(c))
                    } else {
                        false
                    }
                }
                TrustCondition::LocationNotIn(countries) => {
                    if let Some(location) = &device.location {
                        location
                            .country
                            .as_ref()
                            .map_or(true, |c| !countries.contains(c))
                    } else {
                        true
                    }
                }
                TrustCondition::IpInRange(start, end) => {
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
                    time_since > *minutes as i64
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

        score.max(0.0).min(1.0)
    }

    // Database operations
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

    async fn store_session(&self, session: &DeviceSession) -> Result<()> {
        // TODO: Implement session storage in database
        // For now, this is a placeholder
        Ok(())
    }
}

/// Device registration request
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceRegistrationRequest {
    pub device_name: String,
    pub os: String,
    pub os_version: String,
    pub browser: Option<String>,
    pub browser_version: Option<String>,
    pub ip_address: String,
    pub user_agent: String,
    pub security_features: DeviceSecurityFeatures,
}

/// Device update request
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceUpdateRequest {
    pub device_name: Option<String>,
    pub trust_score: Option<f64>,
    pub is_trusted: Option<bool>,
    pub security_features: Option<DeviceSecurityFeatures>,
}

/// Trust evaluation context
#[derive(Debug, Serialize, Deserialize)]
pub struct TrustEvaluationContext {
    pub is_first_login: bool,
    pub known_device: bool,
    pub unusual_time: bool,
    pub location_changed: bool,
    pub ip_reputation: f64, // 0.0 to 1.0
    pub fingerprint_match: bool,
}

/// Trust evaluation result
#[derive(Debug, Serialize, Deserialize)]
pub enum TrustResult {
    Trusted,
    Untrusted,
    ChallengeRequired(Vec<String>),
    Denied,
}
