use crate::AuthencError;
use crate::error::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// Device information for registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Human-readable name for the device
    pub device_name: Option<String>,
    /// Unique fingerprint identifying the device
    pub fingerprint: String,
    /// Operating system name
    pub os: Option<String>,
    /// Operating system version
    pub os_version: Option<String>,
    /// Browser name
    pub browser: Option<String>,
    /// Browser version
    pub browser_version: Option<String>,
    /// IP address of the device
    pub ip_address: Option<IpAddr>,
    /// User agent string from the browser
    pub user_agent: Option<String>,
    /// Security features available on the device
    pub security_features: Option<serde_json::Value>,
    /// Location data associated with the device as JSON
    pub location_data: Option<serde_json::Value>,
    /// Initial trust score for the device
    pub trust_score: Option<f64>,
}

/// Device model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// Unique identifier for the device
    pub id: Uuid,
    /// ID of the user this device belongs to
    pub user_id: Uuid,
    /// Human-readable name for the device
    pub device_name: Option<String>,
    /// Unique fingerprint identifying the device
    pub device_fingerprint: String,
    /// Trust score for the device (0.0 to 1.0)
    pub trust_score: f64,
    /// Risk level assessment ("low", "medium", "high")
    pub risk_level: String,
    /// Operating system name
    pub os: Option<String>,
    /// Operating system version
    pub os_version: Option<String>,
    /// Browser name
    pub browser: Option<String>,
    /// Browser version
    pub browser_version: Option<String>,
    /// IP address of the device
    pub ip_address: Option<IpAddr>,
    /// User agent string from the browser
    pub user_agent: Option<String>,
    /// Location data associated with the device as JSON
    pub location_data: Option<serde_json::Value>,
    /// Security features available on the device as JSON
    pub security_features: Option<serde_json::Value>,
    /// Timestamp when the device was last seen
    pub last_seen_at: DateTime<Utc>,
    /// Timestamp when the device was first seen
    pub first_seen_at: DateTime<Utc>,
    /// Timestamp when the device was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the device was last updated
    pub updated_at: DateTime<Utc>,
}


/// Trust evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustResult {
    /// Overall trust score (0.0 to 1.0)
    pub score: f64,
    /// List of trust evaluation factors
    pub factors: Vec<TrustFactor>,
    /// Risk level assessment ("low", "medium", "high")
    pub risk_level: String,
    /// List of security recommendations
    pub recommendations: Vec<String>,
}

/// Trust evaluation factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustFactor {
    /// Name of the trust factor
    pub name: String,
    /// Score contribution of this factor (0.0 to 1.0)
    pub score: f64,
    /// Weight of this factor in the overall calculation
    pub weight: f64,
    /// Description of the trust factor
    pub description: String,
}
