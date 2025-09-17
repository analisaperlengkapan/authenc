use crate::error::Result;
use crate::AuthencError;
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
    pub ip_address: Option<String>,
    /// User agent string from the browser
    pub user_agent: Option<String>,
    /// Location data associated with the device as JSON
    pub location_data: Option<serde_json::Value>,
    /// Timestamp when the device was last seen
    pub last_seen_at: DateTime<Utc>,
    /// Timestamp when the device was first seen
    pub first_seen_at: DateTime<Utc>,
    /// Timestamp when the device was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the device was last updated
    pub updated_at: DateTime<Utc>,
}

impl TryFrom<tokio_postgres::Row> for Device {
    type Error = AuthencError;

    fn try_from(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            device_name: row.try_get("device_name")?,
            device_fingerprint: row.try_get("device_fingerprint")?,
            trust_score: row.try_get("trust_score")?,
            risk_level: row.try_get("risk_level")?,
            os: row.try_get("os")?,
            os_version: row.try_get("os_version")?,
            browser: row.try_get("browser")?,
            browser_version: row.try_get("browser_version")?,
            ip_address: row.try_get("ip_address")?,
            user_agent: row.try_get("user_agent")?,
            location_data: {
                let json_str: Option<String> = row.try_get("location_data")?;
                json_str.and_then(|s| serde_json::from_str(&s).ok())
            },
            last_seen_at: row.try_get("last_seen_at")?,
            first_seen_at: row.try_get("first_seen_at")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
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
