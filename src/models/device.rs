use crate::error::Result;
use crate::AuthencError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// Device information for registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_name: Option<String>,
    pub fingerprint: String,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub browser: Option<String>,
    pub browser_version: Option<String>,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
}

/// Device model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_name: Option<String>,
    pub device_fingerprint: String,
    pub trust_score: f64,
    pub risk_level: String,
    pub os: Option<String>,
    pub os_version: Option<String>,
    pub browser: Option<String>,
    pub browser_version: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub location_data: Option<serde_json::Value>,
    pub last_seen_at: DateTime<Utc>,
    pub first_seen_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
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
    pub score: f64,
    pub factors: Vec<TrustFactor>,
    pub risk_level: String,
    pub recommendations: Vec<String>,
}

/// Trust evaluation factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustFactor {
    pub name: String,
    pub score: f64,
    pub weight: f64,
    pub description: String,
}
