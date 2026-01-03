use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Policy entity for authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Unique identifier for the policy
    pub id: Uuid,
    /// Name of the policy
    pub name: String,
    /// Description of the policy
    pub description: Option<String>,
    /// Type of the policy (e.g., user, role, time, etc.)
    pub policy_type: String,
    /// Logic used by the policy (POSITIVE, NEGATIVE, etc.)
    pub logic: String,
    /// Configuration for the policy
    pub config: serde_json::Value,
    /// Whether the policy is enabled
    pub enabled: bool,
    /// ID of the realm the policy belongs to
    pub realm_id: Uuid,
    /// Timestamp when the policy was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the policy was last updated
    pub updated_at: DateTime<Utc>,
}
