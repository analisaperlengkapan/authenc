use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub timestamp: DateTime<Utc>,
    pub event: String,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub status: String,
    pub detail: Option<String>,
}
