use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone_number: Option<String>,
    pub phone_verified: bool,
    pub webauthn_enabled: bool,
    pub account_locked: bool,
    pub last_login_at: Option<String>,
    pub realm_id: Option<String>,
    pub organization_id: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone_number: Option<String>,
    pub enabled: Option<bool>,
    pub email_verified: Option<bool>,
    pub phone_verified: Option<bool>,
    pub require_password_change: Option<bool>,
    pub attributes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSetupRequest {
    pub user_label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub qr_code_uri: String,
    pub user_label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpStatusResponse {
    pub enabled: bool,
    pub configured_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyTotpSetupRequest {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub path: String,
    pub parent_id: Option<String>,
    pub description: Option<String>,
    pub member_count: i64,
    pub subgroup_count: i64,
    pub realm_id: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub realm_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGroupRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditLog {
    pub timestamp: String,
    pub event: String,
    pub user_id: Option<String>,
    pub client_id: Option<String>,
    pub status: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogResponse {
    pub total: u64,
    pub logs: Vec<AuditLog>,
}
