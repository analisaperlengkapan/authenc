use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

pub fn deserialize_optional_nullable<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let value: Option<T> = Option::deserialize(deserializer)?;
    Ok(Some(value))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub email_verified: bool,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone_number: Option<String>,
    pub phone_verified: bool,
    #[serde(default)]
    pub totp_enabled: bool,
    pub webauthn_enabled: bool,
    pub account_locked: bool,
    pub last_login_at: Option<String>,
    pub realm_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub require_password_change: bool,
    pub attributes: Option<serde_json::Value>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<Option<Uuid>>,
    pub attributes: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone_number: Option<String>,
    pub enabled: Option<bool>,
    pub realm_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RealmResponse {
    pub id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub registration_allowed: bool,
    pub verify_email: bool,
    pub reset_password_allowed: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRealmRequest {
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRealmRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub registration_allowed: Option<bool>,
    pub verify_email: Option<bool>,
    pub reset_password_allowed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub realm_id: Option<Uuid>,
    pub composite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientResponse {
    pub client_id: String,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateClientRequest {
    pub client_id: String,
    pub name: String,
    pub client_secret: String,
    pub redirect_uris: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateClientRequest {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub redirect_uris: Option<Vec<String>>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub path: String,
    pub description: Option<String>,
    pub member_count: i64,
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
pub struct IdentityProviderResponse {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub provider_type: String,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub realm_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIdentityProviderRequest {
    pub name: String,
    pub display_name: String,
    pub provider_type: String,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub realm_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub domain: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateOrganizationRequest {
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListOrganizationsResponse {
    pub success: bool,
    pub organizations: Vec<Organization>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrganizationMember {
    pub user_id: String,
    pub role: String,
    pub joined_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationMembersResponse {
    pub success: bool,
    pub members: Vec<OrganizationMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrganizationSettings {
    pub organization_id: String,
    pub allow_public_signup: bool,
    pub require_email_verification: bool,
    pub enable_two_factor: bool,
    pub password_policy: String,
    pub session_timeout: u64,
    pub max_users: Option<i32>,
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationSettingsResponse {
    pub success: bool,
    pub settings: OrganizationSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebauthnCredential {
    pub id: String,
    pub name: Option<String>,
    pub created_at: String,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyResponse {
    pub id: Uuid,
    pub name: String,
    pub policy_type: String,
    pub logic: String,
    pub enabled: bool,
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub description: Option<String>,
    pub policy_type: String,
    pub logic: String,
    pub config: serde_json::Value,
    pub enabled: bool,
    pub realm_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PermissionResponse {
    pub id: Uuid,
    pub name: String,
    pub resource_id: String,
    pub scopes: Vec<String>,
    pub policies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePermissionRequest {
    pub name: String,
    pub description: Option<String>,
    pub resource: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityStats {
    pub active_sessions: u64,
    pub trusted_devices: u64,
    pub risky_sessions: u64,
    pub compliance_rate: f64,
}
