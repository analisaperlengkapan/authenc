use authenc_core::error::{AuthencError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Organization model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    /// Unique identifier for the organization
    pub id: Uuid,
    /// Name of the organization (must be unique within realm)
    pub name: String,
    /// Display name for the organization
    pub display_name: Option<String>,
    /// Description of the organization
    pub description: Option<String>,
    /// Domain associated with the organization
    pub domain: Option<String>,
    /// URL to the organization's logo
    pub logo_url: Option<String>,
    /// URL to the organization's website
    pub website_url: Option<String>,
    /// ID of the user who owns this organization
    pub owner_id: Uuid,
    /// ID of the realm this organization belongs to
    pub realm_id: Option<Uuid>,
    /// Whether the organization is enabled
    pub enabled: bool,
    /// Timestamp when the organization was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the organization was last updated
    pub updated_at: DateTime<Utc>,
    /// Timestamp when the organization was soft deleted
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Organization member model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationMember {
    /// Unique identifier for the organization membership
    pub id: Uuid,
    /// ID of the organization
    pub organization_id: Uuid,
    /// ID of the user who is a member
    pub user_id: Uuid,
    /// Role of the member in the organization
    pub role: String,
    /// ID of the user who invited this member
    pub invited_by: Option<Uuid>,
    /// Timestamp when the invitation was sent
    pub invited_at: Option<DateTime<Utc>>,
    /// Timestamp when the user joined the organization
    pub joined_at: Option<DateTime<Utc>>,
    /// Timestamp when the membership was created
    pub created_at: DateTime<Utc>,
    /// Timestamp when the membership was last updated
    pub updated_at: DateTime<Utc>,
}

/// Organization invitation model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationInvitation {
    /// Unique identifier for the invitation
    pub id: Uuid,
    /// ID of the organization being invited to
    pub organization_id: Uuid,
    /// Email address of the invited user
    pub email: String,
    /// Role to assign to the user upon acceptance
    pub role: String,
    /// ID of the user who sent the invitation
    pub invited_by: Uuid,
    /// Hash of the invitation token
    pub token_hash: String,
    /// Timestamp when the invitation expires
    pub expires_at: DateTime<Utc>,
    /// Timestamp when the invitation was accepted
    pub accepted_at: Option<DateTime<Utc>>,
    /// ID of the user who accepted the invitation
    pub accepted_by: Option<Uuid>,
    /// Timestamp when the invitation was created
    pub created_at: DateTime<Utc>,
}

impl TryFrom<tokio_postgres::Row> for Organization {
    type Error = AuthencError;

    fn try_from(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            display_name: row.try_get("display_name")?,
            description: row.try_get("description")?,
            domain: row.try_get("domain")?,
            logo_url: row.try_get("logo_url")?,
            website_url: row.try_get("website_url")?,
            owner_id: row.try_get("owner_id")?,
            realm_id: row.try_get("realm_id")?,
            enabled: row.try_get("enabled")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            deleted_at: row.try_get("deleted_at")?,
        })
    }
}

impl TryFrom<tokio_postgres::Row> for OrganizationInvitation {
    type Error = AuthencError;

    fn try_from(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            organization_id: row.try_get("organization_id")?,
            email: row.try_get("email")?,
            role: row.try_get("role")?,
            invited_by: row.try_get("invited_by")?,
            token_hash: row.try_get("token_hash")?,
            expires_at: row.try_get("expires_at")?,
            accepted_at: row.try_get("accepted_at")?,
            accepted_by: row.try_get("accepted_by")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

impl TryFrom<tokio_postgres::Row> for OrganizationMember {
    type Error = AuthencError;

    fn try_from(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Self {
            id: row.try_get("id")?,
            organization_id: row.try_get("organization_id")?,
            user_id: row.try_get("user_id")?,
            role: row.try_get("role")?,
            invited_by: row.try_get("invited_by")?,
            invited_at: row.try_get("invited_at")?,
            joined_at: row.try_get("joined_at")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

/// Organization creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOrganizationRequest {
    /// Name of the organization to create
    pub name: String,
    /// Display name for the organization
    pub display_name: Option<String>,
    /// Description of the organization
    pub description: Option<String>,
    /// Domain associated with the organization
    pub domain: Option<String>,
}

/// Organization member invitation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteMemberRequest {
    /// Email address of the user to invite
    pub email: String,
    /// Role to assign to the invited user
    pub role: String,
}

/// Organization settings model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationSettings {
    /// ID of the organization these settings apply to
    pub organization_id: Uuid,
    /// Whether public signup is allowed for this organization
    pub allow_public_signup: bool,
    /// Whether email verification is required for new users
    pub require_email_verification: bool,
    /// Whether two-factor authentication is enabled
    pub enable_two_factor: bool,
    /// Password policy rules for the organization
    pub password_policy: String,
    /// Session timeout in seconds
    pub session_timeout: u64,
    /// Maximum number of users allowed in the organization
    pub max_users: Option<u32>,
    /// List of enabled features for the organization
    pub features: Vec<String>,
}

impl TryFrom<tokio_postgres::Row> for OrganizationSettings {
    type Error = AuthencError;

    fn try_from(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Self {
            organization_id: row.try_get("organization_id")?,
            allow_public_signup: row.try_get("allow_public_signup")?,
            require_email_verification: row.try_get("require_email_verification")?,
            enable_two_factor: row.try_get("enable_two_factor")?,
            password_policy: row.try_get("password_policy")?,
            session_timeout: row.try_get::<_, i64>("session_timeout")? as u64,
            max_users: row.try_get::<_, Option<i32>>("max_users")?.map(|n| n as u32),
            features: row.try_get("features")?,
        })
    }
}
