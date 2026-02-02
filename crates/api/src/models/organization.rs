use crate::error::{AuthencError, Result};
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

/// Organization roles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OrganizationRole {
    /// Owner of the organization with full administrative privileges
    Owner,
    /// Administrator with elevated privileges
    Admin,
    /// Regular member with standard access
    Member,
    /// Guest with limited access
    Guest,
}

impl OrganizationRole {
    /// Convert the role to its string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            OrganizationRole::Owner => "OWNER",
            OrganizationRole::Admin => "ADMIN",
            OrganizationRole::Member => "MEMBER",
            OrganizationRole::Guest => "GUEST",
        }
    }

    /// Parse a string into an OrganizationRole
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "OWNER" => Some(OrganizationRole::Owner),
            "ADMIN" => Some(OrganizationRole::Admin),
            "MEMBER" => Some(OrganizationRole::Member),
            "GUEST" => Some(OrganizationRole::Guest),
            _ => None,
        }
    }
}

impl std::str::FromStr for OrganizationRole {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse(s).ok_or(())
    }
}
