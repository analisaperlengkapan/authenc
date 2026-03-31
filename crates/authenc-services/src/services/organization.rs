use authenc_database::database::Database;
use authenc_core::error::{AuthencError, Result};
use authenc_models::models::organization::{
    Organization, OrganizationInvitation as ModelOrganizationInvitation, OrganizationMember,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

// Organization represents a tenant/organization in the system
// Using the model Organization for now
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct Organization {
//     /// Unique identifier for the organization
//     pub id: Uuid,
//     /// Internal name of the organization (used for identification)
//     pub name: String,
//     /// Display name of the organization (shown to users)
//     pub display_name: String,
//     /// Optional description of the organization
//     pub description: Option<String>,
//     /// Domain associated with the organization
//     pub domain: Option<String>,
//     /// URL to the organization's logo
//     pub logo_url: Option<String>,
//     /// Website URL of the organization
//     pub website: Option<String>,
//     /// Whether the organization is enabled/active
//     pub enabled: bool,
//     /// Timestamp when the organization was created
//     pub created_at: chrono::DateTime<chrono::Utc>,
//     /// Timestamp when the organization was last updated
//     pub updated_at: chrono::DateTime<chrono::Utc>,
//     /// Additional attributes for the organization
//     pub attributes: HashMap<String, String>,
// }

// Organization member with role
// Using the model OrganizationMember for now
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct OrganizationMember {
//     /// ID of the user who is a member
//     pub user_id: Uuid,
//     /// ID of the organization
//     pub organization_id: Uuid,
//     /// Role of the member in the organization
//     pub role: OrganizationRole,
//     /// Timestamp when the user joined the organization
//     pub joined_at: chrono::DateTime<chrono::Utc>,
//     /// ID of the user who invited this member
//     pub invited_by: Option<Uuid>,
// }

/// Organization roles
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
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
            OrganizationRole::Owner => "owner",
            OrganizationRole::Admin => "admin",
            OrganizationRole::Member => "member",
            OrganizationRole::Guest => "guest",
        }
    }

    /// Parse a string into an OrganizationRole
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "owner" => Some(OrganizationRole::Owner),
            "admin" => Some(OrganizationRole::Admin),
            "member" => Some(OrganizationRole::Member),
            "guest" => Some(OrganizationRole::Guest),
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

/// Organization invitation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationInvitation {
    /// Unique identifier for the invitation
    pub id: Uuid,
    /// ID of the organization being invited to
    pub organization_id: Uuid,
    /// Email address of the invited user
    pub email: String,
    /// Role to be assigned to the user upon acceptance
    pub role: OrganizationRole,
    /// ID of the user who sent the invitation
    pub invited_by: Uuid,
    /// Timestamp when the invitation was sent
    pub invited_at: chrono::DateTime<chrono::Utc>,
    /// Timestamp when the invitation expires
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Timestamp when the invitation was accepted
    pub accepted_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Unique token for the invitation
    pub token: String,
}

/// Organization settings
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

/// Organization service for multi-tenancy
pub struct OrganizationService {
    #[allow(dead_code)]
    db: Arc<Database>,
}

impl OrganizationService {
    /// Create new organization service
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Create a new organization
    pub async fn create_organization(
        &self,
        name: &str,
        display_name: &str,
        description: Option<&str>,
        created_by: Uuid,
        domain: Option<&str>,
    ) -> Result<Organization> {
        let org_name = name.to_string();
        let org_display_name = display_name.to_string();
        let org_description = description.map(|s| s.to_string());
        let org_domain = domain.map(|s| s.to_string());
        let role_str = OrganizationRole::Owner.as_str().to_string();

        self.db
            .with_transaction(move |client| {
                Box::pin(async move {
                    let now = chrono::Utc::now();
                    let org_id = Uuid::new_v4();

                    // Insert organization
                    let org_query = r#"
                        INSERT INTO organizations (
                            id, name, display_name, description, domain,
                            logo_url, website_url, owner_id, realm_id,
                            enabled, created_at, updated_at
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                        RETURNING
                            id, name, display_name, description, domain,
                            logo_url, website_url, owner_id, realm_id,
                            enabled, created_at, updated_at, deleted_at
                    "#;

                    let row = client
                        .query_one(
                            org_query,
                            &[
                                &org_id,
                                &org_name,
                                &Some(org_display_name),
                                &org_description,
                                &org_domain,
                                &None::<String>,  // logo_url
                                &None::<String>,  // website_url
                                &created_by,      // owner_id
                                &None::<Uuid>,    // realm_id
                                &true,            // enabled
                                &now,
                                &now,
                            ],
                        )
                        .await
                        .map_err(|e| {
                            AuthencError::database(format!(
                                "Failed to create organization: {}",
                                e
                            ))
                        })?;

                    let organization = Organization {
                        id: row.get(0),
                        name: row.get(1),
                        display_name: row.get(2),
                        description: row.get(3),
                        domain: row.get(4),
                        logo_url: row.get(5),
                        website_url: row.get(6),
                        owner_id: row.get(7),
                        realm_id: row.get(8),
                        enabled: row.get(9),
                        created_at: row.get(10),
                        updated_at: row.get(11),
                        deleted_at: row.get(12),
                    };

                    // Add creator as owner member
                    let member_id = Uuid::new_v4();
                    let member_query = r#"
                        INSERT INTO organization_members (
                            id, organization_id, user_id, role, invited_by,
                            invited_at, joined_at, created_at, updated_at
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    "#;

                    client
                        .execute(
                            member_query,
                            &[
                                &member_id,
                                &organization.id,
                                &created_by,
                                &role_str,
                                &Some(created_by),
                                &now,
                                &now,
                                &now,
                                &now,
                            ],
                        )
                        .await
                        .map_err(|e| {
                            AuthencError::database(format!(
                                "Failed to add owner member: {}",
                                e
                            ))
                        })?;

                    Ok(organization)
                })
            })
            .await
    }

    /// List all organizations
    pub async fn list_organizations(&self) -> Result<Vec<Organization>> {
        authenc_database::database::operations::organizations::list_all_organizations(&self.db)
            .await
            .map_err(|e| AuthencError::database(format!("Failed to list organizations: {}", e)))
    }

    /// Get organization by ID
    pub async fn get_organization(&self, organization_id: &Uuid) -> Result<Option<Organization>> {
        authenc_database::database::operations::organizations::get_organization_by_id(
            &self.db,
            *organization_id,
        )
        .await
        .map_err(|e| AuthencError::database(format!("Failed to get organization: {}", e)))
    }

    /// Get organization by domain
    pub async fn get_organization_by_domain(&self, domain: &str) -> Result<Option<Organization>> {
        authenc_database::database::operations::organizations::get_organization_by_domain(&self.db, domain)
            .await
            .map_err(|e| {
                AuthencError::database(format!("Failed to get organization by domain: {}", e))
            })
    }

    /// Update organization
    pub async fn update_organization(
        &self,
        organization_id: &Uuid,
        updates: &OrganizationUpdate,
    ) -> Result<()> {
        let mut org = self.get_organization(organization_id)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("Organization not found"))?;

        if let Some(name) = &updates.name {
            org.name = name.clone();
        }
        if let Some(display_name) = &updates.display_name {
            org.display_name = Some(display_name.clone());
        }
        if let Some(description) = &updates.description {
            org.description = Some(description.clone());
        }
        if let Some(domain) = &updates.domain {
            org.domain = Some(domain.clone());
        }
        if let Some(logo_url) = &updates.logo_url {
            org.logo_url = Some(logo_url.clone());
        }
        if let Some(website) = &updates.website {
            org.website_url = Some(website.clone());
        }
        if let Some(enabled) = updates.enabled {
            org.enabled = enabled;
        }

        org.updated_at = chrono::Utc::now();

        authenc_database::database::operations::organizations::update_organization(&self.db, &org)
            .await
            .map_err(|e| AuthencError::database(format!("Failed to update organization: {}", e)))
    }

    /// Delete organization
    pub async fn delete_organization(&self, organization_id: &Uuid) -> Result<()> {
        authenc_database::database::operations::organizations::delete_organization(&self.db, organization_id)
            .await
            .map_err(|e| AuthencError::database(format!("Failed to delete organization: {}", e)))
    }

    /// Add member to organization
    pub async fn add_member(
        &self,
        organization_id: &Uuid,
        user_id: &Uuid,
        role: OrganizationRole,
        invited_by: Option<Uuid>,
    ) -> Result<()> {
        let member = OrganizationMember {
            id: Uuid::new_v4(),
            user_id: *user_id,
            organization_id: *organization_id,
            role: role.as_str().to_string(),
            invited_by,
            invited_at: None,
            joined_at: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        // Store member in database
        self.store_member(&member).await?;
        Ok(())
    }

    /// Remove member from organization
    pub async fn remove_member(&self, organization_id: &Uuid, user_id: &Uuid) -> Result<()> {
        authenc_database::database::operations::organizations::remove_organization_member(
            &self.db,
            organization_id,
            user_id,
        )
        .await
        .map_err(|e| AuthencError::database(format!("Failed to remove member: {}", e)))
    }

    /// Update member role
    pub async fn update_member_role(
        &self,
        organization_id: &Uuid,
        user_id: &Uuid,
        new_role: OrganizationRole,
    ) -> Result<()> {
        let role_str = new_role.as_str();
        // The database operation expects &str for role
        let query = r#"
            UPDATE organization_members
            SET role = $3, updated_at = NOW()
            WHERE organization_id = $1 AND user_id = $2
        "#;

        let rows_affected = self.db.execute(query, &[organization_id, user_id, &role_str])
            .await
            .map_err(|e| AuthencError::database(format!("Failed to update member role: {}", e)))?;
        if rows_affected == 0 {
            return Err(AuthencError::resource_not_found("Member not found in organization"));
        }
        Ok(())
    }

    /// Get organization members
    pub async fn get_members(&self, organization_id: &Uuid) -> Result<Vec<OrganizationMember>> {
        authenc_database::database::operations::organizations::get_organization_members(
            &self.db,
            organization_id,
        )
        .await
        .map_err(|e| AuthencError::database(format!("Failed to get members: {}", e)))
    }

    /// Check if user is member of organization
    pub async fn is_member(&self, organization_id: &Uuid, user_id: &Uuid) -> Result<bool> {
        let query = r#"
            SELECT COUNT(*) FROM organization_members
            WHERE organization_id = $1 AND user_id = $2
        "#;
        let count: i64 = self.db.query_one(query, &[organization_id, user_id])
            .await
            .map_err(|e| AuthencError::database(format!("Failed to check membership: {}", e)))?
            .get(0);
        Ok(count > 0)
    }

    /// Check if user has role in organization
    pub async fn has_role(
        &self,
        organization_id: &Uuid,
        user_id: &Uuid,
        role: &OrganizationRole,
    ) -> Result<bool> {
        let role_str = role.as_str();
        let query = r#"
            SELECT COUNT(*) FROM organization_members
            WHERE organization_id = $1 AND user_id = $2 AND role = $3
        "#;
        let count: i64 = self.db.query_one(query, &[organization_id, user_id, &role_str])
            .await
            .map_err(|e| AuthencError::database(format!("Failed to check role: {}", e)))?
            .get(0);
        Ok(count > 0)
    }

    /// Create invitation
    pub async fn create_invitation(
        &self,
        organization_id: &Uuid,
        email: &str,
        role: OrganizationRole,
        invited_by: Uuid,
        expires_in_days: u32,
    ) -> Result<OrganizationInvitation> {
        // Validate expires_in_days to prevent chrono DateTime overflow panic.
        // Cap at 365 days (1 year) which is a reasonable maximum for invitations.
        if expires_in_days == 0 || expires_in_days > 365 {
            return Err(AuthencError::validation(
                "expires_in_days must be between 1 and 365",
            ));
        }

        let mut invitation = OrganizationInvitation {
            id: Uuid::new_v4(),
            organization_id: *organization_id,
            email: email.to_string(),
            role,
            invited_by,
            invited_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::days(expires_in_days as i64),
            accepted_at: None,
            token: self.generate_invitation_token(),
        };

        // Store invitation in database (DB generates the actual ID)
        let db_id = self.store_invitation(&invitation).await?;
        invitation.id = db_id;
        Ok(invitation)
    }

    /// Accept invitation
    pub async fn accept_invitation(
        &self,
        token: &str,
        user_id: Uuid,
        expected_organization_id: &Uuid,
    ) -> Result<Organization> {
        // Find invitation by token
        let invitation = self
            .get_invitation_by_token(token)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("Invitation not found or expired"))?;

        // Validate that the invitation belongs to the expected organization
        if invitation.organization_id != *expected_organization_id {
            return Err(AuthencError::validation(
                "Invitation does not belong to the specified organization",
            ));
        }

        // Check if expired
        if invitation.expires_at < chrono::Utc::now() {
            return Err(AuthencError::validation("Invitation has expired"));
        }

        // Check if already accepted
        if invitation.accepted_at.is_some() {
            return Err(AuthencError::validation(
                "Invitation has already been accepted",
            ));
        }

        // Use a transaction to atomically mark the invitation as accepted
        // and add the user as a member. This prevents the case where the
        // invitation is consumed but the member is not added.
        let inv_id = invitation.id;
        let inv_org_id = invitation.organization_id;
        let inv_role = invitation.role.as_str().to_string();
        let inv_invited_by = invitation.invited_by;

        self.db
            .with_transaction(move |client| {
                Box::pin(async move {
                    // Mark invitation as accepted with AND accepted_at IS NULL
                    // to prevent race conditions.
                    let accept_query = r#"
                        UPDATE organization_invitations
                        SET accepted_at = NOW(), accepted_by = $2
                        WHERE id = $1 AND accepted_at IS NULL
                    "#;
                    let rows_affected = client
                        .execute(accept_query, &[&inv_id, &user_id])
                        .await
                        .map_err(|e| {
                            AuthencError::database(format!(
                                "Failed to mark invitation accepted: {}",
                                e
                            ))
                        })?;
                    if rows_affected == 0 {
                        return Err(AuthencError::validation(
                            "Invitation has already been accepted",
                        ));
                    }

                    // Add user as organization member
                    let member_id = Uuid::new_v4();
                    let now = chrono::Utc::now();
                    let member_query = r#"
                        INSERT INTO organization_members (
                            id, organization_id, user_id, role, invited_by,
                            invited_at, joined_at, created_at, updated_at
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    "#;
                    client
                        .execute(
                            member_query,
                            &[
                                &member_id,
                                &inv_org_id,
                                &user_id,
                                &inv_role,
                                &Some(inv_invited_by),
                                &now,
                                &now,
                                &now,
                                &now,
                            ],
                        )
                        .await
                        .map_err(|e| {
                            AuthencError::database(format!(
                                "Failed to add member: {}",
                                e
                            ))
                        })?;

                    Ok(())
                })
            })
            .await?;

        // Get organization details
        self.get_organization(&invitation.organization_id)
            .await?
            .ok_or_else(|| AuthencError::resource_not_found("Organization not found"))
    }

    /// Get organization settings
    pub async fn get_settings(&self, organization_id: &Uuid) -> Result<OrganizationSettings> {
        // In production, retrieve from database
        Ok(OrganizationSettings {
            organization_id: *organization_id,
            allow_public_signup: false,
            require_email_verification: true,
            enable_two_factor: true,
            password_policy: "default".to_string(),
            session_timeout: 3600,
            max_users: Some(1000),
            features: vec!["oidc".to_string(), "saml".to_string()],
        })
    }

    /// Update organization settings
    pub async fn update_settings(&self, _settings: &OrganizationSettings) -> Result<()> {
        // In production, update in database
        Ok(())
    }

    /// Get user's organizations
    pub async fn get_user_organizations(&self, user_id: &Uuid) -> Result<Vec<Organization>> {
        authenc_database::database::operations::organizations::get_user_organizations(&self.db, user_id)
            .await
            .map_err(|e| AuthencError::database(format!("Failed to get user organizations: {}", e)))
    }

    /// Transfer organization ownership
    pub async fn transfer_ownership(
        &self,
        organization_id: &Uuid,
        current_owner: &Uuid,
        new_owner: &Uuid,
    ) -> Result<()> {
        // Verify current user is owner
        if !self
            .has_role(organization_id, current_owner, &OrganizationRole::Owner)
            .await?
        {
            return Err(AuthencError::forbidden("Only owner can transfer ownership"));
        }

        // Verify new owner is a member of the organization
        if !self.is_member(organization_id, new_owner).await? {
            return Err(AuthencError::validation(
                "New owner must be a member of the organization",
            ));
        }

        // Use a transaction to ensure all three updates are atomic:
        // 1. Demote current owner to Admin
        // 2. Promote new owner to Owner
        // 3. Update organizations.owner_id
        let org_id = *organization_id;
        let old_owner = *current_owner;
        let new_own = *new_owner;
        let old_role_str = OrganizationRole::Admin.as_str().to_string();
        let new_role_str = OrganizationRole::Owner.as_str().to_string();

        self.db
            .with_transaction(move |client| {
                Box::pin(async move {
                    // Demote current owner to Admin
                    let rows = client
                        .execute(
                            r#"UPDATE organization_members
                               SET role = $3, updated_at = NOW()
                               WHERE organization_id = $1 AND user_id = $2"#,
                            &[&org_id, &old_owner, &old_role_str],
                        )
                        .await
                        .map_err(|e| {
                            AuthencError::database(format!(
                                "Failed to demote current owner: {}",
                                e
                            ))
                        })?;
                    if rows == 0 {
                        return Err(AuthencError::resource_not_found(
                            "Current owner not found in organization",
                        ));
                    }

                    // Promote new owner to Owner
                    let rows = client
                        .execute(
                            r#"UPDATE organization_members
                               SET role = $3, updated_at = NOW()
                               WHERE organization_id = $1 AND user_id = $2"#,
                            &[&org_id, &new_own, &new_role_str],
                        )
                        .await
                        .map_err(|e| {
                            AuthencError::database(format!(
                                "Failed to promote new owner: {}",
                                e
                            ))
                        })?;
                    if rows == 0 {
                        return Err(AuthencError::resource_not_found(
                            "New owner not found in organization",
                        ));
                    }

                    // Update organizations.owner_id
                    client
                        .execute(
                            r#"UPDATE organizations
                               SET owner_id = $2, updated_at = NOW()
                               WHERE id = $1 AND deleted_at IS NULL"#,
                            &[&org_id, &new_own],
                        )
                        .await
                        .map_err(|e| {
                            AuthencError::database(format!(
                                "Failed to update organization owner_id: {}",
                                e
                            ))
                        })?;

                    Ok(())
                })
            })
            .await
    }

    /// Add domain to organization for verification
    pub async fn add_domain(
        &self,
        organization_id: &Uuid,
        domain: &str,
        verification_method: &str,
    ) -> Result<authenc_database::database::operations::organizations::OrganizationDomain> {
        authenc_database::database::operations::organizations::add_domain(
            &self.db,
            *organization_id,
            domain,
            verification_method,
        )
        .await
    }

    /// Verify organization domain
    pub async fn verify_domain(&self, domain_id: &Uuid) -> Result<()> {
        authenc_database::database::operations::organizations::verify_domain(&self.db, *domain_id).await
    }

    /// Get organization domains
    pub async fn get_domains(
        &self,
        organization_id: &Uuid,
    ) -> Result<Vec<authenc_database::database::operations::organizations::OrganizationDomain>> {
        authenc_database::database::operations::organizations::get_domains(&self.db, *organization_id).await
    }

    /// Link identity provider to organization
    pub async fn link_identity_provider(
        &self,
        organization_id: &Uuid,
        identity_provider_id: &Uuid,
        priority: i32,
    ) -> Result<()> {
        authenc_database::database::operations::organizations::link_identity_provider(
            &self.db,
            *organization_id,
            *identity_provider_id,
            priority,
        )
        .await
    }

    /// Unlink identity provider from organization
    pub async fn unlink_identity_provider(
        &self,
        organization_id: &Uuid,
        identity_provider_id: &Uuid,
    ) -> Result<()> {
        authenc_database::database::operations::organizations::unlink_identity_provider(
            &self.db,
            *organization_id,
            *identity_provider_id,
        )
        .await
    }

    /// Generate secure invitation token
    fn generate_invitation_token(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let token: String = (0..32)
            .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
            .collect();
        token
    }

    // Database operations
    async fn store_member(&self, member: &OrganizationMember) -> Result<()> {
        authenc_database::database::operations::organizations::add_member(
            &self.db,
            member.organization_id,
            member.user_id,
            &member.role,
            member.invited_by,
        )
        .await
    }

    async fn store_invitation(&self, invitation: &OrganizationInvitation) -> Result<Uuid> {
        // Convert service invitation to model invitation
        let model_invitation = ModelOrganizationInvitation {
            id: invitation.id,
            organization_id: invitation.organization_id,
            email: invitation.email.clone(),
            role: invitation.role.as_str().to_string(),
            invited_by: invitation.invited_by,
            token_hash: {
                use sha2::{Digest, Sha256};
                format!("{:x}", Sha256::digest(invitation.token.as_bytes()))
            },
            expires_at: invitation.expires_at,
            accepted_at: invitation.accepted_at,
            accepted_by: None,
            created_at: invitation.invited_at,
        };
        authenc_database::database::operations::organizations::create_invitation(&self.db, &model_invitation)
            .await
    }

    async fn get_invitation_by_token(&self, token: &str) -> Result<Option<OrganizationInvitation>> {
        use sha2::{Digest, Sha256};
        let token_hash = format!("{:x}", Sha256::digest(token.as_bytes()));

        let model_invitation = authenc_database::database::operations::organizations::get_invitation_by_token(
            &self.db,
            &token_hash,
        )
        .await?;

        Ok(model_invitation.map(|inv| OrganizationInvitation {
            id: inv.id,
            organization_id: inv.organization_id,
            email: inv.email,
            role: OrganizationRole::parse(&inv.role).unwrap_or(OrganizationRole::Member),
            invited_by: inv.invited_by,
            invited_at: inv.created_at,
            expires_at: inv.expires_at,
            accepted_at: inv.accepted_at,
            token: token.to_string(),
        }))
    }
}

/// Organization update request
#[derive(Debug, Serialize, Deserialize)]
pub struct OrganizationUpdate {
    /// New name for the organization
    pub name: Option<String>,
    /// New display name for the organization
    pub display_name: Option<String>,
    /// New description for the organization
    pub description: Option<String>,
    /// New domain for the organization
    pub domain: Option<String>,
    /// New logo URL for the organization
    pub logo_url: Option<String>,
    /// New website URL for the organization
    pub website: Option<String>,
    /// Whether the organization should be enabled
    pub enabled: Option<bool>,
    /// New attributes for the organization
    pub attributes: Option<HashMap<String, String>>,
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_create_organization() {
        // This would need a test database setup
        // let db = Arc::new(Database::new_test().await);
        // let service = OrganizationService::new(db);
        // let org = service.create_organization("test", "Test Org", Some("Test"), Uuid::new_v4()).await;
        // assert!(org.is_ok());
    }
}
