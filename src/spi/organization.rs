//! Organization Service Provider Interface
//!
//! Provides multi-tenancy capabilities for organization management.

use crate::spi::{Provider, ProviderConfig, ProviderFactory, Spi, SpiError};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use uuid::Uuid;

/// Organization SPI implementation
pub struct OrganizationSpi;

impl Spi for OrganizationSpi {
    fn get_name(&self) -> &'static str {
        "organization"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "io.authenc.organization.OrganizationProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "io.authenc.organization.OrganizationProviderFactory"
    }
}

/// Organization representation for SPI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationModel {
    /// Unique identifier for the organization
    pub id: Uuid,
    /// Internal name of the organization
    pub name: String,
    /// Display name of the organization
    pub display_name: String,
    /// Optional description
    pub description: Option<String>,
    /// Domain associated with the organization
    pub domain: Option<String>,
    /// URL to the organization's logo
    pub logo_url: Option<String>,
    /// Website URL
    pub website: Option<String>,
    /// Whether the organization is enabled
    pub enabled: bool,
    /// Additional attributes
    pub attributes: HashMap<String, String>,
}

/// Organization member representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationMemberModel {
    /// User ID
    pub user_id: Uuid,
    /// Organization ID
    pub organization_id: Uuid,
    /// Role in the organization
    pub role: OrganizationRole,
    /// When the user joined
    pub joined_at: chrono::DateTime<chrono::Utc>,
    /// Who invited this member
    pub invited_by: Option<Uuid>,
}

/// Organization roles
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OrganizationRole {
    /// Organization owner with full access
    Owner,
    /// Organization admin with management access
    Admin,
    /// Regular member
    Member,
}

impl OrganizationRole {
    /// Convert the role to its string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            OrganizationRole::Owner => "OWNER",
            OrganizationRole::Admin => "ADMIN",
            OrganizationRole::Member => "MEMBER",
        }
    }

    /// Convert string to OrganizationRole
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "OWNER" => Some(OrganizationRole::Owner),
            "ADMIN" => Some(OrganizationRole::Admin),
            "MEMBER" => Some(OrganizationRole::Member),
            _ => None,
        }
    }
}

/// Organization provider trait
#[async_trait]
pub trait OrganizationProvider: Provider + Send + Sync {
    /// Create a new organization
    async fn create_organization(
        &self,
        name: &str,
        display_name: &str,
        domain: Option<&str>,
    ) -> Result<OrganizationModel, SpiError>;

    /// Get organization by ID
    async fn get_organization(&self, id: &Uuid) -> Result<Option<OrganizationModel>, SpiError>;

    /// Get organization by domain
    async fn get_organization_by_domain(
        &self,
        domain: &str,
    ) -> Result<Option<OrganizationModel>, SpiError>;

    /// Update organization
    async fn update_organization(&self, organization: OrganizationModel) -> Result<(), SpiError>;

    /// Delete organization
    async fn delete_organization(&self, id: &Uuid) -> Result<(), SpiError>;

    /// List organizations with pagination
    async fn list_organizations(
        &self,
        search: Option<&str>,
        first: usize,
        max: usize,
    ) -> Result<Vec<OrganizationModel>, SpiError>;

    /// Add member to organization
    async fn add_member(
        &self,
        organization_id: &Uuid,
        user_id: &Uuid,
        role: OrganizationRole,
        invited_by: Option<Uuid>,
    ) -> Result<(), SpiError>;

    /// Remove member from organization
    async fn remove_member(&self, organization_id: &Uuid, user_id: &Uuid) -> Result<(), SpiError>;

    /// Get organization members
    async fn get_members(
        &self,
        organization_id: &Uuid,
    ) -> Result<Vec<OrganizationMemberModel>, SpiError>;

    /// Get user's organizations
    async fn get_user_organizations(
        &self,
        user_id: &Uuid,
    ) -> Result<Vec<OrganizationModel>, SpiError>;

    /// Update member role
    async fn update_member_role(
        &self,
        organization_id: &Uuid,
        user_id: &Uuid,
        role: OrganizationRole,
    ) -> Result<(), SpiError>;

    /// Check if user is member of organization
    async fn is_member(&self, organization_id: &Uuid, user_id: &Uuid) -> Result<bool, SpiError>;

    /// Get member role
    async fn get_member_role(
        &self,
        organization_id: &Uuid,
        user_id: &Uuid,
    ) -> Result<Option<OrganizationRole>, SpiError>;
}

/// Default organization provider implementation
pub struct DefaultOrganizationProvider {
    // In a real implementation, this would hold database connections, etc.
}

impl Default for DefaultOrganizationProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultOrganizationProvider {
    /// Create a new default organization provider
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl OrganizationProvider for DefaultOrganizationProvider {
    async fn create_organization(
        &self,
        name: &str,
        display_name: &str,
        domain: Option<&str>,
    ) -> Result<OrganizationModel, SpiError> {
        // Default implementation - in practice, this would persist to database
        let organization = OrganizationModel {
            id: Uuid::new_v4(),
            name: name.to_string(),
            display_name: display_name.to_string(),
            description: None,
            domain: domain.map(|s| s.to_string()),
            logo_url: None,
            website: None,
            enabled: true,
            attributes: HashMap::new(),
        };

        Ok(organization)
    }

    async fn get_organization(&self, _id: &Uuid) -> Result<Option<OrganizationModel>, SpiError> {
        // Default implementation - returns None
        Ok(None)
    }

    async fn get_organization_by_domain(
        &self,
        _domain: &str,
    ) -> Result<Option<OrganizationModel>, SpiError> {
        // Default implementation - returns None
        Ok(None)
    }

    async fn update_organization(&self, _organization: OrganizationModel) -> Result<(), SpiError> {
        // Default implementation - no-op
        Ok(())
    }

    async fn delete_organization(&self, _id: &Uuid) -> Result<(), SpiError> {
        // Default implementation - no-op
        Ok(())
    }

    async fn list_organizations(
        &self,
        _search: Option<&str>,
        _first: usize,
        _max: usize,
    ) -> Result<Vec<OrganizationModel>, SpiError> {
        // Default implementation - returns empty list
        Ok(Vec::new())
    }

    async fn add_member(
        &self,
        _organization_id: &Uuid,
        _user_id: &Uuid,
        _role: OrganizationRole,
        _invited_by: Option<Uuid>,
    ) -> Result<(), SpiError> {
        // Default implementation - no-op
        Ok(())
    }

    async fn remove_member(
        &self,
        _organization_id: &Uuid,
        _user_id: &Uuid,
    ) -> Result<(), SpiError> {
        // Default implementation - no-op
        Ok(())
    }

    async fn get_members(
        &self,
        _organization_id: &Uuid,
    ) -> Result<Vec<OrganizationMemberModel>, SpiError> {
        // Default implementation - returns empty list
        Ok(Vec::new())
    }

    async fn get_user_organizations(
        &self,
        _user_id: &Uuid,
    ) -> Result<Vec<OrganizationModel>, SpiError> {
        // Default implementation - returns empty list
        Ok(Vec::new())
    }

    async fn update_member_role(
        &self,
        _organization_id: &Uuid,
        _user_id: &Uuid,
        _role: OrganizationRole,
    ) -> Result<(), SpiError> {
        // Default implementation - no-op
        Ok(())
    }

    async fn is_member(&self, _organization_id: &Uuid, _user_id: &Uuid) -> Result<bool, SpiError> {
        // Default implementation - returns false
        Ok(false)
    }

    async fn get_member_role(
        &self,
        _organization_id: &Uuid,
        _user_id: &Uuid,
    ) -> Result<Option<OrganizationRole>, SpiError> {
        // Default implementation - returns None
        Ok(None)
    }
}

impl Provider for DefaultOrganizationProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Organization provider factory
pub struct DefaultOrganizationProviderFactory;

impl Default for DefaultOrganizationProviderFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultOrganizationProviderFactory {
    /// Create a new factory
    pub fn new() -> Self {
        Self {}
    }
}

impl ProviderFactory<DefaultOrganizationProvider> for DefaultOrganizationProviderFactory {
    fn get_id(&self) -> &'static str {
        "default-organization"
    }

    fn create(
        &self,
        _config: &ProviderConfig,
    ) -> Result<Box<DefaultOrganizationProvider>, SpiError> {
        let provider = DefaultOrganizationProvider::new();
        Ok(Box::new(provider))
    }
}
