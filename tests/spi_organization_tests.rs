#[cfg(test)]
mod tests {
    use authenc::spi::{Spi, organization::*};
    use uuid::Uuid;

    #[test]
    fn test_organization_spi() {
        let spi = OrganizationSpi;
        assert_eq!(spi.get_name(), "organization");
        assert!(!spi.is_internal());
        assert_eq!(
            spi.get_provider_class(),
            "org.keycloak.organization.OrganizationProvider"
        );
        assert_eq!(
            spi.get_provider_factory_class(),
            "org.keycloak.organization.OrganizationProviderFactory"
        );
    }

    #[tokio::test]
    async fn test_default_organization_provider() {
        let provider = DefaultOrganizationProvider::new();

        // Test creating an organization
        let org = provider
            .create_organization("test-org", "Test Organization", Some("test.com"))
            .await
            .unwrap();

        assert_eq!(org.name, "test-org");
        assert_eq!(org.display_name, "Test Organization");
        assert_eq!(org.domain, Some("test.com".to_string()));
        assert!(org.enabled);

        // Test getting organization (should return None in default implementation)
        let retrieved = provider.get_organization(&org.id).await.unwrap();
        assert!(retrieved.is_none());

        // Test getting organization by domain (should return None in default implementation)
        let by_domain = provider
            .get_organization_by_domain("test.com")
            .await
            .unwrap();
        assert!(by_domain.is_none());

        // Test listing organizations (should return empty list)
        let list = provider.list_organizations(None, 0, 10).await.unwrap();
        assert!(list.is_empty());

        // Test member operations
        let user_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();

        // Add member
        provider
            .add_member(&org_id, &user_id, OrganizationRole::Member, None)
            .await
            .unwrap();

        // Check membership (should return false in default implementation)
        let is_member = provider.is_member(&org_id, &user_id).await.unwrap();
        assert!(!is_member);

        // Get member role (should return None in default implementation)
        let role = provider.get_member_role(&org_id, &user_id).await.unwrap();
        assert!(role.is_none());

        // Get members (should return empty list)
        let members = provider.get_members(&org_id).await.unwrap();
        assert!(members.is_empty());

        // Get user organizations (should return empty list)
        let user_orgs = provider.get_user_organizations(&user_id).await.unwrap();
        assert!(user_orgs.is_empty());
    }

    #[test]
    fn test_organization_role_serialization() {
        let role = OrganizationRole::Owner;
        let serialized = serde_json::to_string(&role).unwrap();
        assert_eq!(serialized, "\"Owner\"");

        let deserialized: OrganizationRole = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, OrganizationRole::Owner);
    }

    #[test]
    fn test_organization_model_creation() {
        let mut attributes = std::collections::HashMap::new();
        attributes.insert("custom_field".to_string(), "value".to_string());

        let org = OrganizationModel {
            id: Uuid::new_v4(),
            name: "test-org".to_string(),
            display_name: "Test Organization".to_string(),
            description: Some("A test organization".to_string()),
            domain: Some("test.com".to_string()),
            logo_url: Some("https://example.com/logo.png".to_string()),
            website: Some("https://example.com".to_string()),
            enabled: true,
            attributes,
        };

        assert_eq!(org.name, "test-org");
        assert_eq!(org.display_name, "Test Organization");
        assert_eq!(org.description, Some("A test organization".to_string()));
        assert_eq!(org.domain, Some("test.com".to_string()));
        assert_eq!(
            org.logo_url,
            Some("https://example.com/logo.png".to_string())
        );
        assert_eq!(org.website, Some("https://example.com".to_string()));
        assert!(org.enabled);
        assert_eq!(
            org.attributes.get("custom_field"),
            Some(&"value".to_string())
        );
    }

    #[test]
    fn test_organization_member_model() {
        let member = OrganizationMemberModel {
            user_id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            role: OrganizationRole::Admin,
            joined_at: chrono::Utc::now(),
            invited_by: Some(Uuid::new_v4()),
        };

        assert_eq!(member.role, OrganizationRole::Admin);
        assert!(member.invited_by.is_some());
    }
}
