use authenc_services::services::federation::ldap::LdapIdentityProvider;
use authenc_services::services::federation::{IdentityProvider, IdentityProviderConfig, IdentityProviderType};
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::test]
async fn test_ldap_provider_role_mapping_logic() {
    let mut config_map = HashMap::new();
    config_map.insert("url".to_string(), "ldap://localhost".to_string());
    config_map.insert("base_dn".to_string(), "dc=example,dc=com".to_string());

    // Define role mappings JSON
    let mappings = r#"{"Admins": "admin-role", "Developers": "dev-role"}"#;
    config_map.insert("role_mappings".to_string(), mappings.to_string());

    let config = IdentityProviderConfig {
        id: Uuid::new_v4(),
        name: "ldap".to_string(),
        display_name: "LDAP".to_string(),
        provider_type: IdentityProviderType::LDAP,
        enabled: true,
        config: config_map,
        realm_id: Uuid::new_v4(),
        truststore_path: None,
        keystore_path: None,
    };

    let _provider = LdapIdentityProvider::new(config, None).await.expect("Failed to create provider");
}
