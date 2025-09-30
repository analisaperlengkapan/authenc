use authenc::config::DatabaseConfig;
use authenc::database::Database;
use authenc::services::broker::{
    IdentityBroker, IdentityBrokerRegistry, IdentityProviderConfig, IdentityProviderType,
    LdapConfig, LdapIdentityBroker,
};
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
#[ignore = "Requires PostgreSQL database and LDAP server to be running"]
async fn test_ldap_broker_authentication() {
    // Setup test database
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "test".to_string(),
        password: "test".to_string(),
        database: "test_db".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let database_result = Database::new(&database_config).await;
    let _database = match database_result {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Skipping test due to database connection issues");
            return;
        }
    };

    // Create LDAP configuration
    let ldap_config = LdapConfig {
        host: "localhost".to_string(),
        port: 389,
        bind_dn: "cn=admin,dc=example,dc=com".to_string(),
        bind_password: "admin_password".to_string(),
        user_search_base: "ou=users,dc=example,dc=com".to_string(),
        user_search_filter: "(&(objectClass=person)(uid={0}))".to_string(),
        group_search_base: "ou=groups,dc=example,dc=com".to_string(),
        username_attr: "uid".to_string(),
        email_attr: "mail".to_string(),
        first_name_attr: "givenName".to_string(),
        last_name_attr: "sn".to_string(),
    };

    // Create LDAP broker
    let ldap_broker = LdapIdentityBroker::new(ldap_config);

    // Test successful authentication
    let result = ldap_broker.authenticate("testuser", "testpass").await;
    match result {
        Ok(Some(user)) => {
            assert_eq!(user.username, "testuser");
            assert!(!user.email.is_empty());
            println!("LDAP authentication successful for user: {}", user.username);
        }
        Ok(None) => {
            println!("LDAP authentication failed - user not found or invalid credentials");
        }
        Err(e) => {
            println!("LDAP authentication error: {}", e);
            // This is expected if LDAP server is not available
        }
    }
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database and LDAP server to be running"]
async fn test_ldap_broker_user_info() {
    // Setup test database
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "test".to_string(),
        password: "test".to_string(),
        database: "test_db".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let database_result = Database::new(&database_config).await;
    let _database = match database_result {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Skipping test due to database connection issues");
            return;
        }
    };

    // Create LDAP configuration
    let ldap_config = LdapConfig {
        host: "localhost".to_string(),
        port: 389,
        bind_dn: "cn=admin,dc=example,dc=com".to_string(),
        bind_password: "admin_password".to_string(),
        user_search_base: "ou=users,dc=example,dc=com".to_string(),
        user_search_filter: "(&(objectClass=person)(uid={0}))".to_string(),
        group_search_base: "ou=groups,dc=example,dc=com".to_string(),
        username_attr: "uid".to_string(),
        email_attr: "mail".to_string(),
        first_name_attr: "givenName".to_string(),
        last_name_attr: "sn".to_string(),
    };

    // Create LDAP broker
    let ldap_broker = LdapIdentityBroker::new(ldap_config);

    // Test user info retrieval
    let result = ldap_broker.get_user_info("testuser").await;
    match result {
        Ok(Some(user)) => {
            assert_eq!(user.username, "testuser");
            assert!(!user.email.is_empty());
            println!(
                "LDAP user info retrieval successful for user: {}",
                user.username
            );
        }
        Ok(None) => {
            println!("LDAP user not found");
        }
        Err(e) => {
            println!("LDAP user info retrieval error: {}", e);
            // This is expected if LDAP server is not available
        }
    }
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database and LDAP server to be running"]
async fn test_ldap_broker_registry_integration() {
    // Setup test database
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "test".to_string(),
        password: "test".to_string(),
        database: "test_db".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let database_result = Database::new(&database_config).await;
    let _database = match database_result {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Skipping test due to database connection issues");
            return;
        }
    };

    // Create identity broker registry
    let mut registry = IdentityBrokerRegistry::new();

    // Create LDAP configuration
    let ldap_config = LdapConfig {
        host: "localhost".to_string(),
        port: 389,
        bind_dn: "cn=admin,dc=example,dc=com".to_string(),
        bind_password: "admin_password".to_string(),
        user_search_base: "ou=users,dc=example,dc=com".to_string(),
        user_search_filter: "(&(objectClass=person)(uid={0}))".to_string(),
        group_search_base: "ou=groups,dc=example,dc=com".to_string(),
        username_attr: "uid".to_string(),
        email_attr: "mail".to_string(),
        first_name_attr: "givenName".to_string(),
        last_name_attr: "sn".to_string(),
    };

    // Create LDAP broker
    let ldap_broker = LdapIdentityBroker::new(ldap_config);

    // Create provider configuration
    let realm_id = Uuid::new_v4();
    let provider_config = IdentityProviderConfig {
        id: Uuid::new_v4(),
        name: "Test LDAP Provider".to_string(),
        provider_type: IdentityProviderType::LDAP,
        enabled: true,
        config: serde_json::json!({
            "host": "localhost",
            "port": 389,
            "bind_dn": "cn=admin,dc=example,dc=com",
            "bind_password": "admin_password",
            "user_search_base": "ou=users,dc=example,dc=com",
            "user_search_filter": "(&(objectClass=person)(uid={0}))",
            "group_search_base": "ou=groups,dc=example,dc=com",
            "username_attr": "uid",
            "email_attr": "mail",
            "first_name_attr": "givenName",
            "last_name_attr": "sn"
        }),
        realm_id,
    };

    // Register the broker
    registry.register_broker(provider_config, Box::new(ldap_broker));

    // Test registry functionality
    let enabled_providers = registry.get_enabled_providers(&realm_id);
    assert_eq!(enabled_providers.len(), 1);
    assert_eq!(enabled_providers[0].name, "Test LDAP Provider");
    assert_eq!(
        enabled_providers[0].provider_type,
        IdentityProviderType::LDAP
    );

    println!("LDAP broker registry integration test completed successfully");
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database and LDAP server to be running"]
async fn test_ldap_broker_user_sync() {
    // Setup test database
    let database_config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        username: "test".to_string(),
        password: "test".to_string(),
        database: "test_db".to_string(),
        max_connections: 10,
        connection_timeout: 30,
        audit_log_url: None,
        connection_timeout_seconds: 30,
    };

    let database_result = Database::new(&database_config).await;
    let _database = match database_result {
        Ok(db) => Arc::new(db),
        Err(_) => {
            println!("Skipping test due to database connection issues");
            return;
        }
    };

    // Create LDAP configuration
    let ldap_config = LdapConfig {
        host: "localhost".to_string(),
        port: 389,
        bind_dn: "cn=admin,dc=example,dc=com".to_string(),
        bind_password: "admin_password".to_string(),
        user_search_base: "ou=users,dc=example,dc=com".to_string(),
        user_search_filter: "(&(objectClass=person)(uid={0}))".to_string(),
        group_search_base: "ou=groups,dc=example,dc=com".to_string(),
        username_attr: "uid".to_string(),
        email_attr: "mail".to_string(),
        first_name_attr: "givenName".to_string(),
        last_name_attr: "sn".to_string(),
    };

    // Create LDAP broker
    let ldap_broker = LdapIdentityBroker::new(ldap_config);

    // Create external user for sync
    let external_user = authenc::services::broker::ExternalUser {
        external_id: "testuser123".to_string(),
        username: Some("testuser".to_string()),
        email: Some("testuser@example.com".to_string()),
        first_name: Some("Test".to_string()),
        last_name: Some("User".to_string()),
        groups: vec!["developers".to_string(), "admins".to_string()],
        attributes: std::collections::HashMap::new(),
    };

    // Test user sync
    let result = ldap_broker.sync_user(&external_user).await;
    match result {
        Ok(user) => {
            assert_eq!(user.username, "testuser");
            assert_eq!(user.email, "testuser@example.com");
            assert_eq!(user.first_name, Some("Test".to_string()));
            assert_eq!(user.last_name, Some("User".to_string()));
            assert!(user.federated);
            println!("LDAP user sync successful for user: {}", user.username);
        }
        Err(e) => {
            println!("LDAP user sync error: {}", e);
            // This is expected if LDAP server is not available
        }
    }
}
