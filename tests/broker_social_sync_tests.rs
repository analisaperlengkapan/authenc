use authenc::services::broker::{
    ExternalUser, IdentityBroker, IdentityProviderType, SocialConfig, SocialIdentityBroker,
};
use std::collections::HashMap;

#[tokio::test]
async fn test_social_sync_user() {
    // Setup SocialIdentityBroker
    let config = SocialConfig {
        client_id: "test_client_id".to_string(),
        client_secret: "test_client_secret".to_string(),
        redirect_uri: "http://localhost/callback".to_string(),
        scopes: vec!["email".to_string(), "profile".to_string()],
    };
    let broker = SocialIdentityBroker::new(config, IdentityProviderType::SocialGoogle);

    // Create a sample ExternalUser
    let mut attributes = HashMap::new();
    attributes.insert(
        "picture".to_string(),
        "http://example.com/pic.jpg".to_string(),
    );
    attributes.insert("locale".to_string(), "en-US".to_string());

    let external_user = ExternalUser {
        external_id: "123456789".to_string(),
        username: Some("testuser".to_string()),
        email: Some("test@example.com".to_string()),
        first_name: Some("Test".to_string()),
        last_name: Some("User".to_string()),
        groups: vec!["group1".to_string(), "group2".to_string()],
        attributes,
    };

    // Call sync_user
    let result = broker.sync_user(&external_user).await;

    // Assertions
    assert!(result.is_ok());
    let user = result.unwrap();

    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, "test@example.com");
    assert_eq!(user.first_name, Some("Test".to_string()));
    assert_eq!(user.last_name, Some("User".to_string()));
    assert!(user.email_verified);
    assert!(user.federated);
    assert!(user.enabled);
    assert!(user.password_hash.is_none());

    // Check attributes
    let user_attributes = user.attributes.expect("Attributes should be present");
    assert_eq!(user_attributes["picture"], "http://example.com/pic.jpg");
    assert_eq!(user_attributes["locale"], "en-US");
}

#[tokio::test]
async fn test_social_sync_user_defaults() {
    // Setup SocialIdentityBroker
    let config = SocialConfig {
        client_id: "test_client_id".to_string(),
        client_secret: "test_client_secret".to_string(),
        redirect_uri: "http://localhost/callback".to_string(),
        scopes: vec!["email".to_string()],
    };
    let broker = SocialIdentityBroker::new(config, IdentityProviderType::SocialGitHub);

    // Create a sample ExternalUser with minimal info
    let external_user = ExternalUser {
        external_id: "987654321".to_string(),
        username: None,
        email: None,
        first_name: None,
        last_name: None,
        groups: vec![],
        attributes: HashMap::new(),
    };

    // Call sync_user
    let result = broker.sync_user(&external_user).await;

    // Assertions
    assert!(result.is_ok());
    let user = result.unwrap();

    // Username should fallback to external_id
    assert_eq!(user.username, "987654321");
    // Email should be empty string (default)
    assert_eq!(user.email, "");
    assert!(user.first_name.is_none());
    assert!(user.last_name.is_none());
    assert!(user.federated);
}
