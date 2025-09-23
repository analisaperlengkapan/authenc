use authenc::database::Database;
use authenc::services::social::*;
use authenc::config::DatabaseConfig;
use std::sync::Arc;
use serde_json::json;

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_social_provider_configuration() {
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

    let _database = Arc::new(Database::new(&database_config).await.unwrap());

    // Test Google provider configuration
    let google_config = OAuthConfig {
        provider: SocialProvider::Google,
        client_id: "google_client_id".to_string(),
        client_secret: "google_client_secret".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        authorization_url: "https://accounts.google.com/oauth/authorize".to_string(),
        token_url: "https://oauth2.googleapis.com/token".to_string(),
        user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo".to_string(),
        scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
    };

    assert_eq!(google_config.provider, SocialProvider::Google);
    assert_eq!(google_config.client_id, "google_client_id");
    assert_eq!(google_config.client_secret, "google_client_secret");
    assert_eq!(google_config.redirect_uri, "https://example.com/callback");
    assert!(google_config.scopes.contains(&"email".to_string()));

    // Test Facebook provider configuration
    let facebook_config = OAuthConfig {
        provider: SocialProvider::Facebook,
        client_id: "facebook_client_id".to_string(),
        client_secret: "facebook_client_secret".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        authorization_url: "https://www.facebook.com/v18.0/dialog/oauth".to_string(),
        token_url: "https://graph.facebook.com/v18.0/oauth/access_token".to_string(),
        user_info_url: "https://graph.facebook.com/me".to_string(),
        scopes: vec!["email".to_string(), "public_profile".to_string()],
    };

    assert_eq!(facebook_config.provider, SocialProvider::Facebook);
    assert_eq!(facebook_config.client_id, "facebook_client_id");
    assert!(facebook_config.scopes.contains(&"email".to_string()));

    // Test GitHub provider configuration
    let github_config = OAuthConfig {
        provider: SocialProvider::GitHub,
        client_id: "github_client_id".to_string(),
        client_secret: "github_client_secret".to_string(),
        redirect_uri: "https://example.com/callback".to_string(),
        authorization_url: "https://github.com/login/oauth/authorize".to_string(),
        token_url: "https://github.com/login/oauth/access_token".to_string(),
        user_info_url: "https://api.github.com/user".to_string(),
        scopes: vec!["user:email".to_string(), "read:user".to_string()],
    };

    assert_eq!(github_config.provider, SocialProvider::GitHub);
    assert_eq!(github_config.client_id, "github_client_id");
    assert!(github_config.scopes.contains(&"read:user".to_string()));
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_social_user_profile() {
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

    let _database = Arc::new(Database::new(&database_config).await.unwrap());

    // Test SocialUserProfile structure
    let profile = SocialUserProfile {
        provider: SocialProvider::Google,
        provider_user_id: "google_user_123".to_string(),
        email: Some("user@example.com".to_string()),
        name: Some("John Doe".to_string()),
        first_name: Some("John".to_string()),
        last_name: Some("Doe".to_string()),
        picture_url: Some("https://example.com/avatar.jpg".to_string()),
        locale: Some("en".to_string()),
        verified_email: true,
        raw_data: json!({
            "sub": "google_user_123",
            "email": "user@example.com",
            "name": "John Doe"
        }),
    };

    assert_eq!(profile.provider, SocialProvider::Google);
    assert_eq!(profile.provider_user_id, "google_user_123");
    assert_eq!(profile.email, Some("user@example.com".to_string()));
    assert_eq!(profile.name, Some("John Doe".to_string()));
    assert_eq!(profile.first_name, Some("John".to_string()));
    assert_eq!(profile.last_name, Some("Doe".to_string()));
    assert_eq!(profile.picture_url, Some("https://example.com/avatar.jpg".to_string()));
    assert_eq!(profile.locale, Some("en".to_string()));
    assert!(profile.verified_email);
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_oauth_token_response() {
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

    let _database = Arc::new(Database::new(&database_config).await.unwrap());

    // Test OAuthTokenResponse structure
    let token_response = OAuthTokenResponse {
        access_token: "access_token_123".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: Some(3600),
        refresh_token: Some("refresh_token_456".to_string()),
        scope: Some("openid email profile".to_string()),
        id_token: Some("id_token_789".to_string()),
    };

    assert_eq!(token_response.access_token, "access_token_123");
    assert_eq!(token_response.token_type, "Bearer");
    assert_eq!(token_response.expires_in, Some(3600));
    assert_eq!(token_response.refresh_token, Some("refresh_token_456".to_string()));
    assert_eq!(token_response.scope, Some("openid email profile".to_string()));
    assert_eq!(token_response.id_token, Some("id_token_789".to_string()));
}
