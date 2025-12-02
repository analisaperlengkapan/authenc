use authenc::database::Database;
use authenc::services::token::TokenManager;
use std::sync::Arc;
use uuid::Uuid;

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_token_generation() {
    // Test basic token generation
    let config = authenc::config::AppConfig::default();
    let db = Arc::new(Database::new(&config.database).await.unwrap());
    let token_manager = TokenManager::new(db);

    let user_id = Uuid::new_v4();
    let client_id = Uuid::new_v4().to_string();

    let result = token_manager
        .generate_token_pair(user_id, client_id, Some("openid profile".to_string()), true)
        .await;

    assert!(result.is_ok());
    let token_response = result.unwrap();
    assert_eq!(token_response.token_type, "Bearer");
    assert!(token_response.access_token.len() > 0);
    assert!(token_response.refresh_token.is_some());
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_token_validation() {
    // Test token validation
    let config = authenc::config::AppConfig::default();
    let db = Arc::new(Database::new(&config.database).await.unwrap());
    let token_manager = TokenManager::new(db);

    let user_id = Uuid::new_v4();
    let client_id = Uuid::new_v4().to_string();

    // Generate token
    let token_response = token_manager
        .generate_token_pair(
            user_id,
            client_id.clone(),
            Some("openid".to_string()),
            false,
        )
        .await
        .unwrap();

    // Validate token
    let validation_result = token_manager
        .validate_access_token(&token_response.access_token)
        .await;

    assert!(validation_result.is_ok());
    let (validated_user_id, validated_client_id, scopes) = validation_result.unwrap();
    assert_eq!(validated_user_id, user_id);
    assert_eq!(validated_client_id, client_id);
    assert!(scopes.contains(&"openid".to_string()));
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_token_refresh() {
    // Test refresh token flow
    let config = authenc::config::AppConfig::default();
    let db = Arc::new(Database::new(&config.database).await.unwrap());
    let token_manager = TokenManager::new(db);

    let user_id = Uuid::new_v4();
    let client_id = Uuid::new_v4().to_string();

    // Generate token with refresh token
    let original_response = token_manager
        .generate_token_pair(
            user_id,
            client_id,
            Some("openid profile email".to_string()),
            true,
        )
        .await
        .unwrap();

    let refresh_token = original_response.refresh_token.unwrap();

    // Use refresh token to get new access token
    let refreshed_response = token_manager.refresh_token(&refresh_token).await;

    assert!(refreshed_response.is_ok());
    let new_response = refreshed_response.unwrap();
    assert_ne!(new_response.access_token, original_response.access_token);
    assert!(new_response.refresh_token.is_some());
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_token_revocation() {
    // Test token revocation
    let config = authenc::config::AppConfig::default();
    let db = Arc::new(Database::new(&config.database).await.unwrap());
    let token_manager = TokenManager::new(db);

    let user_id = Uuid::new_v4();
    let client_id = Uuid::new_v4().to_string();

    // Generate token
    let token_response = token_manager
        .generate_token_pair(user_id, client_id, None, false)
        .await
        .unwrap();

    // Revoke token
    let revoke_result = token_manager
        .revoke_token(&token_response.access_token)
        .await;
    assert!(revoke_result.is_ok());

    // Validate revoked token should fail
    let validation_result = token_manager
        .validate_access_token(&token_response.access_token)
        .await;
    assert!(validation_result.is_err());
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_revoke_user_tokens() {
    // Test revoking all tokens for a user
    let config = authenc::config::AppConfig::default();
    let db = Arc::new(Database::new(&config.database).await.unwrap());
    let token_manager = TokenManager::new(db);

    let user_id = Uuid::new_v4();
    let client_id = Uuid::new_v4().to_string();

    // Generate multiple tokens
    token_manager
        .generate_token_pair(user_id, client_id.clone(), None, false)
        .await
        .unwrap();
    token_manager
        .generate_token_pair(user_id, client_id.clone(), None, false)
        .await
        .unwrap();

    // Revoke all user tokens
    let revoked_count = token_manager.revoke_user_tokens(user_id).await.unwrap();
    assert!(revoked_count >= 2);
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_token_introspection() {
    // Test RFC 7662 token introspection
    let config = authenc::config::AppConfig::default();
    let db = Arc::new(Database::new(&config.database).await.unwrap());
    let token_manager = TokenManager::new(db);

    let user_id = Uuid::new_v4();
    let client_id = Uuid::new_v4().to_string();

    // Generate token
    let token_response = token_manager
        .generate_token_pair(
            user_id,
            client_id.clone(),
            Some("openid".to_string()),
            false,
        )
        .await
        .unwrap();

    // Introspect active token
    let introspection = token_manager
        .introspect_token(&token_response.access_token)
        .await
        .unwrap();

    assert!(introspection.active);
    assert_eq!(introspection.client_id, Some(client_id));
    assert_eq!(introspection.scope, Some("openid".to_string()));
    assert_eq!(introspection.token_type, Some("Bearer".to_string()));
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_introspect_invalid_token() {
    // Test introspecting an invalid token
    let config = authenc::config::AppConfig::default();
    let db = Arc::new(Database::new(&config.database).await.unwrap());
    let token_manager = TokenManager::new(db);

    let introspection = token_manager
        .introspect_token("invalid_token_12345")
        .await
        .unwrap();

    assert!(!introspection.active);
    assert!(introspection.client_id.is_none());
    assert!(introspection.scope.is_none());
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_token_rotation() {
    // Test refresh token rotation (security feature)
    let config = authenc::config::AppConfig::default();
    let db = Arc::new(Database::new(&config.database).await.unwrap());
    let token_manager = TokenManager::with_config(db, 3600, 2592000, true); // Enable rotation

    let user_id = Uuid::new_v4();
    let client_id = Uuid::new_v4().to_string();

    // Generate token
    let original_response = token_manager
        .generate_token_pair(user_id, client_id, Some("openid".to_string()), true)
        .await
        .unwrap();

    let refresh_token = original_response.refresh_token.as_ref().unwrap();

    // Refresh token (should rotate)
    let new_response = token_manager.refresh_token(refresh_token).await.unwrap();

    // Old access token should be revoked (rotation enabled)
    let old_validation = token_manager
        .validate_access_token(&original_response.access_token)
        .await;
    assert!(old_validation.is_err());

    // New access token should work
    let new_validation = token_manager
        .validate_access_token(&new_response.access_token)
        .await;
    assert!(new_validation.is_ok());
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_get_user_active_tokens() {
    // Test retrieving all active tokens for a user
    let config = authenc::config::AppConfig::default();
    let db = Arc::new(Database::new(&config.database).await.unwrap());
    let token_manager = TokenManager::new(db);

    let user_id = Uuid::new_v4();
    let client_id = Uuid::new_v4().to_string();

    // Generate tokens
    token_manager
        .generate_token_pair(user_id, client_id.clone(), None, false)
        .await
        .unwrap();
    token_manager
        .generate_token_pair(user_id, client_id.clone(), None, false)
        .await
        .unwrap();

    // Get active tokens
    let tokens = token_manager.get_user_tokens(user_id).await.unwrap();
    assert!(tokens.len() >= 2);

    for token_info in tokens {
        assert_eq!(token_info.client_id.to_string(), client_id);
    }
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_cleanup_expired_tokens() {
    // Test cleanup of expired tokens
    let config = authenc::config::AppConfig::default();
    let db = Arc::new(Database::new(&config.database).await.unwrap());
    let token_manager = TokenManager::new(db);

    // Note: This test would require manually expiring tokens or waiting
    // For now, just verify the cleanup function doesn't error
    let cleanup_result = token_manager.cleanup_expired_tokens().await;
    assert!(cleanup_result.is_ok());
}

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn test_token_hash_consistency() {
    // Test that token hashing is consistent
    let config = authenc::config::AppConfig::default();
    let db = Arc::new(Database::new(&config.database).await.unwrap());
    let token_manager = TokenManager::new(db);

    let user_id = Uuid::new_v4();
    let client_id = Uuid::new_v4().to_string();

    // Generate two tokens and verify they are unique
    let token1 = token_manager
        .generate_token_pair(user_id, client_id.clone(), None, false)
        .await
        .unwrap();
    
    let token2 = token_manager
        .generate_token_pair(user_id, client_id, None, false)
        .await
        .unwrap();

    // Each token should be unique
    assert_ne!(token1.access_token, token2.access_token);
}
