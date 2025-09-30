use authenc::services::forever_unknown_secrets::ForeverUnknownSecretsService;
use std::time::{Duration, SystemTime};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_and_get_secret() {
        let service = ForeverUnknownSecretsService::new();

        // Create a secret
        let secret_id = service
            .create_secret(
                "test_secret".to_string(),
                "Testing forever unknown secrets".to_string(),
                32,   // 256 bits
                3600, // 1 hour rotation
            )
            .await
            .unwrap();

        // Get the secret
        let secret_value = service.get_secret(secret_id).await.unwrap();
        assert_eq!(secret_value.len(), 32);

        // Get it again (should be the same value)
        let secret_value2 = service.get_secret(secret_id).await.unwrap();
        assert_eq!(secret_value, secret_value2);
    }

    #[tokio::test]
    async fn test_secret_rotation() {
        let service = ForeverUnknownSecretsService::new();

        // Create a secret with very short rotation interval
        let secret_id = service
            .create_secret(
                "rotating_secret".to_string(),
                "Testing secret rotation".to_string(),
                16,
                1, // 1 second rotation
            )
            .await
            .unwrap();

        // Get initial value
        let initial_value = service.get_secret(secret_id).await.unwrap();

        // Wait for rotation interval
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Get value again (should be rotated)
        let rotated_value = service.get_secret(secret_id).await.unwrap();

        // Values should be different after rotation
        assert_ne!(initial_value, rotated_value);
        assert_eq!(initial_value.len(), rotated_value.len());
    }

    #[tokio::test]
    async fn test_manual_rotation() {
        let service = ForeverUnknownSecretsService::new();

        let secret_id = service
            .create_secret(
                "manual_rotation".to_string(),
                "Testing manual rotation".to_string(),
                24,
                3600,
            )
            .await
            .unwrap();

        let initial_value = service.get_secret(secret_id).await.unwrap();

        // Manually rotate
        service.rotate_secret(secret_id).await.unwrap();

        let rotated_value = service.get_secret(secret_id).await.unwrap();

        assert_ne!(initial_value, rotated_value);
    }

    #[tokio::test]
    async fn test_secret_deletion() {
        let service = ForeverUnknownSecretsService::new();

        let secret_id = service
            .create_secret(
                "delete_test".to_string(),
                "Testing secret deletion".to_string(),
                16,
                3600,
            )
            .await
            .unwrap();

        // Verify secret exists
        let _ = service.get_secret(secret_id).await.unwrap();

        // Delete secret
        service.delete_secret(secret_id).await.unwrap();

        // Should fail to get deleted secret
        assert!(service.get_secret(secret_id).await.is_err());
    }

    #[tokio::test]
    async fn test_list_secrets() {
        let service = ForeverUnknownSecretsService::new();

        // Create multiple secrets
        let id1 = service
            .create_secret("secret1".to_string(), "First secret".to_string(), 16, 3600)
            .await
            .unwrap();

        let id2 = service
            .create_secret("secret2".to_string(), "Second secret".to_string(), 32, 7200)
            .await
            .unwrap();

        let secrets = service.list_secrets().await;
        assert_eq!(secrets.len(), 2);

        // Check configurations
        let secret1_config = secrets.iter().find(|s| s.id == id1).unwrap();
        assert_eq!(secret1_config.name, "secret1");
        assert_eq!(secret1_config.key_size, 16);

        let secret2_config = secrets.iter().find(|s| s.id == id2).unwrap();
        assert_eq!(secret2_config.name, "secret2");
        assert_eq!(secret2_config.key_size, 32);
    }

    #[tokio::test]
    async fn test_key_derivation() {
        let service = ForeverUnknownSecretsService::new();

        let secret_id = service
            .create_secret(
                "derive_test".to_string(),
                "Testing key derivation".to_string(),
                32,
                3600,
            )
            .await
            .unwrap();

        let context = b"test_context";
        let derived_key = service.derive_key(secret_id, context, 64).await.unwrap();

        assert_eq!(derived_key.len(), 64);

        // Same context should produce same derived key
        let derived_key2 = service.derive_key(secret_id, context, 64).await.unwrap();
        assert_eq!(derived_key, derived_key2);

        // Different context should produce different key
        let different_context = b"different_context";
        let derived_key3 = service
            .derive_key(secret_id, different_context, 64)
            .await
            .unwrap();
        assert_ne!(derived_key, derived_key3);
    }

    #[tokio::test]
    async fn test_statistics() {
        let service = ForeverUnknownSecretsService::new();

        // Initially no secrets
        let stats = service.get_statistics().await;
        assert_eq!(stats["total_secrets"], 0);
        assert_eq!(stats["active_secrets"], 0);

        // Create secrets
        let _ = service
            .create_secret(
                "stats_test1".to_string(),
                "Statistics test 1".to_string(),
                16,
                3600,
            )
            .await
            .unwrap();

        let _ = service
            .create_secret(
                "stats_test2".to_string(),
                "Statistics test 2".to_string(),
                32,
                7200,
            )
            .await
            .unwrap();

        let stats = service.get_statistics().await;
        assert_eq!(stats["total_secrets"], 2);
        assert_eq!(stats["active_secrets"], 2);
        assert_eq!(stats["total_rotations"], 0); // No rotations yet
    }

    #[tokio::test]
    async fn test_cleanup_expired_secrets() {
        let service = ForeverUnknownSecretsService::new();

        // Create a secret with very short max age
        let secret_id = service
            .create_secret(
                "expired_test".to_string(),
                "Testing expired secret cleanup".to_string(),
                16,
                3600,
            )
            .await
            .unwrap();

        // Manually set max age to 0 and make the secret appear old
        {
            let mut configs = service.configs.write().await;
            let mut secrets = service.secrets.write().await;

            if let Some(config) = configs.get_mut(&secret_id) {
                config.max_age_seconds = 0;
            }

            if let Some(secret) = secrets.get_mut(&secret_id) {
                // Set created_at to 1 second ago so it's considered expired
                secret.created_at = SystemTime::now() - Duration::from_secs(1);
            }
        }

        // Cleanup should remove the expired secret
        let removed = service.cleanup_expired_secrets().await.unwrap();
        assert_eq!(removed, 1);

        // Secret should no longer exist
        assert!(service.get_secret(secret_id).await.is_err());
    }

    #[tokio::test]
    async fn test_invalid_secret_access() {
        let service = ForeverUnknownSecretsService::new();

        let invalid_id = uuid::Uuid::new_v4();

        // Should fail for non-existent secret
        assert!(service.get_secret(invalid_id).await.is_err());
        assert!(service.rotate_secret(invalid_id).await.is_err());
        assert!(service.delete_secret(invalid_id).await.is_err());
        assert!(service.get_secret_info(invalid_id).await.is_err());
    }
}
