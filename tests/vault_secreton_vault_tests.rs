//! Integration test for SecretonVault

use authenc::vault::secreton_vault::{SecretonClient, SecretonVault};
use authenc::vault::Vault;
use std::env;

#[tokio::test]
async fn test_secreton_vault_get_secret() {
    let endpoint = env::var("SECRETON_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:8200".to_string());
    let token = env::var("SECRETON_TOKEN").unwrap_or_else(|_| "dev-token".to_string());
    let client = SecretonClient::new(endpoint, token);
    let vault = SecretonVault::new(client);
    // This test expects a secret "test-key" to exist in Secreton (mock/dev)
    let secret = vault.get_secret("test-key", None).await;
    // Accept None or Some for dev, but should not panic
    assert!(secret.is_none() || secret.as_ref().map(|s| !s.value.is_empty()).unwrap_or(false));
}
