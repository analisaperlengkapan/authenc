//! Tests for FileVault (file-based vault provider)

extern crate authenc;

use authenc::vault::{file_vault::FileVault, Vault};
use std::fs;

#[tokio::test]
async fn test_file_vault_get_secret() {
    // Setup: create a temp directory and secret file
    let temp_dir = tempfile::tempdir().unwrap();
    let secret_path = temp_dir.path().join("myrealm").join("mysecret");
    fs::create_dir_all(secret_path.parent().unwrap()).unwrap();
    fs::write(&secret_path, "supersecret").unwrap();

    let vault = FileVault::new(temp_dir.path());
    let secret = vault.get_secret("mysecret", Some("myrealm")).await;
    assert!(secret.is_some());
    assert_eq!(secret.unwrap().value, "supersecret");
}
