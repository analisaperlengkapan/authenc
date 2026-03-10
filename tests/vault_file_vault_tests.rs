//! Tests for FileVault (file-based vault provider)

extern crate authenc;

use authenc::vault::{Vault, file_vault::FileVault};
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

#[tokio::test]
async fn test_file_vault_path_traversal_validation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vault = FileVault::new(temp_dir.path());

    // Test cases that should be REJECTED
    let invalid_cases = vec![
        "../escape",
        "secret/../../etc/passwd",
        "/absolute/path",
        ".",
        "some/./path",
        "",
    ];

    for case in invalid_cases {
        // get_secret should return None
        assert!(vault.get_secret(case, None).await.is_none(), "Should reject key: {}", case);
        assert!(vault.get_secret("valid", Some(case)).await.is_none(), "Should reject realm: {}", case);

        // put_secret should return Err
        assert!(vault.put_secret(case, "val", None, None).await.is_err(), "Should reject key: {}", case);
        assert!(vault.put_secret("valid", "val", Some(case), None).await.is_err(), "Should reject realm: {}", case);

        // delete_secret should return Err
        assert!(vault.delete_secret(case, None).await.is_err(), "Should reject key: {}", case);
        assert!(vault.delete_secret("valid", Some(case)).await.is_err(), "Should reject realm: {}", case);
    }

    // list_secrets validation
    for case in vec!["..", "/", "."] {
        assert!(vault.list_secrets(Some(case)).await.is_err(), "Should reject realm in list_secrets: {}", case);
    }
}

#[tokio::test]
async fn test_file_vault_nested_paths_rejected() {
    let temp_dir = tempfile::tempdir().unwrap();
    let vault = FileVault::new(temp_dir.path());

    // Subdirectories are now explicitly rejected to prevent inconsistencies with list_secrets
    let nested_key = "subdir/secret";
    let nested_realm = "my/realm";

    assert!(vault.put_secret(nested_key, "data", None, None).await.is_err());
    assert!(vault.put_secret("secret", "data", Some(nested_realm), None).await.is_err());
}
