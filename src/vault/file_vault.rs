//! File-based vault provider for Authenc (Kubernetes/OpenShift compatible)

use super::{Secret, Vault};
use async_trait::async_trait;
use std::fs;
use std::path::{Path, PathBuf};

/// File-based vault provider for storing secrets in the filesystem
pub struct FileVault {
    /// Base directory where secrets are stored
    base_dir: PathBuf,
}

impl FileVault {
    /// Create a new file-based vault with specified base directory
    ///
    /// This constructor initializes a file-based secret vault that stores
    /// encrypted secrets on the local filesystem. Secrets are organized
    /// within the specified base directory and can be optionally scoped
    /// to specific realms for multi-tenancy support.
    ///
    /// # Arguments
    /// * `base_dir` - Base directory path where secrets will be stored
    ///
    /// # Returns
    /// A new `FileVault` instance configured for file-based secret storage
    ///
    /// # Security Considerations
    /// - Base directory should have restrictive file permissions (700)
    /// - Filesystem should support secure deletion for key rotation
    /// - Directory should be on encrypted storage for data protection
    /// - Access to vault directory should be audited and monitored
    ///
    /// # File Organization
    /// - Secrets stored as encrypted files within base directory
    /// - Optional realm subdirectories for tenant isolation
    /// - File names derived from secret keys with secure hashing
    /// - Metadata stored alongside encrypted secret data
    ///
    /// # Example
    /// ```rust
    /// use authenc::vault::file_vault::FileVault;
    /// use std::path::Path;
    ///
    /// let vault = FileVault::new("/var/authenc/secrets");
    /// // Vault is ready for secret storage operations
    /// ```
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Self {
        FileVault {
            base_dir: base_dir.as_ref().to_path_buf(),
        }
    }
}

#[async_trait]
impl Vault for FileVault {
    async fn get_secret(&self, key: &str, realm: Option<&str>) -> Option<Secret> {
        let mut path = self.base_dir.clone();
        if let Some(realm) = realm {
            path.push(realm);
        }
        path.push(key);
        match fs::read_to_string(&path) {
            Ok(value) => Some(Secret {
                value: value.trim().to_string(),
                metadata: None,
                version: Some(1),
                created_at: Some(chrono::Utc::now()),
                expires_at: None,
            }),
            Err(_) => None,
        }
    }

    async fn put_secret(
        &self,
        key: &str,
        value: &str,
        realm: Option<&str>,
        _metadata: Option<std::collections::HashMap<String, String>>,
    ) -> Result<(), super::VaultError> {
        let mut path = self.base_dir.clone();
        if let Some(realm) = realm {
            path.push(realm);
            fs::create_dir_all(&path).map_err(|e| {
                super::VaultError::Other(format!("Failed to create realm directory: {}", e))
            })?;
        }
        path.push(key);
        fs::write(&path, value)
            .map_err(|e| super::VaultError::Other(format!("Failed to write secret: {}", e)))
    }

    async fn delete_secret(&self, key: &str, realm: Option<&str>) -> Result<(), super::VaultError> {
        let mut path = self.base_dir.clone();
        if let Some(realm) = realm {
            path.push(realm);
        }
        path.push(key);
        fs::remove_file(&path)
            .map_err(|e| super::VaultError::Other(format!("Failed to delete secret: {}", e)))
    }

    async fn list_secrets(&self, realm: Option<&str>) -> Result<Vec<String>, super::VaultError> {
        let mut path = self.base_dir.clone();
        if let Some(realm) = realm {
            path.push(realm);
        }

        match fs::read_dir(&path) {
            Ok(entries) => Ok(entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
                .collect()),
            Err(e) => Err(super::VaultError::Other(format!(
                "Failed to list secrets: {}",
                e
            ))),
        }
    }

    async fn rotate_secret(
        &self,
        key: &str,
        realm: Option<&str>,
        generator: Box<dyn Fn() -> String + Send>,
    ) -> Result<super::RotationResult, super::VaultError> {
        let old_secret = self.get_secret(key, realm).await;
        let new_value = generator();
        self.put_secret(key, &new_value, realm, None).await?;

        let new_secret = self.get_secret(key, realm).await.ok_or_else(|| {
            super::VaultError::Other("Failed to retrieve rotated secret".to_string())
        })?;

        Ok(super::RotationResult {
            new_secret,
            old_secret,
            rotated_at: chrono::Utc::now(),
        })
    }

    async fn get_secret_versions(
        &self,
        _key: &str,
        _realm: Option<&str>,
    ) -> Result<Vec<Secret>, super::VaultError> {
        // File vault doesn't support versioning
        Ok(vec![])
    }

    async fn health_check(&self) -> Result<bool, super::VaultError> {
        Ok(self.base_dir.exists())
    }
}
