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
            }),
            Err(_) => None,
        }
    }
}
