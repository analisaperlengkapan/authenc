//! File-based vault provider for Authenc (Kubernetes/OpenShift compatible)

use super::{Secret, Vault};
use async_trait::async_trait;
use std::fs;
use std::path::{Path, PathBuf};

pub struct FileVault {
    base_dir: PathBuf,
}

impl FileVault {
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
