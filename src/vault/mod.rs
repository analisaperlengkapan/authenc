//! Vault abstraction for secret management in Authenc
// Supports pluggable secret providers: file, keystore, HashiCorp Vault, KMS, etc.

use async_trait::async_trait;
use std::collections::HashMap;

/// Represents a secret value fetched from a vault
#[derive(Debug, Clone)]
pub struct Secret {
    pub value: String,
    pub metadata: Option<HashMap<String, String>>,
}

/// Vault trait for pluggable secret backends
#[async_trait]
pub trait Vault: Send + Sync {
    /// Fetch a secret by key (optionally scoped by realm)
    async fn get_secret(&self, key: &str, realm: Option<&str>) -> Option<Secret>;
}

// Example: File-based vault provider (Kubernetes/OpenShift compatible)
pub mod file_vault;
// Example: Keystore-based vault provider
pub mod keystore_vault;
// Example: HashiCorp Vault provider
pub mod hashicorp_vault;
// Example: KMS provider
pub mod kms_vault;
// Example: Secreton provider (custom Rust-based secret manager)
pub mod secreton_vault;

// ...existing code for provider modules will be implemented separately...
