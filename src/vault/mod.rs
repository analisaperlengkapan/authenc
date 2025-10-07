//! Vault abstraction for secret management in Authenc
// Supports pluggable secret providers: file, keystore, HashiCorp Vault, KMS, etc.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Represents a secret value fetched from a vault
#[derive(Debug, Clone)]
pub struct Secret {
    /// The actual secret value
    pub value: String,
    /// Optional metadata associated with the secret
    pub metadata: Option<HashMap<String, String>>,
    /// Version of the secret (for rotation tracking)
    pub version: Option<u32>,
    /// Creation timestamp
    pub created_at: Option<DateTime<Utc>>,
    /// Expiration timestamp (for automatic rotation)
    pub expires_at: Option<DateTime<Utc>>,
}

/// Result of secret rotation operation
#[derive(Debug, Clone)]
pub struct RotationResult {
    /// New secret value
    pub new_secret: Secret,
    /// Old secret value (for graceful transition)
    pub old_secret: Option<Secret>,
    /// Rotation timestamp
    pub rotated_at: DateTime<Utc>,
}

/// HSM key metadata
#[derive(Debug, Clone)]
pub struct HsmKeyMetadata {
    /// Key ID in HSM
    pub key_id: String,
    /// Key algorithm (RSA, ECDSA, AES, etc.)
    pub algorithm: String,
    /// Key size in bits
    pub key_size: u32,
    /// Whether key is exportable
    pub exportable: bool,
    /// Key usage (sign, encrypt, wrap, etc.)
    pub usage: Vec<String>,
}

/// Vault trait for pluggable secret backends
#[async_trait]
pub trait Vault: Send + Sync {
    /// Fetch a secret by key (optionally scoped by realm)
    async fn get_secret(&self, key: &str, realm: Option<&str>) -> Option<Secret>;

    /// Store or update a secret
    async fn put_secret(
        &self,
        key: &str,
        value: &str,
        realm: Option<&str>,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<(), VaultError>;

    /// Delete a secret
    async fn delete_secret(&self, key: &str, realm: Option<&str>) -> Result<(), VaultError>;

    /// List all secret keys (with optional realm filter)
    async fn list_secrets(&self, realm: Option<&str>) -> Result<Vec<String>, VaultError>;

    /// Rotate a secret (generate new value, keep old for transition)
    async fn rotate_secret(
        &self,
        key: &str,
        realm: Option<&str>,
        generator: Box<dyn Fn() -> String + Send>,
    ) -> Result<RotationResult, VaultError>;

    /// Get secret version history
    async fn get_secret_versions(
        &self,
        key: &str,
        realm: Option<&str>,
    ) -> Result<Vec<Secret>, VaultError>;

    /// Check if vault is healthy and accessible
    async fn health_check(&self) -> Result<bool, VaultError>;
}

/// Extended vault trait for HSM integration
#[async_trait]
pub trait HsmVault: Vault {
    /// Generate a key in HSM
    async fn generate_hsm_key(
        &self,
        key_id: &str,
        algorithm: &str,
        key_size: u32,
        usage: Vec<String>,
    ) -> Result<HsmKeyMetadata, VaultError>;

    /// Sign data using HSM key
    async fn hsm_sign(
        &self,
        key_id: &str,
        data: &[u8],
        algorithm: &str,
    ) -> Result<Vec<u8>, VaultError>;

    /// Encrypt data using HSM key
    async fn hsm_encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, VaultError>;

    /// Decrypt data using HSM key
    async fn hsm_decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, VaultError>;

    /// List all HSM keys
    async fn list_hsm_keys(&self) -> Result<Vec<HsmKeyMetadata>, VaultError>;

    /// Delete HSM key
    async fn delete_hsm_key(&self, key_id: &str) -> Result<(), VaultError>;
}

/// Vault error types
#[derive(Debug, Clone)]
pub enum VaultError {
    /// Secret not found
    NotFound(String),
    /// Vault backend unreachable
    Unavailable(String),
    /// Authentication failed
    AuthenticationFailed(String),
    /// Authorization failed
    Unauthorized(String),
    /// Invalid secret format
    InvalidFormat(String),
    /// HSM operation failed
    HsmError(String),
    /// Generic error
    Other(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::NotFound(msg) => write!(f, "Secret not found: {}", msg),
            VaultError::Unavailable(msg) => write!(f, "Vault unavailable: {}", msg),
            VaultError::AuthenticationFailed(msg) => {
                write!(f, "Vault authentication failed: {}", msg)
            }
            VaultError::Unauthorized(msg) => write!(f, "Vault unauthorized: {}", msg),
            VaultError::InvalidFormat(msg) => write!(f, "Invalid secret format: {}", msg),
            VaultError::HsmError(msg) => write!(f, "HSM error: {}", msg),
            VaultError::Other(msg) => write!(f, "Vault error: {}", msg),
        }
    }
}

impl std::error::Error for VaultError {}

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
