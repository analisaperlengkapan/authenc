use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;

use authenc_api::error::Result;
use crate::spi::{Provider, ProviderConfig, ProviderFactory, Spi, SpiError};

/// Key status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyStatus {
    /// Key is active and can be used for signing/verification
    Active,
    /// Key is passive and available but not actively used
    Passive,
    /// Key is disabled and cannot be used
    Disabled,
}

impl KeyStatus {
    /// Create a KeyStatus from active and enabled flags
    pub fn from(active: bool, enabled: bool) -> Self {
        if !enabled {
            KeyStatus::Disabled
        } else if active {
            KeyStatus::Active
        } else {
            KeyStatus::Passive
        }
    }

    /// Check if the key is active
    pub fn is_active(&self) -> bool {
        matches!(self, KeyStatus::Active)
    }

    /// Check if the key is enabled (active or passive)
    pub fn is_enabled(&self) -> bool {
        matches!(self, KeyStatus::Active | KeyStatus::Passive)
    }
}

/// Abstract key metadata base class
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Provider identifier
    pub provider_id: String,
    /// Provider priority for key selection
    pub provider_priority: i64,
    /// Key ID (kid) for JWT headers
    pub kid: String,
    /// Current status of the key
    pub status: KeyStatus,
}

impl KeyMetadata {
    /// Create new key metadata
    pub fn new(provider_id: String, kid: String) -> Self {
        Self {
            provider_id,
            provider_priority: 0,
            kid,
            status: KeyStatus::Active,
        }
    }

    /// Get the provider ID
    pub fn get_provider_id(&self) -> &str {
        &self.provider_id
    }

    /// Set the provider ID
    pub fn set_provider_id(&mut self, provider_id: String) {
        self.provider_id = provider_id;
    }

    /// Get the provider priority
    pub fn get_provider_priority(&self) -> i64 {
        self.provider_priority
    }

    /// Set the provider priority
    pub fn set_provider_priority(&mut self, provider_priority: i64) {
        self.provider_priority = provider_priority;
    }

    /// Get the key ID (kid)
    pub fn get_kid(&self) -> &str {
        &self.kid
    }

    /// Set the key ID (kid)
    pub fn set_kid(&mut self, kid: String) {
        self.kid = kid;
    }

    /// Get the key status
    pub fn get_status(&self) -> KeyStatus {
        self.status
    }

    /// Set the key status
    pub fn set_status(&mut self, status: KeyStatus) {
        self.status = status;
    }
}

/// RSA key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RsaKeyMetadata {
    /// Base key metadata
    #[serde(flatten)]
    pub key_metadata: KeyMetadata,
    /// RSA public key in PEM format
    pub public_key_pem: String,
    /// X.509 certificate in PEM format (optional)
    pub certificate_pem: Option<String>,
}

impl RsaKeyMetadata {
    /// Create new RSA key metadata
    pub fn new(provider_id: String, kid: String, public_key_pem: String) -> Self {
        Self {
            key_metadata: KeyMetadata::new(provider_id, kid),
            public_key_pem,
            certificate_pem: None,
        }
    }

    /// Get the RSA public key in PEM format
    pub fn get_public_key_pem(&self) -> &str {
        &self.public_key_pem
    }

    /// Set the RSA public key in PEM format
    pub fn set_public_key_pem(&mut self, public_key_pem: String) {
        self.public_key_pem = public_key_pem;
    }

    /// Get the X.509 certificate in PEM format
    pub fn get_certificate_pem(&self) -> Option<&str> {
        self.certificate_pem.as_deref()
    }

    /// Set the X.509 certificate in PEM format
    pub fn set_certificate_pem(&mut self, certificate_pem: Option<String>) {
        self.certificate_pem = certificate_pem;
    }
}

impl std::ops::Deref for RsaKeyMetadata {
    type Target = KeyMetadata;

    fn deref(&self) -> &Self::Target {
        &self.key_metadata
    }
}

impl std::ops::DerefMut for RsaKeyMetadata {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.key_metadata
    }
}

/// Secret key metadata for symmetric keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKeyMetadata {
    /// Base key metadata
    #[serde(flatten)]
    pub key_metadata: KeyMetadata,
    /// Encryption/signing algorithm (e.g., "HS256", "HS384", "HS512")
    pub algorithm: String,
    /// Secret key in base64 encoded format
    pub secret: String, // Base64 encoded
}

impl SecretKeyMetadata {
    /// Create new secret key metadata
    pub fn new(provider_id: String, kid: String, algorithm: String, secret: String) -> Self {
        Self {
            key_metadata: KeyMetadata::new(provider_id, kid),
            algorithm,
            secret,
        }
    }

    /// Get the encryption/signing algorithm
    pub fn get_algorithm(&self) -> &str {
        &self.algorithm
    }

    /// Set the encryption/signing algorithm
    pub fn set_algorithm(&mut self, algorithm: String) {
        self.algorithm = algorithm;
    }

    /// Get the secret key (base64 encoded)
    pub fn get_secret(&self) -> &str {
        &self.secret
    }

    /// Set the secret key (base64 encoded)
    pub fn set_secret(&mut self, secret: String) {
        self.secret = secret;
    }
}

impl std::ops::Deref for SecretKeyMetadata {
    type Target = KeyMetadata;

    fn deref(&self) -> &Self::Target {
        &self.key_metadata
    }
}

impl std::ops::DerefMut for SecretKeyMetadata {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.key_metadata
    }
}

/// Key provider trait for managing cryptographic keys
#[async_trait]
pub trait KeyProvider: Provider + Send + Sync {
    /// Get the key type this provider handles (e.g., "rsa", "secret")
    fn get_key_type(&self) -> &str;

    /// Get all keys managed by this provider
    async fn get_keys(&self) -> Result<Vec<Box<dyn KeyMetadataTrait>>>;

    /// Get a specific key by kid (key ID)
    async fn get_key(&self, kid: &str) -> Result<Option<Box<dyn KeyMetadataTrait>>>;

    /// Get the active key for signing operations
    async fn get_active_key(&self) -> Result<Option<Box<dyn KeyMetadataTrait>>>;

    /// Get the passive key (for key rotation)
    async fn get_passive_key(&self) -> Result<Option<Box<dyn KeyMetadataTrait>>>;

    /// Check if this provider supports the given algorithm
    fn supports_algorithm(&self, algorithm: &str) -> bool;
}

/// Trait for key metadata objects
pub trait KeyMetadataTrait: Send + Sync {
    /// Get this object as Any for downcasting
    fn as_any(&self) -> &dyn Any;
    /// Get this object as mutable Any for downcasting
    fn as_any_mut(&mut self) -> &mut dyn Any;
    /// Get the provider ID
    fn get_provider_id(&self) -> &str;
    /// Get the provider priority
    fn get_provider_priority(&self) -> i64;
    /// Get the key ID (kid)
    fn get_kid(&self) -> &str;
    /// Get the key status
    fn get_status(&self) -> KeyStatus;
    /// Set the key status
    fn set_status(&mut self, status: KeyStatus);
}

impl KeyMetadataTrait for RsaKeyMetadata {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn get_provider_id(&self) -> &str {
        self.key_metadata.get_provider_id()
    }

    fn get_provider_priority(&self) -> i64 {
        self.key_metadata.get_provider_priority()
    }

    fn get_kid(&self) -> &str {
        self.key_metadata.get_kid()
    }

    fn get_status(&self) -> KeyStatus {
        self.key_metadata.get_status()
    }

    fn set_status(&mut self, status: KeyStatus) {
        self.key_metadata.set_status(status);
    }
}

impl KeyMetadataTrait for SecretKeyMetadata {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn get_provider_id(&self) -> &str {
        self.key_metadata.get_provider_id()
    }

    fn get_provider_priority(&self) -> i64 {
        self.key_metadata.get_provider_priority()
    }

    fn get_kid(&self) -> &str {
        self.key_metadata.get_kid()
    }

    fn get_status(&self) -> KeyStatus {
        self.key_metadata.get_status()
    }

    fn set_status(&mut self, status: KeyStatus) {
        self.key_metadata.set_status(status);
    }
}

/// Key manager for coordinating multiple key providers
#[async_trait]
pub trait KeyManager: Provider + Send + Sync {
    /// Get the active key for signing with the specified algorithm
    async fn get_active_key(&self, algorithm: &str) -> Result<Option<Box<dyn KeyMetadataTrait>>>;

    /// Get a key by kid (key ID)
    async fn get_key(&self, kid: &str) -> Result<Option<Box<dyn KeyMetadataTrait>>>;

    /// Get all keys for the specified algorithm
    async fn get_keys(&self, algorithm: &str) -> Result<Vec<Box<dyn KeyMetadataTrait>>>;

    /// Get the default key for an algorithm
    async fn get_default_key(&self, algorithm: &str) -> Result<Option<Box<dyn KeyMetadataTrait>>>;
}

/// Default key manager implementation
pub struct DefaultKeyManager {
    /// List of registered key providers
    providers: Vec<Box<dyn KeyProvider>>,
}

impl Default for DefaultKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultKeyManager {
    /// Create a new default key manager
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Add a key provider to the manager
    pub fn add_provider(&mut self, provider: Box<dyn KeyProvider>) {
        self.providers.push(provider);
    }
}

#[async_trait]
impl KeyManager for DefaultKeyManager {
    async fn get_active_key(&self, algorithm: &str) -> Result<Option<Box<dyn KeyMetadataTrait>>> {
        for provider in &self.providers {
            if provider.supports_algorithm(algorithm)
                && let Some(key) = provider.get_active_key().await? {
                    return Ok(Some(key));
                }
        }
        Ok(None)
    }

    async fn get_key(&self, kid: &str) -> Result<Option<Box<dyn KeyMetadataTrait>>> {
        for provider in &self.providers {
            if let Some(key) = provider.get_key(kid).await? {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }

    async fn get_keys(&self, algorithm: &str) -> Result<Vec<Box<dyn KeyMetadataTrait>>> {
        let mut keys = Vec::new();
        for provider in &self.providers {
            if provider.supports_algorithm(algorithm) {
                keys.extend(provider.get_keys().await?);
            }
        }
        Ok(keys)
    }

    async fn get_default_key(&self, algorithm: &str) -> Result<Option<Box<dyn KeyMetadataTrait>>> {
        self.get_active_key(algorithm).await
    }
}

impl Provider for DefaultKeyManager {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Key manager factory
pub struct DefaultKeyManagerFactory;

impl Default for DefaultKeyManagerFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultKeyManagerFactory {
    /// Create a new default key manager factory
    pub fn new() -> Self {
        Self
    }
}

impl ProviderFactory<dyn KeyManager> for DefaultKeyManagerFactory {
    fn create(
        &self,
        _config: &ProviderConfig,
    ) -> std::result::Result<Box<dyn KeyManager>, SpiError> {
        Ok(Box::new(DefaultKeyManager::new()))
    }

    fn init(&mut self, _config: &ProviderConfig) -> std::result::Result<(), SpiError> {
        Ok(())
    }

    fn get_id(&self) -> &'static str {
        "default-key-manager"
    }
}

/// Keys SPI implementation
pub struct KeysSpi;

impl Spi for KeysSpi {
    fn get_name(&self) -> &'static str {
        "keys"
    }

    fn is_internal(&self) -> bool {
        true
    }

    fn get_provider_class(&self) -> &'static str {
        "KeyManager"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "KeyManagerFactory"
    }
}
