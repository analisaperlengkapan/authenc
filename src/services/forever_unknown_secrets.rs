use async_trait::async_trait;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
#[cfg(feature = "tpm")]
use tss_esapi::{
    Context, Tcti,
    interface_types::algorithm::HashingAlgorithm,
    structures::{Digest, PublicKeyRsa},
    tcti_ldr::TctiNameConf,
};
use uuid::Uuid;

use crate::error::AuthencError;

/// TPM/HSM Manager for hardware-backed secret generation
#[derive(Debug)]
pub struct HardwareSecurityManager {
    /// Whether TPM/HSM is available
    available: bool,
    #[cfg(feature = "tpm")]
    /// TPM context (only available when TPM feature is enabled)
    tpm_context: Option<Context>,
}

impl Default for HardwareSecurityManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareSecurityManager {
    /// Create a new hardware security manager
    pub fn new() -> Self {
        #[cfg(feature = "tpm")]
        {
            // Try to initialize TPM context
            match Self::initialize_tpm() {
                Ok(context) => Self {
                    available: true,
                    tpm_context: Some(context),
                },
                Err(_) => Self {
                    available: false,
                    tpm_context: None,
                },
            }
        }
        #[cfg(not(feature = "tpm"))]
        Self { available: false }
    }

    /// Check if hardware security is available
    pub fn is_available(&self) -> bool {
        self.available
    }

    #[cfg(feature = "tpm")]
    /// Initialize TPM context
    fn initialize_tpm() -> Result<Context, Box<dyn std::error::Error>> {
        // Try different TCTI configurations
        let tcti_configs = vec![
            TctiNameConf::Device("/dev/tpm0".into()),
            TctiNameConf::Device("/dev/tpmrm0".into()),
            TctiNameConf::Mssim(Default::default()),
        ];

        for config in tcti_configs {
            match Context::new(config) {
                Ok(context) => return Ok(context),
                Err(_) => continue,
            }
        }

        Err("No TPM device available".into())
    }

    /// Generate random bytes using hardware security when available
    pub fn generate_random_bytes(&mut self, size: usize) -> Result<Vec<u8>, AuthencError> {
        #[cfg(feature = "tpm")]
        {
            if let Some(ref mut context) = self.tpm_context {
                // Use TPM for random number generation
                match context.get_random(size as u16) {
                    Ok(random_bytes) => return Ok(random_bytes.value().to_vec()),
                    Err(_) => {
                        // Fall back to software RNG if TPM fails
                        let mut bytes = vec![0u8; size];
                        rand::thread_rng().fill_bytes(&mut bytes);
                        return Ok(bytes);
                    }
                }
            }
        }

        // Fall back to software RNG
        let mut bytes = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut bytes);
        Ok(bytes)
    }
}

/// Forever Unknown Secret configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForeverUnknownSecretConfig {
    /// Secret ID
    pub id: Uuid,
    /// Human-readable name
    pub name: String,
    /// Purpose/description
    pub purpose: String,
    /// Key size in bytes
    pub key_size: usize,
    /// Rotation interval in seconds
    pub rotation_interval_seconds: u64,
    /// Maximum age before forced rotation
    pub max_age_seconds: u64,
    /// Whether to use hardware security (TPM/HSM) when available
    pub hardware_security: bool,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// In-memory secret storage (never persisted)
#[derive(Debug, Clone)]
pub struct InMemorySecret {
    /// The secret value (never serialized/persisted)
    pub value: Vec<u8>,
    /// Creation timestamp
    pub created_at: SystemTime,
    /// Last rotation timestamp
    pub last_rotated: SystemTime,
    /// Version number for rotation tracking
    pub version: u64,
}

/// Forever Unknown Secrets service
#[derive(Debug)]
pub struct ForeverUnknownSecretsService {
    /// Configuration for each secret (public for testing)
    pub configs: RwLock<HashMap<Uuid, ForeverUnknownSecretConfig>>,
    /// In-memory secret storage (never persisted to disk) - public for testing
    pub secrets: RwLock<HashMap<Uuid, InMemorySecret>>,
    /// RNG for secret generation
    rng: RwLock<ChaCha20Rng>,
    /// Hardware security manager
    hardware_security: HardwareSecurityManager,
}

impl ForeverUnknownSecretsService {
    /// Create a new forever unknown secrets service
    pub fn new() -> Self {
        // Use system time as seed for RNG
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        Self {
            configs: RwLock::new(HashMap::new()),
            secrets: RwLock::new(HashMap::new()),
            rng: RwLock::new(ChaCha20Rng::seed_from_u64(seed)),
            hardware_security: HardwareSecurityManager::new(),
        }
    }

    /// Create a new forever unknown secret
    pub async fn create_secret(
        &self,
        name: String,
        purpose: String,
        key_size: usize,
        rotation_interval_seconds: u64,
    ) -> Result<Uuid, AuthencError> {
        let id = Uuid::new_v4();
        let hardware_security_available = self.hardware_security.is_available();
        let config = ForeverUnknownSecretConfig {
            id,
            name,
            purpose,
            key_size,
            rotation_interval_seconds,
            max_age_seconds: rotation_interval_seconds * 2, // Max age is 2x rotation interval
            hardware_security: hardware_security_available, // Use hardware security if available
            metadata: HashMap::new(),
        };

        // Generate initial secret using hardware security if available
        let secret_value = if hardware_security_available {
            // Use hardware-backed random generation
            let mut hw_manager = HardwareSecurityManager::new();
            hw_manager.generate_random_bytes(key_size)?
        } else {
            // Fall back to software RNG
            let mut secret_value = vec![0u8; key_size];
            {
                let mut rng = self.rng.write().await;
                rng.fill_bytes(&mut secret_value);
            }
            secret_value
        };

        let now = SystemTime::now();
        let in_memory_secret = InMemorySecret {
            value: secret_value,
            created_at: now,
            last_rotated: now,
            version: 1,
        };

        // Store configuration and secret
        {
            let mut configs = self.configs.write().await;
            configs.insert(id, config);
        }
        {
            let mut secrets = self.secrets.write().await;
            secrets.insert(id, in_memory_secret);
        }

        Ok(id)
    }

    /// Get a secret value (will rotate if needed)
    pub async fn get_secret(&self, id: Uuid) -> Result<Vec<u8>, AuthencError> {
        // Check if rotation is needed
        self.check_and_rotate_secret(id).await?;

        let secrets = self.secrets.read().await;
        let secret = secrets
            .get(&id)
            .ok_or_else(|| AuthencError::resource_not_found("Secret not found"))?;

        Ok(secret.value.clone())
    }

    /// Manually rotate a secret
    pub async fn rotate_secret(&self, id: Uuid) -> Result<(), AuthencError> {
        let configs = self.configs.read().await;
        let config = configs
            .get(&id)
            .ok_or_else(|| AuthencError::resource_not_found("Secret configuration not found"))?;

        // Generate new secret value using hardware security if available
        let new_value = if config.hardware_security && self.hardware_security.is_available() {
            // Use hardware-backed random generation
            let mut hw_manager = HardwareSecurityManager::new();
            hw_manager.generate_random_bytes(config.key_size)?
        } else {
            // Fall back to software RNG
            let mut new_value = vec![0u8; config.key_size];
            {
                let mut rng = self.rng.write().await;
                rng.fill_bytes(&mut new_value);
            }
            new_value
        };

        // Update secret
        let mut secrets = self.secrets.write().await;
        if let Some(secret) = secrets.get_mut(&id) {
            secret.value = new_value;
            secret.last_rotated = SystemTime::now();
            secret.version += 1;
        }

        Ok(())
    }

    /// Delete a secret (permanently removes it from memory)
    pub async fn delete_secret(&self, id: Uuid) -> Result<(), AuthencError> {
        let mut configs = self.configs.write().await;
        let mut secrets = self.secrets.write().await;

        // Check if secret exists
        if !configs.contains_key(&id) || !secrets.contains_key(&id) {
            return Err(AuthencError::resource_not_found("Secret not found"));
        }

        configs.remove(&id);
        secrets.remove(&id);

        Ok(())
    }

    /// List all secret configurations (without values)
    pub async fn list_secrets(&self) -> Vec<ForeverUnknownSecretConfig> {
        let configs = self.configs.read().await;
        configs.values().cloned().collect()
    }

    /// Get secret metadata
    pub async fn get_secret_info(
        &self,
        id: Uuid,
    ) -> Result<ForeverUnknownSecretConfig, AuthencError> {
        let configs = self.configs.read().await;
        configs
            .get(&id)
            .cloned()
            .ok_or_else(|| AuthencError::resource_not_found("Secret not found"))
    }

    /// Check if a secret needs rotation and rotate if necessary
    async fn check_and_rotate_secret(&self, id: Uuid) -> Result<(), AuthencError> {
        let configs = self.configs.read().await;
        let config = configs
            .get(&id)
            .ok_or_else(|| AuthencError::resource_not_found("Secret configuration not found"))?;

        let secrets = self.secrets.read().await;
        let secret = secrets
            .get(&id)
            .ok_or_else(|| AuthencError::resource_not_found("Secret not found"))?;

        let now = SystemTime::now();
        let time_since_rotation = now
            .duration_since(secret.last_rotated)
            .unwrap_or(Duration::from_secs(0));

        let needs_rotation = time_since_rotation.as_secs() >= config.rotation_interval_seconds
            || secret.version == 0; // Force rotation on first access after restart

        drop(secrets); // Release read lock

        if needs_rotation {
            self.rotate_secret(id).await?;
        }

        Ok(())
    }

    /// Get secret statistics
    pub async fn get_statistics(&self) -> HashMap<String, serde_json::Value> {
        let configs = self.configs.read().await;
        let secrets = self.secrets.read().await;

        let mut stats = HashMap::new();
        stats.insert(
            "total_secrets".to_string(),
            serde_json::json!(configs.len()),
        );
        stats.insert(
            "active_secrets".to_string(),
            serde_json::json!(secrets.len()),
        );

        let mut total_rotations = 0u64;
        let mut oldest_secret = None;
        let mut newest_secret = None;

        for secret in secrets.values() {
            total_rotations += secret.version.saturating_sub(1); // Subtract 1 for initial version

            if let Ok(age) = SystemTime::now().duration_since(secret.created_at) {
                if oldest_secret.is_none_or(|oldest| age > oldest) {
                    oldest_secret = Some(age);
                }
                if newest_secret.is_none_or(|newest| age < newest) {
                    newest_secret = Some(age);
                }
            }
        }

        stats.insert(
            "total_rotations".to_string(),
            serde_json::json!(total_rotations),
        );
        stats.insert(
            "oldest_secret_age_seconds".to_string(),
            serde_json::json!(oldest_secret.map(|d| d.as_secs()).unwrap_or(0)),
        );
        stats.insert(
            "newest_secret_age_seconds".to_string(),
            serde_json::json!(newest_secret.map(|d| d.as_secs()).unwrap_or(0)),
        );

        stats
    }

    /// Cleanup expired secrets based on max age
    pub async fn cleanup_expired_secrets(&self) -> Result<usize, AuthencError> {
        let mut secrets = self.secrets.write().await;
        let mut configs = self.configs.write().await;

        let now = SystemTime::now();
        let mut removed = 0;

        // Find secrets that have exceeded max age
        let expired_ids: Vec<Uuid> = secrets
            .iter()
            .filter_map(|(id, secret)| {
                if let Some(config) = configs.get(id) {
                    let age = now
                        .duration_since(secret.created_at)
                        .unwrap_or(Duration::from_secs(0));
                    if age.as_secs() > config.max_age_seconds {
                        Some(*id)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Remove expired secrets
        for id in expired_ids {
            secrets.remove(&id);
            configs.remove(&id);
            removed += 1;
        }

        Ok(removed)
    }

    /// Derive a key from a secret (for key derivation use cases)
    pub async fn derive_key(
        &self,
        secret_id: Uuid,
        context: &[u8],
        output_length: usize,
    ) -> Result<Vec<u8>, AuthencError> {
        let secret_value = self.get_secret(secret_id).await?;

        // Simple HKDF-like key derivation (in production, use proper HKDF)
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&secret_value);
        hasher.update(context);
        let hash = hasher.finalize();

        // Expand to desired length
        let mut result = Vec::with_capacity(output_length);
        let mut counter = 0u32;
        while result.len() < output_length {
            let mut hasher = Sha256::new();
            hasher.update(hash);
            hasher.update(counter.to_be_bytes());
            let chunk = hasher.finalize();
            let remaining = output_length - result.len();
            let take = std::cmp::min(remaining, chunk.len());
            result.extend_from_slice(&chunk[..take]);
            counter += 1;
        }

        Ok(result)
    }

    /// Check if hardware security (TPM/HSM) is available
    pub fn is_hardware_security_available(&self) -> bool {
        self.hardware_security.is_available()
    }

    /// Get hardware security status information
    pub fn get_hardware_security_info(&self) -> serde_json::Value {
        serde_json::json!({
            "available": self.hardware_security.is_available(),
            "type": if self.hardware_security.is_available() { "TPM" } else { "Software" }
        })
    }
}

impl Default for ForeverUnknownSecretsService {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for services that use forever unknown secrets
#[async_trait]
pub trait ForeverUnknownSecretUser {
    /// Get the secret IDs this service depends on
    fn required_secrets(&self) -> Vec<Uuid>;

    /// Handle secret rotation notification
    async fn on_secret_rotated(&self, secret_id: Uuid) -> Result<(), AuthencError>;
}
