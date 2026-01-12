//! HashiCorp Vault provider for Authenc
// Production-ready implementation with KV v2 secrets engine support

use super::{HsmKeyMetadata, HsmVault, RotationResult, Secret, Vault, VaultError};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;

/// HashiCorp Vault provider for enterprise secret management
pub struct HashiCorpVault {
    /// Vault server address
    address: String,
    /// Authentication token
    token: String,
    /// Mount path for KV secrets engine (default: "secret")
    mount_path: String,
    /// Namespace (for Vault Enterprise)
    namespace: Option<String>,
    /// HTTP client for API calls
    client: reqwest::Client,
}

impl Default for HashiCorpVault {
    fn default() -> Self {
        Self::new("http://localhost:8200", "", "secret", None)
    }
}

impl HashiCorpVault {
    /// Create a new HashiCorp Vault-based secret vault
    ///
    /// This constructor initializes a vault that integrates with HashiCorp
    /// Vault for enterprise-grade secret management and cryptographic
    /// operations. The vault provides centralized secret storage with
    /// advanced security features and access control.
    ///
    /// # Arguments
    /// * `address` - Vault server address (e.g., "https://vault.example.com:8200")
    /// * `token` - Vault authentication token
    /// * `mount_path` - KV secrets engine mount path (default: "secret")
    /// * `namespace` - Vault namespace for enterprise (optional)
    ///
    /// # Returns
    /// A new `HashiCorpVault` instance for Vault-based secret management
    ///
    /// # Security Considerations
    /// - Vault server should use TLS with certificate validation
    /// - Authentication tokens should be short-lived and rotated
    /// - Access policies should follow principle of least privilege
    /// - Audit logging should be enabled for all vault operations
    ///
    /// # HashiCorp Vault Features
    /// - Centralized secret storage and key management
    /// - Dynamic secret generation and lease management
    /// - Enterprise authentication methods (LDAP, JWT, etc.)
    /// - Comprehensive audit logging and monitoring
    ///
    /// # Example
    /// ```rust
    /// use authenc::vault::hashicorp_vault::HashiCorpVault;
    ///
    /// let vault = HashiCorpVault::new(
    ///     "https://vault.example.com:8200",
    ///     "s.VaultToken12345",
    ///     "secret",
    ///     Some("authenc-namespace")
    /// );
    /// ```
    pub fn new(address: &str, token: &str, mount_path: &str, namespace: Option<&str>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        HashiCorpVault {
            address: address.to_string(),
            token: token.to_string(),
            mount_path: mount_path.to_string(),
            namespace: namespace.map(|s| s.to_string()),
            client,
        }
    }

    /// Build the full secret path for KV v2
    fn build_secret_path(&self, key: &str, realm: Option<&str>) -> String {
        let scoped_key = match realm {
            Some(r) => format!("{}/{}", r, key),
            None => key.to_string(),
        };
        format!("{}/data/{}", self.mount_path, scoped_key)
    }

    /// Build metadata path for KV v2
    fn build_metadata_path(&self, key: &str, realm: Option<&str>) -> String {
        let scoped_key = match realm {
            Some(r) => format!("{}/{}", r, key),
            None => key.to_string(),
        };
        format!("{}/metadata/{}", self.mount_path, scoped_key)
    }

    /// Build HTTP request with authentication
    fn build_request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}/v1/{}", self.address, path);
        let mut req = self
            .client
            .request(method, &url)
            .header("X-Vault-Token", &self.token);

        if let Some(ref ns) = self.namespace {
            req = req.header("X-Vault-Namespace", ns);
        }

        req
    }
}

#[async_trait]
impl Vault for HashiCorpVault {
    async fn get_secret(&self, key: &str, realm: Option<&str>) -> Option<Secret> {
        let path = self.build_secret_path(key, realm);
        let req = self.build_request(reqwest::Method::GET, &path);

        match req.send().await {
            Ok(response) => {
                if response.status().is_success()
                    && let Ok(json) = response.json::<serde_json::Value>().await {
                        // KV v2 format: data.data contains the secret
                        if let Some(data) = json.get("data").and_then(|d| d.get("data"))
                            && let Some(value) = data.get("value").and_then(|v| v.as_str()) {
                                let metadata = json
                                    .get("data")
                                    .and_then(|d| d.get("metadata"))
                                    .and_then(|m| {
                                        serde_json::from_value::<HashMap<String, String>>(m.clone())
                                            .ok()
                                    });

                                let version = json
                                    .get("data")
                                    .and_then(|d| d.get("metadata"))
                                    .and_then(|m| m.get("version"))
                                    .and_then(|v| v.as_u64())
                                    .map(|v| v as u32);

                                return Some(Secret {
                                    value: value.to_string(),
                                    metadata,
                                    version,
                                    created_at: Some(Utc::now()),
                                    expires_at: None,
                                });
                            }
                    }
                None
            }
            Err(_) => None,
        }
    }

    async fn put_secret(
        &self,
        key: &str,
        value: &str,
        realm: Option<&str>,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<(), VaultError> {
        let path = self.build_secret_path(key, realm);

        let mut data = HashMap::new();
        data.insert("value", value);

        let payload = serde_json::json!({
            "data": data,
            "options": {},
        });

        let req = self
            .build_request(reqwest::Method::POST, &path)
            .json(&payload);

        match req.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    // Update metadata if provided
                    if let Some(meta) = metadata {
                        let metadata_path = self.build_metadata_path(key, realm);
                        let meta_payload = serde_json::json!({
                            "custom_metadata": meta,
                        });
                        let _ = self
                            .build_request(reqwest::Method::POST, &metadata_path)
                            .json(&meta_payload)
                            .send()
                            .await;
                    }
                    Ok(())
                } else {
                    Err(VaultError::Other(format!(
                        "Failed to store secret: {}",
                        response.status()
                    )))
                }
            }
            Err(e) => Err(VaultError::Unavailable(e.to_string())),
        }
    }

    async fn delete_secret(&self, key: &str, realm: Option<&str>) -> Result<(), VaultError> {
        let metadata_path = self.build_metadata_path(key, realm);
        let req = self.build_request(reqwest::Method::DELETE, &metadata_path);

        match req.send().await {
            Ok(response) => {
                if response.status().is_success() || response.status().as_u16() == 404 {
                    Ok(())
                } else {
                    Err(VaultError::Other(format!(
                        "Failed to delete secret: {}",
                        response.status()
                    )))
                }
            }
            Err(e) => Err(VaultError::Unavailable(e.to_string())),
        }
    }

    async fn list_secrets(&self, realm: Option<&str>) -> Result<Vec<String>, VaultError> {
        let list_path = match realm {
            Some(r) => format!("{}/metadata/{}", self.mount_path, r),
            None => format!("{}/metadata", self.mount_path),
        };

        let req = self.build_request(reqwest::Method::from_bytes(b"LIST").unwrap(), &list_path);

        match req.send().await {
            Ok(response) => {
                if response.status().is_success()
                    && let Ok(json) = response.json::<serde_json::Value>().await
                        && let Some(keys) = json.get("data").and_then(|d| d.get("keys"))
                            && let Some(keys_array) = keys.as_array() {
                                return Ok(keys_array
                                    .iter()
                                    .filter_map(|k| k.as_str().map(|s| s.to_string()))
                                    .collect());
                            }
                Ok(vec![])
            }
            Err(e) => Err(VaultError::Unavailable(e.to_string())),
        }
    }

    async fn rotate_secret(
        &self,
        key: &str,
        realm: Option<&str>,
        generator: Box<dyn Fn() -> String + Send>,
    ) -> Result<RotationResult, VaultError> {
        // Get old secret first
        let old_secret = self.get_secret(key, realm).await;

        // Generate new secret
        let new_value = generator();

        // Store new secret
        self.put_secret(key, &new_value, realm, None).await?;

        // Fetch the new secret with metadata
        let new_secret = self
            .get_secret(key, realm)
            .await
            .ok_or_else(|| VaultError::Other("Failed to retrieve rotated secret".to_string()))?;

        Ok(RotationResult {
            new_secret,
            old_secret,
            rotated_at: Utc::now(),
        })
    }

    async fn get_secret_versions(
        &self,
        key: &str,
        realm: Option<&str>,
    ) -> Result<Vec<Secret>, VaultError> {
        let metadata_path = self.build_metadata_path(key, realm);
        let req = self.build_request(reqwest::Method::GET, &metadata_path);

        match req.send().await {
            Ok(response) => {
                if response.status().is_success()
                    && let Ok(json) = response.json::<serde_json::Value>().await
                        && let Some(versions) = json.get("data").and_then(|d| d.get("versions")) {
                            // Return version metadata (actual values require separate calls)
                            let mut result = vec![];
                            if let Some(versions_obj) = versions.as_object() {
                                for (version_str, _) in versions_obj.iter() {
                                    if let Ok(version_num) = version_str.parse::<u32>() {
                                        result.push(Secret {
                                            value: String::new(), // Placeholder
                                            metadata: None,
                                            version: Some(version_num),
                                            created_at: Some(Utc::now()),
                                            expires_at: None,
                                        });
                                    }
                                }
                            }
                            return Ok(result);
                        }
                Ok(vec![])
            }
            Err(e) => Err(VaultError::Unavailable(e.to_string())),
        }
    }

    async fn health_check(&self) -> Result<bool, VaultError> {
        let req = self.build_request(reqwest::Method::GET, "sys/health");

        match req.send().await {
            Ok(response) => {
                // Vault returns 200 for initialized+unsealed, 429 for unsealed+standby, 503 for sealed
                let status = response.status().as_u16();
                Ok(status == 200 || status == 429)
            }
            Err(e) => Err(VaultError::Unavailable(e.to_string())),
        }
    }
}

#[async_trait]
impl HsmVault for HashiCorpVault {
    async fn generate_hsm_key(
        &self,
        key_id: &str,
        algorithm: &str,
        key_size: u32,
        usage: Vec<String>,
    ) -> Result<HsmKeyMetadata, VaultError> {
        // Use Vault Transit engine for HSM-like operations
        let path = format!("transit/keys/{}", key_id);

        let payload = serde_json::json!({
            "type": algorithm.to_lowercase(),
            "exportable": false,
        });

        let req = self
            .build_request(reqwest::Method::POST, &path)
            .json(&payload);

        match req.send().await {
            Ok(response) => {
                if response.status().is_success() {
                    Ok(HsmKeyMetadata {
                        key_id: key_id.to_string(),
                        algorithm: algorithm.to_string(),
                        key_size,
                        exportable: false,
                        usage,
                    })
                } else {
                    Err(VaultError::HsmError(format!(
                        "Failed to generate HSM key: {}",
                        response.status()
                    )))
                }
            }
            Err(e) => Err(VaultError::Unavailable(e.to_string())),
        }
    }

    async fn hsm_sign(
        &self,
        key_id: &str,
        data: &[u8],
        algorithm: &str,
    ) -> Result<Vec<u8>, VaultError> {
        use base64::Engine;
        let path = format!("transit/sign/{}/{}", key_id, algorithm);

        let payload = serde_json::json!({
            "input": base64::engine::general_purpose::STANDARD.encode(data),
        });

        let req = self
            .build_request(reqwest::Method::POST, &path)
            .json(&payload);

        match req.send().await {
            Ok(response) => {
                if response.status().is_success()
                    && let Ok(json) = response.json::<serde_json::Value>().await
                        && let Some(signature) = json
                            .get("data")
                            .and_then(|d| d.get("signature"))
                            .and_then(|s| s.as_str())
                        {
                            return base64::engine::general_purpose::STANDARD
                                .decode(signature)
                                .map_err(|e| VaultError::InvalidFormat(e.to_string()));
                        }
                Err(VaultError::HsmError("Sign operation failed".to_string()))
            }
            Err(e) => Err(VaultError::Unavailable(e.to_string())),
        }
    }

    async fn hsm_encrypt(&self, key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, VaultError> {
        use base64::Engine;
        let path = format!("transit/encrypt/{}", key_id);

        let payload = serde_json::json!({
            "plaintext": base64::engine::general_purpose::STANDARD.encode(plaintext),
        });

        let req = self
            .build_request(reqwest::Method::POST, &path)
            .json(&payload);

        match req.send().await {
            Ok(response) => {
                if response.status().is_success()
                    && let Ok(json) = response.json::<serde_json::Value>().await
                        && let Some(ciphertext) = json
                            .get("data")
                            .and_then(|d| d.get("ciphertext"))
                            .and_then(|c| c.as_str())
                        {
                            return Ok(ciphertext.as_bytes().to_vec());
                        }
                Err(VaultError::HsmError("Encrypt operation failed".to_string()))
            }
            Err(e) => Err(VaultError::Unavailable(e.to_string())),
        }
    }

    async fn hsm_decrypt(&self, key_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>, VaultError> {
        use base64::Engine;
        let path = format!("transit/decrypt/{}", key_id);

        let ciphertext_str = String::from_utf8_lossy(ciphertext);
        let payload = serde_json::json!({
            "ciphertext": ciphertext_str,
        });

        let req = self
            .build_request(reqwest::Method::POST, &path)
            .json(&payload);

        match req.send().await {
            Ok(response) => {
                if response.status().is_success()
                    && let Ok(json) = response.json::<serde_json::Value>().await
                        && let Some(plaintext) = json
                            .get("data")
                            .and_then(|d| d.get("plaintext"))
                            .and_then(|p| p.as_str())
                        {
                            return base64::engine::general_purpose::STANDARD
                                .decode(plaintext)
                                .map_err(|e| VaultError::InvalidFormat(e.to_string()));
                        }
                Err(VaultError::HsmError("Decrypt operation failed".to_string()))
            }
            Err(e) => Err(VaultError::Unavailable(e.to_string())),
        }
    }

    async fn list_hsm_keys(&self) -> Result<Vec<HsmKeyMetadata>, VaultError> {
        let path = "transit/keys";
        let req = self.build_request(reqwest::Method::from_bytes(b"LIST").unwrap(), path);

        match req.send().await {
            Ok(response) => {
                if response.status().is_success()
                    && let Ok(json) = response.json::<serde_json::Value>().await
                        && let Some(keys) = json.get("data").and_then(|d| d.get("keys"))
                            && let Some(keys_array) = keys.as_array() {
                                return Ok(keys_array
                                    .iter()
                                    .filter_map(|k| k.as_str())
                                    .map(|key_id| HsmKeyMetadata {
                                        key_id: key_id.to_string(),
                                        algorithm: "unknown".to_string(),
                                        key_size: 0,
                                        exportable: false,
                                        usage: vec![],
                                    })
                                    .collect());
                            }
                Ok(vec![])
            }
            Err(e) => Err(VaultError::Unavailable(e.to_string())),
        }
    }

    async fn delete_hsm_key(&self, key_id: &str) -> Result<(), VaultError> {
        let path = format!("transit/keys/{}", key_id);
        let req = self.build_request(reqwest::Method::DELETE, &path);

        match req.send().await {
            Ok(response) => {
                if response.status().is_success() || response.status().as_u16() == 404 {
                    Ok(())
                } else {
                    Err(VaultError::HsmError(format!(
                        "Failed to delete HSM key: {}",
                        response.status()
                    )))
                }
            }
            Err(e) => Err(VaultError::Unavailable(e.to_string())),
        }
    }
}
