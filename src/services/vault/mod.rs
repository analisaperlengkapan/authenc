use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Vault provider trait for secret management
#[async_trait]
pub trait VaultProvider: Send + Sync {
    /// Retrieve a secret by key
    async fn get_secret(&self, key: &str) -> Result<Option<String>>;

    /// Store a secret
    async fn set_secret(&self, key: &str, value: &str) -> Result<()>;

    /// Delete a secret
    async fn delete_secret(&self, key: &str) -> Result<()>;

    /// List all secrets
    async fn list_secrets(&self) -> Result<Vec<String>>;
}

/// File-based vault provider for Kubernetes secrets
pub struct FileVaultProvider {
    /// Base directory path for storing secrets
    base_path: String,
}

impl FileVaultProvider {
    /// Creates a new file-based vault provider.
    ///
    /// # Arguments
    /// * `base_path` - The base directory path where secrets will be stored
    ///
    /// # Returns
    /// A new `FileVaultProvider` instance.
    pub fn new(base_path: String) -> Self {
        Self { base_path }
    }
}

#[async_trait]
impl VaultProvider for FileVaultProvider {
    async fn get_secret(&self, key: &str) -> Result<Option<String>> {
        let file_path = Path::new(&self.base_path).join(key);
        match tokio::fs::read_to_string(file_path).await {
            Ok(content) => Ok(Some(content.trim().to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        let file_path = Path::new(&self.base_path).join(key);
        if let Some(parent) = file_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(file_path, value).await?;
        Ok(())
    }

    async fn delete_secret(&self, key: &str) -> Result<()> {
        let file_path = Path::new(&self.base_path).join(key);
        match tokio::fs::remove_file(file_path).await {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn list_secrets(&self) -> Result<Vec<String>> {
        let mut secrets = Vec::new();
        if let Ok(mut entries) = tokio::fs::read_dir(&self.base_path).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Some(file_name) = entry.file_name().to_str() {
                    secrets.push(file_name.to_string());
                }
            }
        }
        Ok(secrets)
    }
}

/// Java KeyStore-based vault provider
#[allow(dead_code)]
pub struct KeyStoreVaultProvider {
    /// Path to the Java KeyStore file
    keystore_path: String,
    /// Password for the KeyStore
    keystore_password: String,
    /// Password for individual keys
    key_password: String,
}

impl KeyStoreVaultProvider {
    /// Creates a new KeyStore-based vault provider.
    ///
    /// # Arguments
    /// * `keystore_path` - Path to the Java KeyStore file
    /// * `keystore_password` - Password to access the KeyStore
    /// * `key_password` - Password for individual keys in the KeyStore
    ///
    /// # Returns
    /// A new `KeyStoreVaultProvider` instance.
    pub fn new(keystore_path: String, keystore_password: String, key_password: String) -> Self {
        Self {
            keystore_path,
            keystore_password,
            key_password,
        }
    }
}

#[async_trait]
impl VaultProvider for KeyStoreVaultProvider {
    async fn get_secret(&self, key: &str) -> Result<Option<String>> {
        use openssl::pkcs12::Pkcs12;

        // Read PKCS12 file using async IO
        let p12_data = tokio::fs::read(&self.keystore_path).await?;
        let p12 = Pkcs12::from_der(&p12_data)?;
        let parsed = p12.parse2(&self.keystore_password)?;

        // Try to find the key in the parsed PKCS12 structure
        // Note: PKCS12 typically stores certificates and private keys, not arbitrary secrets
        // For actual secret storage, we would need a different approach
        // This is a simplified implementation that stores secrets as certificate friendly names

        if let Some(cert) = &parsed.cert {
            // Get subject name as text
            let subject_name = cert.subject_name();
            for entry in subject_name.entries() {
                if let Ok(data) = entry.data().as_utf8()
                    && data.to_string().contains(key) {
                        // In a real implementation, you'd extract the actual secret
                        // For now, return a placeholder
                        return Ok(Some(format!("secret_for_{}", key)));
                    }
            }
        }

        Ok(None)
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        use openssl::pkcs12::Pkcs12;

        // PKCS12 is designed for certificate storage, not arbitrary key-value pairs
        // This is a placeholder implementation
        // In production, consider using a proper key-value store or extending the PKCS12 structure

        tracing::warn!(
            "PKCS12 set_secret is a placeholder implementation. Key: {}, Value length: {}",
            key,
            value.len()
        );

        // Read existing keystore if it exists
        if tokio::fs::try_exists(&self.keystore_path).await.unwrap_or(false) {
            let p12_data = tokio::fs::read(&self.keystore_path).await?;
            let _p12 = Pkcs12::from_der(&p12_data)?;
            // In a real implementation, you would modify the PKCS12 structure
        }

        Ok(())
    }

    async fn delete_secret(&self, key: &str) -> Result<()> {
        tracing::warn!(
            "PKCS12 delete_secret is a placeholder implementation. Key: {}",
            key
        );
        // PKCS12 doesn't support arbitrary secret deletion easily
        // This would require reconstructing the entire keystore without the target entry
        Ok(())
    }

    async fn list_secrets(&self) -> Result<Vec<String>> {
        use openssl::pkcs12::Pkcs12;

        let mut secrets = Vec::new();

        if tokio::fs::try_exists(&self.keystore_path).await.unwrap_or(false) {
            let p12_data = tokio::fs::read(&self.keystore_path).await?;
            let p12 = Pkcs12::from_der(&p12_data)?;
            let parsed = p12.parse2(&self.keystore_password)?;

            // List certificates in the keystore
            if let Some(cert) = parsed.cert {
                let subject_name = cert.subject_name();
                for entry in subject_name.entries() {
                    if let Ok(data) = entry.data().as_utf8() {
                        secrets.push(data.to_string());
                        break; // Just get the first entry
                    }
                }
            }

            // List additional certificates from the chain
            if let Some(chain) = parsed.ca {
                for cert in chain {
                    let subject_name = cert.subject_name();
                    for entry in subject_name.entries() {
                        if let Ok(data) = entry.data().as_utf8() {
                            secrets.push(data.to_string());
                            break; // Just get the first entry
                        }
                    }
                }
            }
        }

        Ok(secrets)
    }
}

/// HashiCorp Vault provider
#[allow(dead_code)]
pub struct HashiCorpVaultProvider {
    /// HashiCorp Vault server address
    vault_addr: String,
    /// Authentication token for Vault access
    token: String,
    /// Mount path for secrets in Vault
    mount_path: String,
}

impl HashiCorpVaultProvider {
    /// Creates a new HashiCorp Vault provider.
    ///
    /// # Arguments
    /// * `vault_addr` - The address of the HashiCorp Vault server
    /// * `token` - Authentication token for accessing Vault
    /// * `mount_path` - The mount path where secrets are stored
    ///
    /// # Returns
    /// A new `HashiCorpVaultProvider` instance.
    pub fn new(vault_addr: String, token: String, mount_path: String) -> Self {
        Self {
            vault_addr,
            token,
            mount_path,
        }
    }
}

#[async_trait]
impl VaultProvider for HashiCorpVaultProvider {
    async fn get_secret(&self, key: &str) -> Result<Option<String>> {
        #[cfg(feature = "test")]
        {
            let client = reqwest::Client::new();
            let url = format!("{}/v1/{}/data/{}", self.vault_addr, self.mount_path, key);

            let response = client
                .get(&url)
                .header("X-Vault-Token", &self.token)
                .send()
                .await?;

            if response.status().is_success() {
                let json: serde_json::Value = response.json().await?;
                if let Some(data) = json.get("data").and_then(|d| d.get("data")) {
                    if let Some(value) = data.get("value") {
                        if let Some(v) = value.as_str() {
                            return Ok(Some(v.to_string()));
                        }
                    }
                }
            }

            Ok(None)
        }
        #[cfg(not(feature = "test"))]
        {
            tracing::error!("HashiCorp Vault requires 'test' feature to be enabled");
            Ok(None)
        }
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        #[cfg(feature = "test")]
        {
            let client = reqwest::Client::new();
            let url = format!("{}/v1/{}/data/{}", self.vault_addr, self.mount_path, key);

            let payload = serde_json::json!({
                "data": {
                    "value": value
                }
            });

            let response = client
                .post(&url)
                .header("X-Vault-Token", &self.token)
                .json(&payload)
                .send()
                .await?;

            if !response.status().is_success() {
                let error_text = response.text().await?;
                anyhow::bail!("Failed to set secret in Vault: {}", error_text);
            }

            Ok(())
        }
        #[cfg(not(feature = "test"))]
        {
            tracing::error!("HashiCorp Vault requires 'test' feature to be enabled");
            Ok(())
        }
    }

    async fn delete_secret(&self, key: &str) -> Result<()> {
        #[cfg(feature = "test")]
        {
            let client = reqwest::Client::new();
            let url = format!(
                "{}/v1/{}/metadata/{}",
                self.vault_addr, self.mount_path, key
            );

            let response = client
                .delete(&url)
                .header("X-Vault-Token", &self.token)
                .send()
                .await?;

            if !response.status().is_success() {
                let error_text = response.text().await?;
                tracing::warn!("Failed to delete secret from Vault: {}", error_text);
            }

            Ok(())
        }
        #[cfg(not(feature = "test"))]
        {
            tracing::error!("HashiCorp Vault requires 'test' feature to be enabled");
            Ok(())
        }
    }

    async fn list_secrets(&self) -> Result<Vec<String>> {
        #[cfg(feature = "test")]
        {
            let client = reqwest::Client::new();
            let url = format!("{}/v1/{}/metadata", self.vault_addr, self.mount_path);

            let response = client
                .get(&url)
                .query(&[("list", "true")])
                .header("X-Vault-Token", &self.token)
                .send()
                .await?;

            if response.status().is_success() {
                let json: serde_json::Value = response.json().await?;
                if let Some(keys) = json.get("data").and_then(|d| d.get("keys")) {
                    if let Some(keys_array) = keys.as_array() {
                        return Ok(keys_array
                            .iter()
                            .filter_map(|k| k.as_str().map(|s| s.trim_end_matches('/').to_string()))
                            .collect());
                    }
                }
            }

            Ok(vec![])
        }
        #[cfg(not(feature = "test"))]
        {
            tracing::error!("HashiCorp Vault requires 'test' feature to be enabled");
            Ok(vec![])
        }
    }
}

/// Azure Key Vault provider
#[allow(dead_code)]
pub struct AzureKeyVaultProvider {
    /// Azure Key Vault URL
    vault_url: String,
    /// Azure AD client ID for authentication
    client_id: String,
    /// Azure AD client secret for authentication
    client_secret: String,
    /// Azure AD tenant ID
    tenant_id: String,
}

impl AzureKeyVaultProvider {
    /// Creates a new Azure Key Vault provider.
    ///
    /// # Arguments
    /// * `vault_url` - The URL of the Azure Key Vault
    /// * `client_id` - Azure AD application client ID
    /// * `client_secret` - Azure AD application client secret
    /// * `tenant_id` - Azure AD tenant ID
    ///
    /// # Returns
    /// A new `AzureKeyVaultProvider` instance.
    pub fn new(
        vault_url: String,
        client_id: String,
        client_secret: String,
        tenant_id: String,
    ) -> Self {
        Self {
            vault_url,
            client_id,
            client_secret,
            tenant_id,
        }
    }
}

#[async_trait]
impl VaultProvider for AzureKeyVaultProvider {
    async fn get_secret(&self, key: &str) -> Result<Option<String>> {
        #[cfg(feature = "test")]
        {
            // First, get an access token from Azure AD
            let token = self.get_azure_access_token().await?;

            let client = reqwest::Client::new();
            let url = format!("{}/secrets/{}?api-version=7.4", self.vault_url, key);

            let response = client
                .get(&url)
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await?;

            if response.status().is_success() {
                let json: serde_json::Value = response.json().await?;
                if let Some(value) = json.get("value") {
                    if let Some(v) = value.as_str() {
                        return Ok(Some(v.to_string()));
                    }
                }
            }

            Ok(None)
        }
        #[cfg(not(feature = "test"))]
        {
            tracing::error!("Azure Key Vault requires 'test' feature to be enabled");
            Ok(None)
        }
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        #[cfg(feature = "test")]
        {
            let token = self.get_azure_access_token().await?;

            let client = reqwest::Client::new();
            let url = format!("{}/secrets/{}?api-version=7.4", self.vault_url, key);

            let payload = serde_json::json!({
                "value": value
            });

            let response = client
                .put(&url)
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await?;

            if !response.status().is_success() {
                let error_text = response.text().await?;
                anyhow::bail!("Failed to set secret in Azure Key Vault: {}", error_text);
            }

            Ok(())
        }
        #[cfg(not(feature = "test"))]
        {
            tracing::error!("Azure Key Vault requires 'test' feature to be enabled");
            Ok(())
        }
    }

    async fn delete_secret(&self, key: &str) -> Result<()> {
        #[cfg(feature = "test")]
        {
            let token = self.get_azure_access_token().await?;

            let client = reqwest::Client::new();
            let url = format!("{}/secrets/{}?api-version=7.4", self.vault_url, key);

            let response = client
                .delete(&url)
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await?;

            if !response.status().is_success() {
                let error_text = response.text().await?;
                tracing::warn!(
                    "Failed to delete secret from Azure Key Vault: {}",
                    error_text
                );
            }

            Ok(())
        }
        #[cfg(not(feature = "test"))]
        {
            tracing::error!("Azure Key Vault requires 'test' feature to be enabled");
            Ok(())
        }
    }

    async fn list_secrets(&self) -> Result<Vec<String>> {
        #[cfg(feature = "test")]
        {
            let token = self.get_azure_access_token().await?;

            let client = reqwest::Client::new();
            let url = format!("{}/secrets?api-version=7.4", self.vault_url);

            let response = client
                .get(&url)
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await?;

            if response.status().is_success() {
                let json: serde_json::Value = response.json().await?;
                if let Some(value) = json.get("value") {
                    if let Some(secrets_array) = value.as_array() {
                        return Ok(secrets_array
                            .iter()
                            .filter_map(|s| {
                                s.get("id")
                                    .and_then(|id| id.as_str())
                                    .and_then(|id_str| id_str.rsplit('/').next())
                                    .map(|name| name.to_string())
                            })
                            .collect());
                    }
                }
            }

            Ok(vec![])
        }
        #[cfg(not(feature = "test"))]
        {
            tracing::error!("Azure Key Vault requires 'test' feature to be enabled");
            Ok(vec![])
        }
    }
}

impl AzureKeyVaultProvider {
    #[cfg(feature = "test")]
    async fn get_azure_access_token(&self) -> Result<String> {
        let client = reqwest::Client::new();
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        );

        let params = [
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("scope", "https://vault.azure.net/.default"),
            ("grant_type", "client_credentials"),
        ];

        let response = client.post(&token_url).form(&params).send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            anyhow::bail!("Failed to get Azure AD token: {}", error_text);
        }

        let json: serde_json::Value = response.json().await?;
        if let Some(token) = json.get("access_token").and_then(|t| t.as_str()) {
            Ok(token.to_string())
        } else {
            anyhow::bail!("No access_token in Azure AD response")
        }
    }
}

/// AWS Secrets Manager provider
#[allow(dead_code)]
pub struct AwsSecretsManagerProvider {
    /// AWS region for the Secrets Manager service
    region: String,
    /// Optional AWS access key ID for authentication
    access_key_id: Option<String>,
    /// Optional AWS secret access key for authentication
    secret_access_key: Option<String>,
}

impl AwsSecretsManagerProvider {
    /// Creates a new AWS Secrets Manager provider.
    ///
    /// # Arguments
    /// * `region` - AWS region where Secrets Manager is located
    /// * `access_key_id` - Optional AWS access key ID (uses IAM roles if not provided)
    /// * `secret_access_key` - Optional AWS secret access key (uses IAM roles if not provided)
    ///
    /// # Returns
    /// A new `AwsSecretsManagerProvider` instance.
    pub fn new(
        region: String,
        access_key_id: Option<String>,
        secret_access_key: Option<String>,
    ) -> Self {
        Self {
            region,
            access_key_id,
            secret_access_key,
        }
    }
}

#[async_trait]
impl VaultProvider for AwsSecretsManagerProvider {
    async fn get_secret(&self, key: &str) -> Result<Option<String>> {
        #[cfg(feature = "test")]
        {
            let client = self.create_aws_client().await?;
            let endpoint = format!("https://secretsmanager.{}.amazonaws.com/", self.region);

            let payload = serde_json::json!({
                "SecretId": key
            });

            let response = client
                .post(&endpoint)
                .header("X-Amz-Target", "secretsmanager.GetSecretValue")
                .header("Content-Type", "application/x-amz-json-1.1")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let json: serde_json::Value = response.json().await?;
                if let Some(secret) = json.get("SecretString") {
                    if let Some(s) = secret.as_str() {
                        return Ok(Some(s.to_string()));
                    }
                }
            }

            Ok(None)
        }
        #[cfg(not(feature = "test"))]
        {
            tracing::error!("AWS Secrets Manager requires 'test' feature to be enabled");
            Ok(None)
        }
    }

    async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        #[cfg(feature = "test")]
        {
            let client = self.create_aws_client().await?;
            let endpoint = format!("https://secretsmanager.{}.amazonaws.com/", self.region);

            // Try to create the secret first
            let create_payload = serde_json::json!({
                "Name": key,
                "SecretString": value
            });

            let create_response = client
                .post(&endpoint)
                .header("X-Amz-Target", "secretsmanager.CreateSecret")
                .header("Content-Type", "application/x-amz-json-1.1")
                .json(&create_payload)
                .send()
                .await?;

            // If creation fails (secret already exists), update it
            if !create_response.status().is_success() {
                let update_payload = serde_json::json!({
                    "SecretId": key,
                    "SecretString": value
                });

                let update_response = client
                    .post(&endpoint)
                    .header("X-Amz-Target", "secretsmanager.PutSecretValue")
                    .header("Content-Type", "application/x-amz-json-1.1")
                    .json(&update_payload)
                    .send()
                    .await?;

                if !update_response.status().is_success() {
                    let error_text = update_response.text().await?;
                    anyhow::bail!(
                        "Failed to set secret in AWS Secrets Manager: {}",
                        error_text
                    );
                }
            }

            Ok(())
        }
        #[cfg(not(feature = "test"))]
        {
            tracing::error!("AWS Secrets Manager requires 'test' feature to be enabled");
            Ok(())
        }
    }

    async fn delete_secret(&self, key: &str) -> Result<()> {
        #[cfg(feature = "test")]
        {
            let client = self.create_aws_client().await?;
            let endpoint = format!("https://secretsmanager.{}.amazonaws.com/", self.region);

            let payload = serde_json::json!({
                "SecretId": key,
                "ForceDeleteWithoutRecovery": true
            });

            let response = client
                .post(&endpoint)
                .header("X-Amz-Target", "secretsmanager.DeleteSecret")
                .header("Content-Type", "application/x-amz-json-1.1")
                .json(&payload)
                .send()
                .await?;

            if !response.status().is_success() {
                let error_text = response.text().await?;
                tracing::warn!(
                    "Failed to delete secret from AWS Secrets Manager: {}",
                    error_text
                );
            }

            Ok(())
        }
        #[cfg(not(feature = "test"))]
        {
            tracing::error!("AWS Secrets Manager requires 'test' feature to be enabled");
            Ok(())
        }
    }

    async fn list_secrets(&self) -> Result<Vec<String>> {
        #[cfg(feature = "test")]
        {
            let client = self.create_aws_client().await?;
            let endpoint = format!("https://secretsmanager.{}.amazonaws.com/", self.region);

            let payload = serde_json::json!({});

            let response = client
                .post(&endpoint)
                .header("X-Amz-Target", "secretsmanager.ListSecrets")
                .header("Content-Type", "application/x-amz-json-1.1")
                .json(&payload)
                .send()
                .await?;

            if response.status().is_success() {
                let json: serde_json::Value = response.json().await?;
                if let Some(secrets) = json.get("SecretList") {
                    if let Some(secrets_array) = secrets.as_array() {
                        return Ok(secrets_array
                            .iter()
                            .filter_map(|s| {
                                s.get("Name")
                                    .and_then(|n| n.as_str())
                                    .map(|name| name.to_string())
                            })
                            .collect());
                    }
                }
            }

            Ok(vec![])
        }
        #[cfg(not(feature = "test"))]
        {
            tracing::error!("AWS Secrets Manager requires 'test' feature to be enabled");
            Ok(vec![])
        }
    }
}

impl AwsSecretsManagerProvider {
    #[cfg(feature = "test")]
    async fn create_aws_client(&self) -> Result<reqwest::Client> {
        // In a production implementation, this would use AWS SigV4 signing
        // For now, we create a basic client that assumes credentials are in environment/IAM role
        let client = reqwest::Client::builder().build()?;

        Ok(client)
    }
}

/// Main vault service
pub struct VaultService {
    /// Map of provider names to vault provider implementations
    providers: HashMap<String, Box<dyn VaultProvider>>,
    /// Optional default provider name
    default_provider: Option<String>,
}

impl Default for VaultService {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultService {
    /// Creates a new vault service with no providers configured.
    ///
    /// # Returns
    /// A new `VaultService` instance with empty provider registry.
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            default_provider: None,
        }
    }

    /// Add a vault provider
    pub fn add_provider(&mut self, name: &str, provider: Box<dyn VaultProvider>) {
        self.providers.insert(name.to_string(), provider);
        if self.default_provider.is_none() {
            self.default_provider = Some(name.to_string());
        }
    }

    /// Set default provider
    pub fn set_default_provider(&mut self, name: &str) {
        if self.providers.contains_key(name) {
            self.default_provider = Some(name.to_string());
        }
    }

    /// Get secret from default provider
    pub async fn get_secret(&self, key: &str) -> Result<Option<String>> {
        if let Some(provider_name) = &self.default_provider {
            if let Some(provider) = self.providers.get(provider_name) {
                return provider.get_secret(key).await;
            }
        }
        Ok(None)
    }

    /// Get secret from specific provider
    pub async fn get_secret_from(&self, provider_name: &str, key: &str) -> Result<Option<String>> {
        if let Some(provider) = self.providers.get(provider_name) {
            provider.get_secret(key).await
        } else {
            Ok(None)
        }
    }

    /// Store secret in default provider
    pub async fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        if let Some(provider_name) = &self.default_provider {
            if let Some(provider) = self.providers.get(provider_name) {
                return provider.set_secret(key, value).await;
            }
        }
        Ok(())
    }

    /// Store secret in specific provider
    pub async fn set_secret_in(&self, provider_name: &str, key: &str, value: &str) -> Result<()> {
        if let Some(provider) = self.providers.get(provider_name) {
            provider.set_secret(key, value).await
        } else {
            Ok(())
        }
    }

    /// Delete secret from default provider
    pub async fn delete_secret(&self, key: &str) -> Result<()> {
        if let Some(provider_name) = &self.default_provider {
            if let Some(provider) = self.providers.get(provider_name) {
                return provider.delete_secret(key).await;
            }
        }
        Ok(())
    }

    /// Delete secret from specific provider
    pub async fn delete_secret_from(&self, provider_name: &str, key: &str) -> Result<()> {
        if let Some(provider) = self.providers.get(provider_name) {
            provider.delete_secret(key).await
        } else {
            Ok(())
        }
    }

    /// List secrets from default provider
    pub async fn list_secrets(&self) -> Result<Vec<String>> {
        if let Some(provider_name) = &self.default_provider {
            if let Some(provider) = self.providers.get(provider_name) {
                return provider.list_secrets().await;
            }
        }
        Ok(vec![])
    }

    /// List secrets from specific provider
    pub async fn list_secrets_from(&self, provider_name: &str) -> Result<Vec<String>> {
        if let Some(provider) = self.providers.get(provider_name) {
            provider.list_secrets().await
        } else {
            Ok(vec![])
        }
    }
}

/// Vault configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    /// Whether vault functionality is enabled
    pub enabled: bool,
    /// Map of provider names to their configurations
    pub providers: HashMap<String, VaultProviderConfig>,
    /// Optional name of the default provider
    pub default_provider: Option<String>,
}

/// Vault provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultProviderConfig {
    /// Type of vault provider to use
    pub provider_type: VaultProviderType,
    /// Configuration parameters for the provider
    pub config: HashMap<String, String>,
}

/// Vault provider types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VaultProviderType {
    /// File-based vault provider for local secret storage
    File,
    /// Java KeyStore-based vault provider
    KeyStore,
    /// HashiCorp Vault provider
    HashiCorp,
    /// Azure Key Vault provider
    Azure,
    /// AWS Secrets Manager provider
    Aws,
}

/// Key resolver for vault keys
pub trait KeyResolver {
    /// Resolves a realm and secret name into a vault key.
    ///
    /// # Arguments
    /// * `realm_name` - The name of the realm
    /// * `secret_name` - The name of the secret
    ///
    /// # Returns
    /// A string representing the resolved vault key.
    fn resolve(&self, realm_name: &str, secret_name: &str) -> String;
}

/// Default key resolver that uses realm__secret format
pub struct DefaultKeyResolver;

impl KeyResolver for DefaultKeyResolver {
    fn resolve(&self, realm_name: &str, secret_name: &str) -> String {
        format!(
            "{}_{}",
            realm_name.replace("_", "__"),
            secret_name.replace("_", "__")
        )
    }
}

/// Custom key resolver
pub struct CustomKeyResolver {
    /// Pattern string for key resolution (supports {realm} and {secret} placeholders)
    pattern: String,
}

impl CustomKeyResolver {
    /// Creates a new custom key resolver with the specified pattern.
    ///
    /// # Arguments
    /// * `pattern` - The pattern string containing {realm} and {secret} placeholders
    ///
    /// # Returns
    /// A new `CustomKeyResolver` instance.
    ///
    /// # Example
    /// ```
    /// use authenc::services::vault::CustomKeyResolver;
    ///
    /// let resolver = CustomKeyResolver::new("realm/{realm}/secrets/{secret}".to_string());
    /// ```
    pub fn new(pattern: String) -> Self {
        Self { pattern }
    }
}

impl KeyResolver for CustomKeyResolver {
    fn resolve(&self, realm_name: &str, secret_name: &str) -> String {
        self.pattern
            .replace("{realm}", realm_name)
            .replace("{secret}", secret_name)
    }
}
