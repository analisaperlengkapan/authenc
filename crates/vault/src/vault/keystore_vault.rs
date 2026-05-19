//! Keystore-based vault provider for Authenc
//!
//! This module provides integration with Java KeyStore (JKS) and PKCS#12 files for
//! secret storage and key management.
//!
//! # Status
//! - JKS and PKCS#12 support via `keytool` and `openssl` CLI tools
//! - Read-only access to keys and certificates (get_secret)
//! - Listing entries (list_secrets)
//! - Deleting entries (delete_secret)
//! - Write support (put_secret) is currently limited/disabled due to complexity of mapping arbitrary strings to Keystore entries.

use super::{Secret, Vault, VaultError};
use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::process::Command;

/// Helper struct to manage temporary password files securely.
/// Deletes the file when dropped.
struct PasswordFile {
    path: PathBuf,
}

impl PasswordFile {
    /// Creates a new temporary file containing the password.
    async fn new(password: &str) -> Result<Self, VaultError> {
        let mut path = std::env::temp_dir();
        path.push(format!("authenc_pass_{}", uuid::Uuid::new_v4()));

        tokio::fs::write(&path, password).await.map_err(|e| {
             VaultError::Other(format!("Failed to create secure password file: {}", e))
        })?;

        Ok(Self { path })
    }
}

impl Drop for PasswordFile {
    fn drop(&mut self) {
        // Best effort cleanup. We use std::fs here because Drop cannot be async.
        // This is a blocking operation but acceptable for temp file cleanup in this context.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Keystore-based vault provider for secure secret storage
///
/// This vault integrates with Java KeyStore (JKS) and PKCS#12 files.
/// It utilizes system tools (`keytool`, `openssl`) to interact with the keystore files.
///
/// # Prerequisites
/// - `keytool` (from JDK/JRE) must be in the PATH
/// - `openssl` must be in the PATH
pub struct KeystoreVault {
    /// Path to the keystore file
    path: Option<PathBuf>,
    /// Password for the keystore
    password: Option<String>,
    /// Type of keystore (JKS, PKCS12, JCEKS)
    store_type: String,
}

impl Default for KeystoreVault {
    fn default() -> Self {
        Self::new()
    }
}

impl KeystoreVault {
    /// Create a new Java KeyStore-based vault
    pub fn new() -> Self {
        KeystoreVault {
            path: None,
            password: None,
            store_type: "PKCS12".to_string(),
        }
    }

    /// Create a new keystore vault with a specific path and password
    ///
    /// # Arguments
    /// * `path` - Path to the keystore file
    /// * `password` - Password for the keystore
    /// * `store_type` - Type of keystore (e.g., "JKS", "PKCS12")
    pub fn with_config(path: &str, password: Option<String>, store_type: Option<String>) -> Self {
        KeystoreVault {
            path: Some(PathBuf::from(path)),
            password,
            store_type: store_type.unwrap_or_else(|| "PKCS12".to_string()),
        }
    }

    /// Helper to detect if keystore is JKS based on extension or configured type
    fn is_jks(&self) -> bool {
        if self.store_type.to_uppercase() == "JKS" {
            return true;
        }
        if let Some(path) = &self.path
            && let Some(ext) = path.extension()
                && let Some(ext_str) = ext.to_str() {
                    return ext_str.eq_ignore_ascii_case("jks") || ext_str.eq_ignore_ascii_case("ks");
                }
        false
    }

    /// Helper to get the path to the PKCS#12 file.
    /// If the store is JKS, this converts it to a temporary PKCS#12 file.
    /// Returns (PathBuf, bool) where bool indicates if the file is temporary and should be deleted.
    async fn get_p12_path(&self) -> Result<(PathBuf, bool), VaultError> {
        let path = self.path.as_ref().ok_or_else(|| {
            VaultError::Unavailable("Keystore path not configured".to_string())
        })?;

        if !path.exists() {
            return Err(VaultError::NotFound(format!(
                "Keystore file not found: {:?}",
                path
            )));
        }

        if self.is_jks() {
            // Convert JKS to PKCS12
            let temp_dir = std::env::temp_dir();
            let temp_file = temp_dir.join(format!("authenc_convert_{}.p12", uuid::Uuid::new_v4()));

            let password = self.password.as_deref().unwrap_or("");

            // Use temporary file for password to avoid process listing exposure
            let pass_file = PasswordFile::new(password).await?;

            // keytool -importkeystore -srckeystore <jks> -destkeystore <p12> -srcstoretype JKS -deststoretype PKCS12 -srcstorepass:file <path> ...
            let mut cmd = Command::new("keytool");
            cmd.arg("-importkeystore")
                .arg("-srckeystore")
                .arg(path)
                .arg("-destkeystore")
                .arg(&temp_file)
                .arg("-srcstoretype")
                .arg("JKS")
                .arg("-deststoretype")
                .arg("PKCS12")
                .arg("-noprompt");

            // Pass passwords via file for security
            cmd.arg("-srcstorepass:file").arg(&pass_file.path);
            cmd.arg("-deststorepass:file").arg(&pass_file.path);

            let output = cmd.output().await.map_err(|e| {
                VaultError::Unavailable(format!("Failed to execute keytool: {}", e))
            })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(VaultError::Other(format!(
                    "Failed to convert JKS to PKCS12: {}",
                    stderr
                )));
            }

            Ok((temp_file, true))
        } else {
            Ok((path.clone(), false))
        }
    }
}

#[async_trait]
impl Vault for KeystoreVault {
    async fn get_secret(&self, key: &str, _realm: Option<&str>) -> Option<Secret> {
        // We use openssl to extract the key/cert
        let (p12_path, is_temp) = match self.get_p12_path().await {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("Failed to prepare keystore: {}", e);
                return None;
            }
        };

        let result: Result<Option<Secret>, VaultError> = async {
             // openssl pkcs12 -in <file> -nodes -passin pass:<pass>
            let mut cmd = Command::new("openssl");
            cmd.arg("pkcs12")
                .arg("-in")
                .arg(&p12_path)
                .arg("-nodes"); // Don't encrypt private keys in output

            if let Some(pass) = &self.password {
                cmd.env("P12_PASS", pass);
                cmd.arg("-passin").arg("env:P12_PASS");
            } else {
                 cmd.arg("-passin").arg("pass:");
            }

            let output = cmd.output().await.map_err(|e| {
                VaultError::Unavailable(format!("Failed to execute openssl: {}", e))
            })?;

            if !output.status.success() {
                 // OpenSSL failed (wrong password? bad file?)
                 tracing::warn!("OpenSSL pkcs12 dump failed: {}", String::from_utf8_lossy(&output.stderr));
                 return Ok(None);
            }

            let stdout = String::from_utf8_lossy(&output.stdout);

            // Parse the output to find the entry with the matching friendlyName
            // OpenSSL output format:
            // Bag Attributes
            //     friendlyName: <alias>
            // ... PEM block ...

            // We split by "Bag Attributes"
            let parts: Vec<&str> = stdout.split("Bag Attributes").collect();
            let mut secret_value = String::new();
            let mut found_any = false;

            for part in parts {
                if part.contains(&format!("friendlyName: {}", key)) || part.contains(&format!("friendlyName:{}", key)) {
                     found_any = true;
                     // This part belongs to our key
                     // Extract PEM blocks

                     // Look for Private Key
                     if let Some(start) = part.find("-----BEGIN PRIVATE KEY-----")
                         && let Some(end) = part[start..].find("-----END PRIVATE KEY-----") {
                             secret_value.push_str(&part[start..start+end+25]);
                             secret_value.push('\n');
                         }

                     // Look for RSA Private Key (legacy)
                     if let Some(start) = part.find("-----BEGIN RSA PRIVATE KEY-----")
                         && let Some(end) = part[start..].find("-----END RSA PRIVATE KEY-----") {
                             secret_value.push_str(&part[start..start+end+29]);
                             secret_value.push('\n');
                         }

                     // Look for Encrypted Private Key
                     if let Some(start) = part.find("-----BEGIN ENCRYPTED PRIVATE KEY-----")
                         && let Some(end) = part[start..].find("-----END ENCRYPTED PRIVATE KEY-----") {
                             secret_value.push_str(&part[start..start+end+35]);
                             secret_value.push('\n');
                         }

                     // Look for Certificate
                     if let Some(start) = part.find("-----BEGIN CERTIFICATE-----")
                         && let Some(end) = part[start..].find("-----END CERTIFICATE-----") {
                             secret_value.push_str(&part[start..start+end+25]);
                             secret_value.push('\n');
                         }
                }
            }

            if found_any && !secret_value.is_empty() {
                 return Ok(Some(Secret {
                     value: secret_value.trim().to_string(),
                     metadata: None,
                     version: None,
                     created_at: None,
                     expires_at: None,
                 }));
            }

            Ok(None)
        }.await;

        // Clean up temp file
        if is_temp {
            let _ = tokio::fs::remove_file(p12_path).await;
        }

        result.unwrap_or_default()
    }

    async fn put_secret(
        &self,
        _key: &str,
        _value: &str,
        _realm: Option<&str>,
        _metadata: Option<HashMap<String, String>>,
    ) -> Result<(), VaultError> {
        // Implementing put_secret is complex because we need to know if the value is a Key, Cert, or generic secret.
        // For now, we defer this.
        tracing::warn!("KeystoreVault::put_secret is not implemented. Use keytool to manage the keystore file directly.");
        Err(VaultError::NotImplemented(
            "Writing secrets to KeystoreVault is not supported via this API. Please use 'keytool' to manage the keystore.".to_string()
        ))
    }

    async fn delete_secret(&self, key: &str, _realm: Option<&str>) -> Result<(), VaultError> {
        let path = self.path.as_ref().ok_or_else(|| {
            VaultError::Unavailable("Keystore path not configured".to_string())
        })?;

        // keytool -delete -alias <key> -keystore <path>
        let mut cmd = Command::new("keytool");
        cmd.arg("-delete")
            .arg("-alias")
            .arg(key)
            .arg("-keystore")
            .arg(path);

        if self.is_jks() {
             cmd.arg("-storetype").arg("JKS");
        } else {
             cmd.arg("-storetype").arg("PKCS12");
        }

        if let Some(pass) = &self.password {
             cmd.arg("-storepass").arg(pass);
        }

        let output = cmd.output().await.map_err(|e| {
            VaultError::Unavailable(format!("Failed to execute keytool: {}", e))
        })?;

        if !output.status.success() {
             let stderr = String::from_utf8_lossy(&output.stderr);
             if stderr.contains("Alias <") && stderr.contains("> does not exist") {
                 return Err(VaultError::NotFound(format!("Secret '{}' not found", key)));
             }
             return Err(VaultError::Other(format!("Failed to delete secret: {}", stderr)));
        }

        Ok(())
    }

    async fn list_secrets(&self, _realm: Option<&str>) -> Result<Vec<String>, VaultError> {
         let path = self.path.as_ref().ok_or_else(|| {
            VaultError::Unavailable("Keystore path not configured".to_string())
        })?;

        // keytool -list -keystore <path>
        let mut cmd = Command::new("keytool");
        cmd.arg("-list")
            .arg("-keystore")
            .arg(path);

        // Use -rfc to get consistent alias format "Alias name: <alias>"
        // This is much more reliable than parsing the tabular output which varies by version/locale
        cmd.arg("-rfc");

        if self.is_jks() {
             cmd.arg("-storetype").arg("JKS");
        } else {
             cmd.arg("-storetype").arg("PKCS12");
        }

        if let Some(pass) = &self.password {
             cmd.arg("-storepass").arg(pass);
        }

        let output = cmd.output().await.map_err(|e| {
            VaultError::Unavailable(format!("Failed to execute keytool: {}", e))
        })?;

        // keytool may output to stderr even on success in some versions or if there are warnings
        // Check status first
        if !output.status.success() {
             let stderr = String::from_utf8_lossy(&output.stderr);
             return Err(VaultError::Other(format!("Failed to list secrets: {}", stderr)));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut secrets = Vec::new();

        for line in stdout.lines() {
            // RFC format always outputs "Alias name: <alias>"
            if line.trim().starts_with("Alias name: ") {
                 let alias = line.trim().trim_start_matches("Alias name: ").trim();
                 if !alias.is_empty() {
                     secrets.push(alias.to_string());
                 }
            }
        }

        // Final fallback: try regex or simpler parsing if the above failed but we have content
        if secrets.is_empty() && !stdout.is_empty() {
             // Maybe it's not "Alias name: " but just "Alias name:"?
             for line in stdout.lines() {
                 if line.trim().starts_with("Alias name:") {
                     let alias = line.trim().trim_start_matches("Alias name:").trim();
                     if !alias.is_empty() {
                         secrets.push(alias.to_string());
                     }
                 }
             }
        }

        Ok(secrets)
    }

    async fn rotate_secret(
        &self,
        _key: &str,
        _realm: Option<&str>,
        _generator: Box<dyn Fn() -> String + Send>,
    ) -> Result<super::RotationResult, VaultError> {
        Err(VaultError::NotImplemented(
            "Secret rotation is not supported for KeystoreVault.".to_string()
        ))
    }

    async fn get_secret_versions(
        &self,
        _key: &str,
        _realm: Option<&str>,
    ) -> Result<Vec<Secret>, VaultError> {
        Err(VaultError::NotImplemented(
            "Versioning is not supported for KeystoreVault.".to_string()
        ))
    }

    async fn health_check(&self) -> Result<bool, VaultError> {
        if let Some(path) = &self.path {
            if !path.exists() {
                return Ok(false);
            }
            // Try listing to verify password/integrity
            match self.list_secrets(None).await {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            Ok(false)
        }
    }
}
