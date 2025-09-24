use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use uuid::Uuid;

use crate::error::{Result, AuthencError as Error};
use crate::models::user::UserProfile;
use crate::models::User;
use crate::spi::{Provider, ProviderFactory, Spi, ProviderConfig, SpiError};

/// SPI for LDAP and Active Directory federation
#[async_trait]
pub trait LdapFederationProvider: Provider {
    /// Check if the provider is enabled
    fn is_enabled(&self) -> bool {
        true
    }

    /// Authenticate user against LDAP/AD
    async fn authenticate(&self, username: &str, password: &str) -> Result<Option<User>>;

    /// Import user from LDAP/AD
    async fn import_user(&self, username: &str) -> Result<Option<User>>;

    /// Sync user attributes from LDAP/AD
    async fn sync_user_attributes(&self, user_id: &str) -> Result<UserProfile>;

    /// Search users in LDAP/AD
    async fn search_users(&self, query: &str, limit: usize) -> Result<Vec<User>>;

    /// Check if user exists in LDAP/AD
    async fn user_exists(&self, username: &str) -> Result<bool>;

    /// Get LDAP/AD connection status
    async fn is_connected(&self) -> bool;
}

/// Configuration for LDAP federation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapFederationConfig {
    /// LDAP server URL (e.g., "ldap://localhost:389" or "ldaps://localhost:636")
    pub server_url: String,

    /// Base DN for searches
    pub base_dn: String,

    /// Bind DN for authentication
    pub bind_dn: Option<String>,

    /// Bind password
    pub bind_password: Option<String>,

    /// User search filter (default: "(uid={0})")
    pub user_search_filter: Option<String>,

    /// Username attribute (default: "uid")
    pub username_attribute: Option<String>,

    /// RDN attribute (default: "uid")
    pub rdn_attribute: Option<String>,

    /// UUID attribute (default: "entryUUID")
    pub uuid_attribute: Option<String>,

    /// User object classes (default: ["person", "organizationalPerson", "user"])
    pub user_object_classes: Option<Vec<String>>,

    /// Connection timeout in seconds
    pub connection_timeout: Option<u64>,

    /// Read timeout in seconds
    pub read_timeout: Option<u64>,

    /// Connection pool size
    pub connection_pool_size: Option<usize>,

    /// Use SSL/TLS
    pub use_ssl: Option<bool>,

    /// Trust store path for SSL
    pub trust_store_path: Option<String>,

    /// Trust store password
    pub trust_store_password: Option<String>,

    /// Custom user attributes mapping
    pub custom_user_attributes: Option<HashMap<String, String>>,

    /// Enable user import
    pub import_enabled: Option<bool>,

    /// Enable periodic sync
    pub sync_enabled: Option<bool>,

    /// Sync interval in minutes
    pub sync_interval: Option<u64>,

    /// Batch size for sync operations
    pub batch_size: Option<usize>,
}

impl Default for LdapFederationConfig {
    fn default() -> Self {
        Self {
            server_url: "ldap://localhost:389".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: None,
            bind_password: None,
            user_search_filter: Some("(uid={0})".to_string()),
            username_attribute: Some("uid".to_string()),
            rdn_attribute: Some("uid".to_string()),
            uuid_attribute: Some("entryUUID".to_string()),
            user_object_classes: Some(vec![
                "person".to_string(),
                "organizationalPerson".to_string(),
                "user".to_string(),
            ]),
            connection_timeout: Some(30),
            read_timeout: Some(30),
            connection_pool_size: Some(10),
            use_ssl: Some(false),
            trust_store_path: None,
            trust_store_password: None,
            custom_user_attributes: None,
            import_enabled: Some(true),
            sync_enabled: Some(false),
            sync_interval: Some(60),
            batch_size: Some(100),
        }
    }
}

/// Factory for creating LDAP federation providers
#[async_trait]
pub trait LdapFederationProviderFactory: ProviderFactory<dyn LdapFederationProvider> {
    /// Create a new LDAP federation provider
    async fn create(&self, config: &LdapFederationConfig) -> Result<Arc<dyn LdapFederationProvider>>;
}

/// Default implementation of LDAP federation provider
pub struct DefaultLdapFederationProvider {
    config: LdapFederationConfig,
}

impl DefaultLdapFederationProvider {
    pub fn new(config: LdapFederationConfig) -> Self {
        Self { config }
    }

    /// Create LDAP connection
    async fn create_ldap_connection(&self) -> Result<LdapConn> {
        let settings = LdapConnSettings::new()
            .set_starttls(self.config.use_ssl.unwrap_or(false));

        let mut ldap = LdapConn::with_settings(settings, &self.config.server_url)
            .map_err(|e| Error::validation(format!("Failed to create LDAP connection: {}", e)))?;

        // Bind with service account if configured
        if let (Some(bind_dn), Some(bind_password)) = (&self.config.bind_dn, &self.config.bind_password) {
            ldap.simple_bind(bind_dn, bind_password)
                .map_err(|e| Error::validation(format!("Failed to bind to LDAP: {}", e)))?;
        }

        Ok(ldap)
    }

    /// Build user search filter
    fn build_user_filter(&self, username: &str) -> String {
        self.config.user_search_filter
            .as_ref()
            .unwrap_or(&"(uid={0})".to_string())
            .replace("{0}", username)
    }

    /// Extract user from LDAP entry
    fn extract_user_from_entry(&self, entry: &SearchEntry, username: &str) -> User {
        let attrs = &entry.attrs;

        let email = attrs.get("mail")
            .and_then(|v| v.first())
            .map(|s| s.to_string());

        let first_name = attrs.get("givenName")
            .and_then(|v| v.first())
            .map(|s| s.to_string());

        let last_name = attrs.get("sn")
            .and_then(|v| v.first())
            .map(|s| s.to_string());

        let mut attributes = serde_json::Map::new();

        // Add standard attributes
        if let Some(ref fname) = first_name {
            attributes.insert("firstName".to_string(), serde_json::Value::String(fname.clone()));
        }
        if let Some(ref lname) = last_name {
            attributes.insert("lastName".to_string(), serde_json::Value::String(lname.clone()));
        }

        // Add custom attributes
        if let Some(custom_attrs) = &self.config.custom_user_attributes {
            for (key, ldap_attr) in custom_attrs {
                if let Some(values) = attrs.get(ldap_attr) {
                    if let Some(value) = values.first() {
                        attributes.insert(key.clone(), serde_json::Value::String(value.clone()));
                    }
                }
            }
        }

        let mut user = User::new(
            username.to_string(),
            email.unwrap_or_else(|| format!("{}@ldap.local", username)),
            None, // No password hash for LDAP users
            Some(Uuid::new_v4()), // Default realm - should be configurable
        );

        user.first_name = first_name;
        user.last_name = last_name;
        user.attributes = Some(serde_json::Value::Object(attributes));
        user.federated = true;

        user
    }
}

#[async_trait]
impl Provider for DefaultLdapFederationProvider {
    async fn close(&mut self) -> () {
        // LDAP connections are automatically closed when Ldap goes out of scope
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[async_trait]
impl LdapFederationProvider for DefaultLdapFederationProvider {
    async fn authenticate(&self, username: &str, password: &str) -> Result<Option<User>> {
        let mut ldap = self.create_ldap_connection().await?;

        // First, search for the user to get their DN
        let filter = self.build_user_filter(username);
        let search_result = ldap.search(
            &self.config.base_dn,
            Scope::Subtree,
            &filter,
            vec!["dn", "uid", "mail", "givenName", "sn"],
        )
        .map_err(|e| Error::validation(format!("LDAP search failed: {}", e)))?;

        let entries = search_result.0;
        if entries.is_empty() {
            return Ok(None); // User not found
        }

        let entry = SearchEntry::construct(entries[0].clone());
        let user_dn = entry.dn;

        // Now try to bind with user credentials
        let auth_result = match ldap.simple_bind(&user_dn, password) {
            Ok(_) => true,
            Err(_) => false,
        };

        if auth_result {
            // Get user info again for creating User object
            let search_result = ldap.search(
                &self.config.base_dn,
                Scope::Subtree,
                &filter,
                vec!["dn", "uid", "mail", "givenName", "sn"],
            )
            .map_err(|e| Error::validation(format!("LDAP search failed: {}", e)))?;

            let entries = search_result.0;
            if entries.is_empty() {
                return Ok(None);
            }

            let entry = SearchEntry::construct(entries[0].clone());
            let user = self.extract_user_from_entry(&entry, username);
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    async fn import_user(&self, username: &str) -> Result<Option<User>> {
        if !self.config.import_enabled.unwrap_or(true) {
            return Ok(None);
        }

        let mut ldap = self.create_ldap_connection().await?;
        let filter = self.build_user_filter(username);
        let search_result = ldap.search(
            &self.config.base_dn,
            Scope::Subtree,
            &filter,
            vec!["dn", "uid", "mail", "givenName", "sn", "entryUUID"],
        )
        .map_err(|e| Error::validation(format!("LDAP search failed: {}", e)))?;

        let entries = search_result.0;
        if entries.is_empty() {
            return Ok(None); // User not found
        }

        let entry = SearchEntry::construct(entries[0].clone());
        let user = self.extract_user_from_entry(&entry, username);
        Ok(Some(user))
    }

    async fn sync_user_attributes(&self, user_id: &str) -> Result<UserProfile> {
        let mut ldap = self.create_ldap_connection().await?;
        let filter = format!("({}={})",
            self.config.username_attribute.as_ref().unwrap_or(&"uid".to_string()),
            user_id
        );

        let search_result = ldap.search(
            &self.config.base_dn,
            Scope::Subtree,
            &filter,
            vec!["dn", "uid", "mail", "givenName", "sn", "entryUUID", "memberOf"],
        )
        .map_err(|e| Error::validation(format!("LDAP search failed: {}", e)))?;

        let entries = search_result.0;
        if entries.is_empty() {
            return Err(Error::validation("User not found in LDAP".to_string()));
        }

        let entry = SearchEntry::construct(entries[0].clone());
        let attrs = &entry.attrs;

        // Parse user_id as Uuid, fallback to new UUID if parsing fails
        let user_uuid = Uuid::parse_str(user_id).unwrap_or_else(|_| Uuid::new_v4());

        let mut profile = UserProfile {
            user_id: user_uuid,
            avatar_url: None,
            bio: None,
            website: None,
            location: None,
            timezone: None,
            locale: None,
            theme: None,
            preferences: None,
            updated_at: chrono::Utc::now(),
        };

        // Create preferences map for LDAP attributes
        let mut preferences = serde_json::Map::new();

        // Extract standard attributes
        if let Some(email) = attrs.get("mail").and_then(|v| v.first()) {
            preferences.insert("email".to_string(), serde_json::Value::String(email.clone()));
        }

        if let Some(first_name) = attrs.get("givenName").and_then(|v| v.first()) {
            preferences.insert("firstName".to_string(), serde_json::Value::String(first_name.clone()));
        }

        if let Some(last_name) = attrs.get("sn").and_then(|v| v.first()) {
            preferences.insert("lastName".to_string(), serde_json::Value::String(last_name.clone()));
        }

        // Extract groups
        if let Some(groups) = attrs.get("memberOf") {
            let groups_array: Vec<serde_json::Value> = groups.iter()
                .map(|g| serde_json::Value::String(g.clone()))
                .collect();
            preferences.insert("groups".to_string(), serde_json::Value::Array(groups_array));
        }

        // Add custom attributes
        if let Some(custom_attrs) = &self.config.custom_user_attributes {
            for (key, ldap_attr) in custom_attrs {
                if let Some(values) = attrs.get(ldap_attr) {
                    let values_array: Vec<serde_json::Value> = values.iter()
                        .map(|v| serde_json::Value::String(v.clone()))
                        .collect();
                    preferences.insert(key.clone(), serde_json::Value::Array(values_array));
                }
            }
        }

        if !preferences.is_empty() {
            profile.preferences = Some(serde_json::Value::Object(preferences));
        }

        Ok(profile)
    }

    async fn search_users(&self, query: &str, limit: usize) -> Result<Vec<User>> {
        let mut ldap = self.create_ldap_connection().await?;
        let filter = format!("(|(uid=*{0}*)(mail=*{0}*)(givenName=*{0}*)(sn=*{0}*))", query);
        let search_result = ldap.search(
            &self.config.base_dn,
            Scope::Subtree,
            &filter,
            vec!["dn", "uid", "mail", "givenName", "sn"],
        )
        .map_err(|e| Error::validation(format!("LDAP search failed: {}", e)))?;

        let mut users = Vec::new();
        let max_results = std::cmp::min(search_result.0.len(), limit);

        for i in 0..max_results {
            let entry = SearchEntry::construct(search_result.0[i].clone());
            let username = entry.attrs.get("uid")
                .and_then(|v| v.first())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("user{}", i));

            let user = self.extract_user_from_entry(&entry, &username);
            users.push(user);
        }

        Ok(users)
    }

    async fn user_exists(&self, username: &str) -> Result<bool> {
        let mut ldap = self.create_ldap_connection().await?;
        let filter = self.build_user_filter(username);
        let search_result = ldap.search(
            &self.config.base_dn,
            Scope::Subtree,
            &filter,
            vec!["dn"],
        )
        .map_err(|e| Error::validation(format!("LDAP search failed: {}", e)))?;

        Ok(!search_result.0.is_empty())
    }

    async fn is_connected(&self) -> bool {
        match self.create_ldap_connection().await {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

/// Default factory for LDAP federation providers
pub struct DefaultLdapFederationProviderFactory;

impl DefaultLdapFederationProviderFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProviderFactory<dyn LdapFederationProvider> for DefaultLdapFederationProviderFactory {
    async fn create(&self, config: &ProviderConfig) -> std::result::Result<Box<dyn LdapFederationProvider>, SpiError> {
        let ldap_config: LdapFederationConfig = serde_json::from_value(
            serde_json::Value::Object(config.properties.iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect())
        ).map_err(|e| SpiError::ConfigurationError(e.to_string()))?;
        let provider = DefaultLdapFederationProvider::new(ldap_config);
        Ok(Box::new(provider))
    }

    fn get_id(&self) -> &'static str {
        "default"
    }
}

#[async_trait]
impl LdapFederationProviderFactory for DefaultLdapFederationProviderFactory {
    async fn create(&self, config: &LdapFederationConfig) -> Result<Arc<dyn LdapFederationProvider>> {
        let provider = DefaultLdapFederationProvider::new(config.clone());
        Ok(Arc::new(provider))
    }
}

/// SPI definition for LDAP federation
pub struct LdapFederationSpi;

impl Spi for LdapFederationSpi {
    fn get_name(&self) -> &'static str {
        "ldap-federation"
    }

    fn get_provider_class(&self) -> &'static str {
        "org.keycloak.storage.ldap.LdapFederationProvider"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "org.keycloak.storage.ldap.LdapFederationProviderFactory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_default_ldap_federation_provider() {
        let config = LdapFederationConfig::default();
        let provider = DefaultLdapFederationProvider::new(config);

        assert!(provider.is_enabled());
        // Note: is_connected() will return false without a real LDAP server
        // assert!(provider.is_connected().await);
    }

    #[tokio::test]
    async fn test_ldap_federation_config() {
        let config = LdapFederationConfig::default();

        assert_eq!(config.server_url, "ldap://localhost:389");
        assert_eq!(config.base_dn, "dc=example,dc=com");
        assert_eq!(config.user_search_filter, Some("(uid={0})".to_string()));
        assert_eq!(config.username_attribute, Some("uid".to_string()));
    }

    #[tokio::test]
    async fn test_default_ldap_federation_factory() {
        let factory = DefaultLdapFederationProviderFactory::new();
        let config = LdapFederationConfig::default();

        // Create ProviderConfig with LDAP config properties
        let mut provider_config = ProviderConfig::new();
        provider_config.set_property("server_url".to_string(), config.server_url.clone());
        provider_config.set_property("base_dn".to_string(), config.base_dn.clone());

        let provider = <DefaultLdapFederationProviderFactory as ProviderFactory<dyn LdapFederationProvider>>::create(&factory, &provider_config).await.unwrap();
        assert!(provider.is_enabled());
    }
}
