use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;

use crate::spi::{Provider, ProviderFactory, Spi, ProviderConfig, SpiError};

/// Policy error for validation failures
#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyError {
    pub message: String,
    pub parameters: Vec<String>,
}

impl PolicyError {
    pub fn new(message: String, parameters: Vec<String>) -> Self {
        Self { message, parameters }
    }

    pub fn simple(message: String) -> Self {
        Self::new(message, vec![])
    }

    pub fn get_message(&self) -> &str {
        &self.message
    }

    pub fn get_parameters(&self) -> &[String] {
        &self.parameters
    }
}

/// Password policy configuration exception
#[derive(Debug, Clone)]
pub struct PasswordPolicyConfigException {
    pub message: String,
}

impl PasswordPolicyConfigException {
    pub fn new(message: String) -> Self {
        Self { message }
    }
}

impl std::fmt::Display for PasswordPolicyConfigException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Password policy config error: {}", self.message)
    }
}

impl std::error::Error for PasswordPolicyConfigException {}

/// Result type for policy validation
pub type PolicyResult<T> = std::result::Result<T, PolicyError>;

/// Password policy provider trait
#[async_trait]
pub trait PasswordPolicyProvider: Provider + Send + Sync {
    /// Validate password against policy for a specific realm and user
    async fn validate(&self, realm_id: &str, user_id: Option<&str>, password: &str) -> PolicyResult<()>;

    /// Validate password against policy (simple version without realm/user context)
    async fn validate_simple(&self, user: Option<&str>, password: &str) -> PolicyResult<()>;

    /// Parse configuration value
    fn parse_config(&self, value: &str) -> std::result::Result<serde_json::Value, PolicyError>;

    /// Parse integer configuration value with default
    fn parse_integer(&self, value: Option<&str>, default_value: Option<i32>) -> std::result::Result<i32, PolicyError> {
        match value {
            Some(v) => v.parse::<i32>().map_err(|_| {
                PolicyError::simple(format!("Not a valid number: {}", v))
            }),
            None => default_value.ok_or_else(|| {
                PolicyError::simple("Integer value required but not provided".to_string())
            }),
        }
    }

    /// Get the policy name
    fn get_policy_name(&self) -> &str;
}

/// Length password policy provider
pub struct LengthPasswordPolicyProvider {
    min_length: Option<i32>,
}

impl LengthPasswordPolicyProvider {
    pub fn new(min_length: Option<i32>) -> Self {
        Self { min_length }
    }
}

#[async_trait]
impl PasswordPolicyProvider for LengthPasswordPolicyProvider {
    async fn validate(&self, _realm_id: &str, _user_id: Option<&str>, password: &str) -> Result<(), PolicyError> {
        let min_len = self.min_length.unwrap_or(8) as usize;
        if password.len() < min_len {
            return Err(PolicyError::new(
                format!("Password must be at least {} characters long", min_len),
                vec![min_len.to_string()],
            ));
        }
        Ok(())
    }

    async fn validate_simple(&self, _user: Option<&str>, password: &str) -> Result<(), PolicyError> {
        self.validate("", None, password).await
    }

    fn parse_config(&self, value: &str) -> std::result::Result<serde_json::Value, PolicyError> {
        let length: i32 = value.parse().map_err(|_| {
            PolicyError::simple(format!("Invalid length value: {}", value))
        })?;
        Ok(serde_json::json!(length))
    }

    fn get_policy_name(&self) -> &str {
        "length"
    }
}

impl Provider for LengthPasswordPolicyProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Hash password policy provider (checks for common patterns)
pub struct HashPasswordPolicyProvider;

impl HashPasswordPolicyProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PasswordPolicyProvider for HashPasswordPolicyProvider {
    async fn validate(&self, _realm_id: &str, user_id: Option<&str>, password: &str) -> PolicyResult<()> {
        // Check for common weak patterns
        let lower_password = password.to_lowercase();

        // Check if password contains username
        if let Some(user) = user_id {
            if lower_password.contains(&user.to_lowercase()) {
                return Err(PolicyError::simple("Password cannot contain username".to_string()));
            }
        }

        // Check for sequential characters
        let sequential_patterns = ["123", "abc", "qwe", "asd", "zxc"];
        for pattern in &sequential_patterns {
            if lower_password.contains(pattern) {
                return Err(PolicyError::simple("Password cannot contain sequential characters".to_string()));
            }
        }

        // Check for repeated characters
        let chars: Vec<char> = password.chars().collect();
        for window in chars.windows(3) {
            if window[0] == window[1] && window[1] == window[2] {
                return Err(PolicyError::simple("Password cannot contain repeated characters".to_string()));
            }
        }

        Ok(())
    }

    async fn validate_simple(&self, user: Option<&str>, password: &str) -> PolicyResult<()> {
        self.validate("", user, password).await
    }

    fn parse_config(&self, _value: &str) -> std::result::Result<serde_json::Value, PolicyError> {
        Ok(serde_json::json!(null))
    }

    fn get_policy_name(&self) -> &str {
        "hash"
    }
}

impl Provider for HashPasswordPolicyProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Uppercase password policy provider
pub struct UppercasePasswordPolicyProvider;

impl UppercasePasswordPolicyProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PasswordPolicyProvider for UppercasePasswordPolicyProvider {
    async fn validate(&self, _realm_id: &str, _user_id: Option<&str>, password: &str) -> PolicyResult<()> {
        if !password.chars().any(|c| c.is_uppercase()) {
            return Err(PolicyError::simple("Password must contain at least one uppercase letter".to_string()));
        }
        Ok(())
    }

    async fn validate_simple(&self, _user: Option<&str>, password: &str) -> PolicyResult<()> {
        self.validate("", None, password).await
    }

    fn parse_config(&self, _value: &str) -> std::result::Result<serde_json::Value, PolicyError> {
        Ok(serde_json::json!(null))
    }

    fn get_policy_name(&self) -> &str {
        "upperCase"
    }
}

impl Provider for UppercasePasswordPolicyProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Lowercase password policy provider
pub struct LowercasePasswordPolicyProvider;

impl LowercasePasswordPolicyProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PasswordPolicyProvider for LowercasePasswordPolicyProvider {
    async fn validate(&self, _realm_id: &str, _user_id: Option<&str>, password: &str) -> PolicyResult<()> {
        if !password.chars().any(|c| c.is_lowercase()) {
            return Err(PolicyError::simple("Password must contain at least one lowercase letter".to_string()));
        }
        Ok(())
    }

    async fn validate_simple(&self, _user: Option<&str>, password: &str) -> PolicyResult<()> {
        self.validate("", None, password).await
    }

    fn parse_config(&self, _value: &str) -> std::result::Result<serde_json::Value, PolicyError> {
        Ok(serde_json::json!(null))
    }

    fn get_policy_name(&self) -> &str {
        "lowerCase"
    }
}

impl Provider for LowercasePasswordPolicyProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Digits password policy provider
pub struct DigitsPasswordPolicyProvider;

impl DigitsPasswordPolicyProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PasswordPolicyProvider for DigitsPasswordPolicyProvider {
    async fn validate(&self, _realm_id: &str, _user_id: Option<&str>, password: &str) -> PolicyResult<()> {
        if !password.chars().any(|c| c.is_digit(10)) {
            return Err(PolicyError::simple("Password must contain at least one digit".to_string()));
        }
        Ok(())
    }

    async fn validate_simple(&self, _user: Option<&str>, password: &str) -> PolicyResult<()> {
        self.validate("", None, password).await
    }

    fn parse_config(&self, _value: &str) -> std::result::Result<serde_json::Value, PolicyError> {
        Ok(serde_json::json!(null))
    }

    fn get_policy_name(&self) -> &str {
        "digits"
    }
}

impl Provider for DigitsPasswordPolicyProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Special characters password policy provider
pub struct SpecialCharsPasswordPolicyProvider;

impl SpecialCharsPasswordPolicyProvider {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PasswordPolicyProvider for SpecialCharsPasswordPolicyProvider {
    async fn validate(&self, _realm_id: &str, _user_id: Option<&str>, password: &str) -> PolicyResult<()> {
        let special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        if !password.chars().any(|c| special_chars.contains(c)) {
            return Err(PolicyError::simple("Password must contain at least one special character".to_string()));
        }
        Ok(())
    }

    async fn validate_simple(&self, _user: Option<&str>, password: &str) -> PolicyResult<()> {
        self.validate("", None, password).await
    }

    fn parse_config(&self, _value: &str) -> std::result::Result<serde_json::Value, PolicyError> {
        Ok(serde_json::json!(null))
    }

    fn get_policy_name(&self) -> &str {
        "specialChars"
    }
}

impl Provider for SpecialCharsPasswordPolicyProvider {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Password policy manager for coordinating multiple policies
#[async_trait]
pub trait PasswordPolicyManager: Provider + Send + Sync {
    /// Validate password against all configured policies
    async fn validate(&self, realm_id: &str, user_id: Option<&str>, password: &str) -> Result<(), Vec<PolicyError>>;

    /// Add a password policy provider
    fn add_policy(&mut self, policy: Box<dyn PasswordPolicyProvider>);

    /// Remove a password policy provider
    fn remove_policy(&mut self, policy_name: &str);

    /// Get all configured policies
    fn get_policies(&self) -> Vec<&dyn PasswordPolicyProvider>;
}

/// Default password policy manager implementation
pub struct DefaultPasswordPolicyManager {
    policies: Vec<Box<dyn PasswordPolicyProvider>>,
}

impl DefaultPasswordPolicyManager {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }
}

#[async_trait]
impl PasswordPolicyManager for DefaultPasswordPolicyManager {
    async fn validate(&self, realm_id: &str, user_id: Option<&str>, password: &str) -> Result<(), Vec<PolicyError>> {
        let mut errors = Vec::new();

        for policy in &self.policies {
            if let Err(error) = policy.validate(realm_id, user_id, password).await {
                errors.push(error);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn add_policy(&mut self, policy: Box<dyn PasswordPolicyProvider>) {
        self.policies.push(policy);
    }

    fn remove_policy(&mut self, policy_name: &str) {
        self.policies.retain(|p| p.get_policy_name() != policy_name);
    }

    fn get_policies(&self) -> Vec<&dyn PasswordPolicyProvider> {
        self.policies.iter().map(|p| p.as_ref()).collect()
    }
}

impl Provider for DefaultPasswordPolicyManager {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// Password policy manager factory
pub struct DefaultPasswordPolicyManagerFactory;

impl DefaultPasswordPolicyManagerFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl ProviderFactory<dyn PasswordPolicyManager> for DefaultPasswordPolicyManagerFactory {
    async fn create(&self, _config: &ProviderConfig) -> std::result::Result<Box<dyn PasswordPolicyManager>, SpiError> {
        Ok(Box::new(DefaultPasswordPolicyManager::new()))
    }

    async fn init(&mut self, _config: &ProviderConfig) -> std::result::Result<(), SpiError> {
        Ok(())
    }

    fn get_id(&self) -> &'static str {
        "default-password-policy-manager"
    }
}

/// Policy SPI implementation
pub struct PolicySpi;

impl Spi for PolicySpi {
    fn get_name(&self) -> &'static str {
        "policy"
    }

    fn is_internal(&self) -> bool {
        false
    }

    fn get_provider_class(&self) -> &'static str {
        "PasswordPolicyManager"
    }

    fn get_provider_factory_class(&self) -> &'static str {
        "PasswordPolicyManagerFactory"
    }
}
