//! Client Policy Framework
//!
//! Comprehensive client policy framework for enforcing security policies
//! on OAuth2/OIDC clients, similar to Keycloak's advanced client policies.
//!
//! Features:
//! - Conditional policy execution based on client attributes
//! - Multiple policy executors for different security requirements
//! - Grant type restrictions
//! - PKCE enforcement
//! - DPoP binding enforcement
//! - Secure redirect URI validation
//! - Token rotation policies

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use async_trait::async_trait;
use uuid::Uuid;
use chrono::Utc;
use crate::error::AuthencError;
use crate::models::oauth2::OAuth2Client;

/// Client Policy Context
#[derive(Debug, Clone)]
pub struct ClientPolicyContext {
    /// Client information
    pub client: OAuth2Client,
    /// Grant type being requested
    pub grant_type: Option<String>,
    /// Response type requested
    pub response_type: Option<String>,
    /// Redirect URI
    pub redirect_uri: Option<String>,
    /// Client authentication method
    pub client_auth_method: Option<String>,
    /// Request parameters
    pub parameters: HashMap<String, String>,
    /// User context (if available)
    pub user_id: Option<String>,
    /// Device fingerprint
    pub device_fingerprint: Option<String>,
}

/// Policy Condition trait
#[async_trait]
pub trait ClientPolicyCondition: Send + Sync {
    /// Evaluate if the condition is met
    async fn evaluate(&self, context: &ClientPolicyContext) -> Result<bool, AuthencError>;

    /// Get condition name
    fn name(&self) -> &str;
}

/// Policy Executor trait
#[async_trait]
pub trait ClientPolicyExecutor: Send + Sync {
    /// Execute the policy
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError>;

    /// Get executor name
    fn name(&self) -> &str;
}

/// Client Policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPolicy {
    /// Policy name
    pub name: String,
    /// Policy description
    pub description: String,
    /// Enabled status
    pub enabled: bool,
    /// Conditions that must be met
    pub conditions: Vec<String>,
    /// Executors to run if conditions are met
    pub executors: Vec<String>,
    /// Policy priority (higher = executed first)
    pub priority: i32,
}

/// Client Profile containing multiple policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientProfile {
    /// Profile name
    pub name: String,
    /// Profile description
    pub description: String,
    /// Enabled status
    pub enabled: bool,
    /// List of policies in this profile
    pub policies: Vec<ClientPolicy>,
}

/// Grant Type Condition
pub struct GrantTypeCondition {
    pub allowed_grant_types: Vec<String>,
}

#[async_trait]
impl ClientPolicyCondition for GrantTypeCondition {
    async fn evaluate(&self, context: &ClientPolicyContext) -> Result<bool, AuthencError> {
        if let Some(grant_type) = &context.grant_type {
            Ok(self.allowed_grant_types.contains(grant_type))
        } else {
            Ok(false)
        }
    }

    fn name(&self) -> &str {
        "grant-type-condition"
    }
}

/// Client Roles Condition
pub struct ClientRolesCondition {
    pub required_roles: Vec<String>,
}

#[async_trait]
impl ClientPolicyCondition for ClientRolesCondition {
    async fn evaluate(&self, _context: &ClientPolicyContext) -> Result<bool, AuthencError> {
        // Check if client has required roles
        // This would integrate with your role management system
        Ok(true) // Placeholder - implement based on your role system
    }

    fn name(&self) -> &str {
        "client-roles-condition"
    }
}

/// PKCE Enforcer Executor
pub struct PkceEnforcerExecutor {
    pub enforce_pkce: bool,
}

#[async_trait]
impl ClientPolicyExecutor for PkceEnforcerExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.enforce_pkce {
            // Check if PKCE parameters are present
            let has_code_challenge = context.parameters.contains_key("code_challenge");
            let has_code_challenge_method = context.parameters.contains_key("code_challenge_method");

            if !has_code_challenge || !has_code_challenge_method {
                return Err(AuthencError::validation(
                    "PKCE is required for this client".to_string()
                ));
            }

            // Validate code challenge method
            if let Some(method) = context.parameters.get("code_challenge_method") {
                if method != "S256" {
                    return Err(AuthencError::validation(
                        "Only S256 code challenge method is allowed".to_string()
                    ));
                }
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "pkce-enforcer-executor"
    }
}

/// DPoP Bind Enforcer Executor
pub struct DPoPBindEnforcerExecutor {
    pub enforce_dpop: bool,
}

#[async_trait]
impl ClientPolicyExecutor for DPoPBindEnforcerExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.enforce_dpop {
            // Check for DPoP header
            if !context.parameters.contains_key("dpop") {
                return Err(AuthencError::validation(
                    "DPoP proof is required for this client".to_string()
                ));
            }

            // Validate DPoP proof
            // This would integrate with your DPoP implementation
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "dpop-bind-enforcer-executor"
    }
}

/// Secure Redirect URIs Enforcer Executor
pub struct SecureRedirectUrisEnforcerExecutor {
    pub enforce_https: bool,
}

#[async_trait]
impl ClientPolicyExecutor for SecureRedirectUrisEnforcerExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.enforce_https {
            if let Some(redirect_uri) = &context.redirect_uri {
                if !redirect_uri.starts_with("https://") {
                    return Err(AuthencError::validation(
                        "Only HTTPS redirect URIs are allowed".to_string()
                    ));
                }
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "secure-redirect-uris-enforcer-executor"
    }
}

/// Reject Implicit Grant Executor
pub struct RejectImplicitGrantExecutor;

#[async_trait]
impl ClientPolicyExecutor for RejectImplicitGrantExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if let Some(response_type) = &context.response_type {
            if response_type == "token" {
                return Err(AuthencError::validation(
                    "Implicit grant is not allowed for this client".to_string()
                ));
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "reject-implicit-grant-executor"
    }
}

/// Client Secret Rotation Executor
pub struct ClientSecretRotationExecutor {
    pub rotation_interval_days: u32,
}

#[async_trait]
impl ClientPolicyExecutor for ClientSecretRotationExecutor {
    async fn execute(&self, _context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        // Check if client secret needs rotation
        // This would integrate with your client secret management
        Ok(())
    }

    fn name(&self) -> &str {
        "client-secret-rotation-executor"
    }
}

/// FAPI (Financial-grade API) Constant
pub struct FapiConstant;

impl FapiConstant {
    pub const FAPI_1_BASELINE: &str = "fapi-1-baseline";
    pub const FAPI_1_ADVANCED: &str = "fapi-1-advanced";
    pub const FAPI_2_SECURITY_PROFILE: &str = "fapi-2-security-profile";
    pub const FAPI_2_MESSAGE_SIGNING: &str = "fapi-2-message-signing";
}

/// FAPI Security Profile Executor
pub struct FapiSecurityProfileExecutor {
    pub profile: String,
}

#[async_trait]
impl ClientPolicyExecutor for FapiSecurityProfileExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        match self.profile.as_str() {
            FapiConstant::FAPI_1_BASELINE => {
                // Enforce FAPI 1.0 Baseline security profile
                self.enforce_fapi_1_baseline(context).await
            }
            FapiConstant::FAPI_1_ADVANCED => {
                // Enforce FAPI 1.0 Advanced security profile
                self.enforce_fapi_1_advanced(context).await
            }
            FapiConstant::FAPI_2_SECURITY_PROFILE => {
                // Enforce FAPI 2.0 Security Profile
                self.enforce_fapi_2_security_profile(context).await
            }
            _ => Ok(())
        }
    }

    fn name(&self) -> &str {
        "fapi-security-profile-executor"
    }
}

impl FapiSecurityProfileExecutor {
    async fn enforce_fapi_1_baseline(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        // FAPI 1.0 Baseline requirements:
        // - TLS 1.2 or higher
        // - PKCE required
        // - Confidential clients must use client authentication
        // - Authorization code grant only

        // Enforce PKCE
        if !context.parameters.contains_key("code_challenge") {
            return Err(AuthencError::validation(
                "FAPI 1.0 Baseline: PKCE is required".to_string()
            ));
        }

        // Enforce authorization code grant
        if let Some(response_type) = &context.response_type {
            if response_type != "code" {
                return Err(AuthencError::validation(
                    "FAPI 1.0 Baseline: Only authorization code grant is allowed".to_string()
                ));
            }
        }

        Ok(())
    }

    async fn enforce_fapi_1_advanced(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        // FAPI 1.0 Advanced requirements:
        // - All Baseline requirements
        // - DPoP or MTLS sender constrained access tokens
        // - Private key JWT client authentication
        // - PS256 or ES256 algorithms

        // First enforce baseline
        self.enforce_fapi_1_baseline(context).await?;

        // Enforce DPoP or MTLS
        let has_dpop = context.parameters.contains_key("dpop");
        let has_mtls = context.client_auth_method.as_deref() == Some("tls_client_auth");

        if !has_dpop && !has_mtls {
            return Err(AuthencError::validation(
                "FAPI 1.0 Advanced: DPoP or MTLS sender constrained access tokens required".to_string()
            ));
        }

        Ok(())
    }

    async fn enforce_fapi_2_security_profile(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        // FAPI 2.0 Security Profile requirements:
        // - All Advanced requirements
        // - PAR (Pushed Authorization Requests)
        // - JARM (JWT Secured Authorization Response Mode)
        // - Rich Authorization Requests (RAR)

        // First enforce advanced
        self.enforce_fapi_1_advanced(context).await?;

        // Enforce PAR
        if !context.parameters.contains_key("request_uri") {
            return Err(AuthencError::ValidationError {
                message: "FAPI 2.0 Security Profile: PAR (Pushed Authorization Requests) is required".to_string()
            });
        }

        Ok(())
    }
}

/// Client Policy Manager
pub struct ClientPolicyManager {
    conditions: HashMap<String, Box<dyn ClientPolicyCondition>>,
    executors: HashMap<String, Box<dyn ClientPolicyExecutor>>,
    profiles: Vec<ClientProfile>,
}

impl ClientPolicyManager {
    pub fn new() -> Self {
        Self {
            conditions: HashMap::new(),
            executors: HashMap::new(),
            profiles: Vec::new(),
        }
    }

    /// Register a policy condition
    pub fn register_condition(&mut self, condition: Box<dyn ClientPolicyCondition>) {
        self.conditions.insert(condition.name().to_string(), condition);
    }

    /// Register a policy executor
    pub fn register_executor(&mut self, executor: Box<dyn ClientPolicyExecutor>) {
        self.executors.insert(executor.name().to_string(), executor);
    }

    /// Add a client profile
    pub fn add_profile(&mut self, profile: ClientProfile) {
        self.profiles.push(profile);
    }

    /// Evaluate and execute policies for a client request
    pub async fn evaluate_policies(&self, mut context: ClientPolicyContext) -> Result<ClientPolicyContext, AuthencError> {
        // Sort profiles by priority (not implemented yet, would need profile priority)
        for profile in &self.profiles {
            if !profile.enabled {
                continue;
            }

            for policy in &profile.policies {
                if !policy.enabled {
                    continue;
                }

                // Evaluate conditions
                let mut conditions_met = true;
                for condition_name in &policy.conditions {
                    if let Some(condition) = self.conditions.get(condition_name) {
                        if !condition.evaluate(&context).await? {
                            conditions_met = false;
                            break;
                        }
                    }
                }

                // Execute executors if conditions are met
                if conditions_met {
                    for executor_name in &policy.executors {
                        if let Some(executor) = self.executors.get(executor_name) {
                            executor.execute(&mut context).await?;
                        }
                    }
                }
            }
        }

        Ok(context)
    }

    /// Create default FAPI security profiles
    pub fn create_default_fapi_profiles(&mut self) {
        // FAPI 1.0 Baseline Profile
        let baseline_policy = ClientPolicy {
            name: "fapi-1-baseline".to_string(),
            description: "FAPI 1.0 Baseline Security Profile".to_string(),
            enabled: true,
            conditions: vec!["grant-type-condition".to_string()],
            executors: vec![
                "pkce-enforcer-executor".to_string(),
                "secure-redirect-uris-enforcer-executor".to_string(),
                "reject-implicit-grant-executor".to_string(),
            ],
            priority: 100,
        };

        let baseline_profile = ClientProfile {
            name: "fapi-1-baseline-profile".to_string(),
            description: "FAPI 1.0 Baseline Security Profile".to_string(),
            enabled: true,
            policies: vec![baseline_policy],
        };

        // FAPI 1.0 Advanced Profile
        let advanced_policy = ClientPolicy {
            name: "fapi-1-advanced".to_string(),
            description: "FAPI 1.0 Advanced Security Profile".to_string(),
            enabled: true,
            conditions: vec!["grant-type-condition".to_string()],
            executors: vec![
                "pkce-enforcer-executor".to_string(),
                "dpop-bind-enforcer-executor".to_string(),
                "secure-redirect-uris-enforcer-executor".to_string(),
                "reject-implicit-grant-executor".to_string(),
            ],
            priority: 200,
        };

        let advanced_profile = ClientProfile {
            name: "fapi-1-advanced-profile".to_string(),
            description: "FAPI 1.0 Advanced Security Profile".to_string(),
            enabled: true,
            policies: vec![advanced_policy],
        };

        self.add_profile(baseline_profile);
        self.add_profile(advanced_profile);
    }
}

impl Default for ClientPolicyManager {
    fn default() -> Self {
        let mut manager = Self::new();

        // Register default conditions
        manager.register_condition(Box::new(GrantTypeCondition {
            allowed_grant_types: vec![
                "authorization_code".to_string(),
                "client_credentials".to_string(),
                "refresh_token".to_string(),
            ],
        }));

        manager.register_condition(Box::new(ClientRolesCondition {
            required_roles: vec![],
        }));

        // Register default executors
        manager.register_executor(Box::new(PkceEnforcerExecutor {
            enforce_pkce: true,
        }));

        manager.register_executor(Box::new(DPoPBindEnforcerExecutor {
            enforce_dpop: true,
        }));

        manager.register_executor(Box::new(SecureRedirectUrisEnforcerExecutor {
            enforce_https: true,
        }));

        manager.register_executor(Box::new(RejectImplicitGrantExecutor));

        manager.register_executor(Box::new(ClientSecretRotationExecutor {
            rotation_interval_days: 90,
        }));

        // Create default FAPI profiles
        manager.create_default_fapi_profiles();

        manager
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::oauth2::OAuth2Client;

    #[tokio::test]
    async fn test_pkce_enforcement() {
        let manager = ClientPolicyManager::default();
        let client = OAuth2Client {
            id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            client_secret_hash: "hashed_secret".to_string(),
            client_name: "Test Client".to_string(),
            client_type: "confidential".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            scopes: vec!["openid".to_string()],
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            owner_id: None,
            realm_id: None,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };

        let context = ClientPolicyContext {
            client,
            grant_type: Some("authorization_code".to_string()),
            response_type: Some("code".to_string()),
            redirect_uri: Some("https://example.com/callback".to_string()),
            client_auth_method: Some("client_secret_basic".to_string()),
            parameters: HashMap::new(), // No PKCE parameters
            user_id: None,
            device_fingerprint: None,
        };

        // This should fail because PKCE is required but not provided
        let result = manager.evaluate_policies(context).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("PKCE"));
    }

    #[tokio::test]
    async fn test_secure_redirect_uri_enforcement() {
        let manager = ClientPolicyManager::default();
        let client = OAuth2Client {
            id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            client_secret_hash: "hashed_secret".to_string(),
            client_name: "Test Client".to_string(),
            client_type: "confidential".to_string(),
            redirect_uris: vec!["http://example.com/callback".to_string()], // HTTP not HTTPS
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            scopes: vec!["openid".to_string()],
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            owner_id: None,
            realm_id: None,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };

        let context = ClientPolicyContext {
            client,
            grant_type: Some("authorization_code".to_string()),
            response_type: Some("code".to_string()),
            redirect_uri: Some("http://example.com/callback".to_string()), // HTTP not HTTPS
            client_auth_method: Some("client_secret_basic".to_string()),
            parameters: HashMap::from([
                ("code_challenge".to_string(), "challenge".to_string()),
                ("code_challenge_method".to_string(), "S256".to_string()),
            ]),
            user_id: None,
            device_fingerprint: None,
        };

        // This should fail because HTTP redirect URI is not allowed
        let result = manager.evaluate_policies(context).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("HTTPS"));
    }

    #[tokio::test]
    async fn test_implicit_grant_rejection() {
        let manager = ClientPolicyManager::default();
        let client = OAuth2Client {
            id: Uuid::new_v4(),
            client_id: "test-client".to_string(),
            client_secret_hash: "hashed_secret".to_string(),
            client_name: "Test Client".to_string(),
            client_type: "confidential".to_string(),
            redirect_uris: vec!["https://example.com/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            scopes: vec!["openid".to_string()],
            token_endpoint_auth_method: "client_secret_basic".to_string(),
            owner_id: None,
            realm_id: None,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };

        let context = ClientPolicyContext {
            client,
            grant_type: Some("implicit".to_string()),
            response_type: Some("token".to_string()), // Implicit flow
            redirect_uri: Some("https://example.com/callback".to_string()),
            client_auth_method: Some("client_secret_basic".to_string()),
            parameters: HashMap::from([
                ("code_challenge".to_string(), "challenge".to_string()),
                ("code_challenge_method".to_string(), "S256".to_string()),
            ]),
            user_id: None,
            device_fingerprint: None,
        };

        // This should fail because implicit grant is rejected
        let result = manager.evaluate_policies(context).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Implicit grant"));
    }
}
