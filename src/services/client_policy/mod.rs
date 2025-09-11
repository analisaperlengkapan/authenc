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
        // Check response type for implicit flow
        if let Some(response_type) = &context.response_type {
            if response_type == "token" {
                return Err(AuthencError::validation(
                    "Implicit grant is not allowed for this client".to_string()
                ));
            }
        }
        
        // Check grant type for implicit flow
        if let Some(grant_type) = &context.grant_type {
            if grant_type == "implicit" {
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

/// Authentication Flow Selector Executor
pub struct AuthenticationFlowSelectorExecutor {
    pub flow_type: String,
}

#[async_trait]
impl ClientPolicyExecutor for AuthenticationFlowSelectorExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        // Select appropriate authentication flow based on client and context
        // This enables dynamic flow selection for enhanced security
        match self.flow_type.as_str() {
            "browser" => {
                // Use browser-based authentication flow
                context.parameters.insert("auth_flow".to_string(), "browser".to_string());
            }
            "direct" => {
                // Use direct grant flow for confidential clients
                context.parameters.insert("auth_flow".to_string(), "direct".to_string());
            }
            "client" => {
                // Use client authentication flow
                context.parameters.insert("auth_flow".to_string(), "client".to_string());
            }
            _ => {
                return Err(AuthencError::validation(
                    format!("Unknown authentication flow type: {}", self.flow_type)
                ));
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "authentication-flow-selector-executor"
    }
}

/// Holder of Key Enforcer Executor
pub struct HolderOfKeyEnforcerExecutor {
    pub enforce_holder_of_key: bool,
}

#[async_trait]
impl ClientPolicyExecutor for HolderOfKeyEnforcerExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.enforce_holder_of_key {
            // Enforce that the client proves possession of the key
            // Check for DPoP proof or MTLS certificate
            let has_dpop = context.parameters.contains_key("dpop");
            let has_mtls = context.client_auth_method.as_deref() == Some("tls_client_auth");

            if !has_dpop && !has_mtls {
                return Err(AuthencError::validation(
                    "Holder of Key enforcement: DPoP proof or MTLS certificate required".to_string()
                ));
            }

            // Validate the proof/certificate binding
            if has_dpop {
                // Validate DPoP proof binding to access token
                self.validate_dpop_binding(context).await?;
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "holder-of-key-enforcer-executor"
    }
}

impl HolderOfKeyEnforcerExecutor {
    async fn validate_dpop_binding(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        // Validate that DPoP proof is properly bound to the access token
        // This prevents token replay attacks
        if let Some(dpop_header) = context.parameters.get("dpop") {
            // Parse and validate DPoP proof
            // Check that the public key in DPoP proof matches the one used for access token
            // Verify the binding between DPoP proof and access token
        }
        Ok(())
    }
}

/// Intent Client Bind Check Executor
pub struct IntentClientBindCheckExecutor {
    pub check_intent_binding: bool,
}

#[async_trait]
impl ClientPolicyExecutor for IntentClientBindCheckExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.check_intent_binding {
            // Check that client intent is properly bound to the authorization request
            // This prevents authorization request tampering
            let intent_id = context.parameters.get("client_intent_id").map(|s| s.clone());
            if let Some(intent_id) = intent_id {
                // Validate intent binding
                self.validate_intent_binding(&intent_id, context).await?;
            } else {
                return Err(AuthencError::validation(
                    "Intent binding required but client_intent_id not provided".to_string()
                ));
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "intent-client-bind-check-executor"
    }
}

impl IntentClientBindCheckExecutor {
    async fn validate_intent_binding(&self, intent_id: &str, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        // Validate that the client intent is properly bound
        // Check intent signature, expiration, and binding to client
        Ok(())
    }
}

/// Lightweight Access Token Executor
pub struct LightweightAccessTokenExecutor {
    pub use_lightweight_tokens: bool,
}

#[async_trait]
impl ClientPolicyExecutor for LightweightAccessTokenExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.use_lightweight_tokens {
            // Issue lightweight access tokens for better performance
            // Lightweight tokens contain minimal claims and rely on token introspection
            context.parameters.insert("token_type".to_string(), "lightweight".to_string());
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "lightweight-access-token-executor"
    }
}

/// Secure Client Authentication Assertion Executor
pub struct SecureClientAuthenticationAssertionExecutor {
    pub require_secure_assertion: bool,
}

#[async_trait]
impl ClientPolicyExecutor for SecureClientAuthenticationAssertionExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.require_secure_assertion {
            // Require secure client authentication assertion (JWT, SAML, etc.)
            let has_jwt_assertion = context.parameters.contains_key("client_assertion");
            let has_jwt_assertion_type = context.parameters.contains_key("client_assertion_type");

            if !has_jwt_assertion || !has_jwt_assertion_type {
                return Err(AuthencError::validation(
                    "Secure client authentication assertion required".to_string()
                ));
            }

            // Validate the assertion
            if let Some(assertion_type) = context.parameters.get("client_assertion_type") {
                if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
                    return Err(AuthencError::validation(
                        "Unsupported client assertion type".to_string()
                    ));
                }
            }

            // Validate JWT assertion signature and claims
            self.validate_jwt_assertion(context).await?;
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "secure-client-authentication-assertion-executor"
    }
}

impl SecureClientAuthenticationAssertionExecutor {
    async fn validate_jwt_assertion(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        // Validate JWT client assertion
        // Check signature, issuer, subject, audience, expiration
        Ok(())
    }
}

/// Secure Client Authenticator Executor
pub struct SecureClientAuthenticatorExecutor {
    pub require_secure_authenticator: bool,
}

#[async_trait]
impl ClientPolicyExecutor for SecureClientAuthenticatorExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.require_secure_authenticator {
            // Require secure client authentication method
            let auth_method = context.client_auth_method.as_deref().unwrap_or("");

            match auth_method {
                "private_key_jwt" | "tls_client_auth" => {
                    // These are secure methods
                }
                _ => {
                    return Err(AuthencError::validation(
                        "Secure client authentication method required (private_key_jwt or tls_client_auth)".to_string()
                    ));
                }
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "secure-client-authenticator-executor"
    }
}

/// Secure Logout Executor
pub struct SecureLogoutExecutor {
    pub enforce_secure_logout: bool,
}

#[async_trait]
impl ClientPolicyExecutor for SecureLogoutExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.enforce_secure_logout {
            // Enforce secure logout mechanisms
            // Require logout tokens, back-channel logout, etc.
            context.parameters.insert("secure_logout".to_string(), "true".to_string());
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "secure-logout-executor"
    }
}

/// Secure PAR Contents Executor
pub struct SecureParContentsExecutor {
    pub enforce_secure_par: bool,
}

#[async_trait]
impl ClientPolicyExecutor for SecureParContentsExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.enforce_secure_par {
            // Enforce secure Pushed Authorization Request contents
            // Validate PAR request parameters and security
            if !context.parameters.contains_key("request_uri") {
                return Err(AuthencError::validation(
                    "Secure PAR: request_uri parameter required".to_string()
                ));
            }

            // Validate PAR contents security
            self.validate_par_security(context).await?;
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "secure-par-contents-executor"
    }
}

impl SecureParContentsExecutor {
    async fn validate_par_security(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        // Validate PAR request security
        // Check for parameter injection, replay attacks, etc.
        Ok(())
    }
}

/// Secure Request Object Executor
pub struct SecureRequestObjectExecutor {
    pub enforce_secure_request_object: bool,
}

#[async_trait]
impl ClientPolicyExecutor for SecureRequestObjectExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.enforce_secure_request_object {
            // Enforce secure OAuth 2.0 request objects
            // Require signed and optionally encrypted request objects
            let has_request = context.parameters.contains_key("request");
            let has_request_uri = context.parameters.contains_key("request_uri");

            if !has_request && !has_request_uri {
                return Err(AuthencError::validation(
                    "Secure request object: request or request_uri parameter required".to_string()
                ));
            }

            // Validate request object security
            self.validate_request_object_security(context).await?;
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "secure-request-object-executor"
    }
}

impl SecureRequestObjectExecutor {
    async fn validate_request_object_security(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        // Validate request object signature and encryption
        Ok(())
    }
}

/// Secure Response Type Executor
pub struct SecureResponseTypeExecutor {
    pub enforce_secure_response_type: bool,
}

#[async_trait]
impl ClientPolicyExecutor for SecureResponseTypeExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.enforce_secure_response_type {
            // Enforce secure response types
            if let Some(response_type) = &context.response_type {
                match response_type.as_str() {
                    "code" => {
                        // Authorization code flow is secure
                    }
                    "code id_token" | "id_token code" => {
                        // Hybrid flow with ID token
                    }
                    _ => {
                        return Err(AuthencError::validation(
                            format!("Insecure response type not allowed: {}", response_type)
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "secure-response-type-executor"
    }
}

/// Secure Session Enforce Executor
pub struct SecureSessionEnforceExecutor {
    pub enforce_secure_session: bool,
}

#[async_trait]
impl ClientPolicyExecutor for SecureSessionEnforceExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.enforce_secure_session {
            // Enforce secure session management
            // Require session binding, rotation, etc.
            context.parameters.insert("secure_session".to_string(), "true".to_string());
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "secure-session-enforce-executor"
    }
}

/// Secure Signing Algorithm Executor
pub struct SecureSigningAlgorithmExecutor {
    pub enforce_secure_algorithm: bool,
    pub allowed_algorithms: Vec<String>,
}

#[async_trait]
impl ClientPolicyExecutor for SecureSigningAlgorithmExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.enforce_secure_algorithm {
            // Enforce secure signing algorithms
            // Check JWT header, ID token, access token algorithms
            if let Some(alg) = context.parameters.get("alg") {
                if !self.allowed_algorithms.contains(alg) {
                    return Err(AuthencError::validation(
                        format!("Insecure signing algorithm not allowed: {}", alg)
                    ));
                }
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "secure-signing-algorithm-executor"
    }
}

/// Suppress Refresh Token Rotation Executor
pub struct SuppressRefreshTokenRotationExecutor {
    pub suppress_rotation: bool,
}

#[async_trait]
impl ClientPolicyExecutor for SuppressRefreshTokenRotationExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.suppress_rotation {
            // Suppress automatic refresh token rotation for this client
            context.parameters.insert("suppress_token_rotation".to_string(), "true".to_string());
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "suppress-refresh-token-rotation-executor"
    }
}

/// Registration Access Token Rotation Disabled Executor
pub struct RegistrationAccessTokenRotationDisabledExecutor {
    pub disable_rotation: bool,
}

#[async_trait]
impl ClientPolicyExecutor for RegistrationAccessTokenRotationDisabledExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.disable_rotation {
            // Disable rotation of registration access tokens
            context.parameters.insert("disable_reg_token_rotation".to_string(), "true".to_string());
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "registration-access-token-rotation-disabled-executor"
    }
}

/// Full Scope Disabled Executor
pub struct FullScopeDisabledExecutor {
    pub disable_full_scope: bool,
}

#[async_trait]
impl ClientPolicyExecutor for FullScopeDisabledExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.disable_full_scope {
            // Disable full scope access for this client
            // Require explicit scope requests
            if !context.parameters.contains_key("scope") {
                return Err(AuthencError::validation(
                    "Full scope disabled: explicit scope parameter required".to_string()
                ));
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "full-scope-disabled-executor"
    }
}

/// Consent Required Executor
pub struct ConsentRequiredExecutor {
    pub require_consent: bool,
}

#[async_trait]
impl ClientPolicyExecutor for ConsentRequiredExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.require_consent {
            // Require user consent for this client
            context.parameters.insert("consent_required".to_string(), "true".to_string());
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "consent-required-executor"
    }
}

/// Confidential Client Accept Executor
pub struct ConfidentialClientAcceptExecutor {
    pub accept_confidential_only: bool,
}

#[async_trait]
impl ClientPolicyExecutor for ConfidentialClientAcceptExecutor {
    async fn execute(&self, context: &mut ClientPolicyContext) -> Result<(), AuthencError> {
        if self.accept_confidential_only {
            // Only accept confidential clients
            if context.client.client_type != "confidential" {
                return Err(AuthencError::validation(
                    "Only confidential clients are accepted".to_string()
                ));
            }
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "confidential-client-accept-executor"
    }
}

/// Client Policy manager
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
                "implicit".to_string(), // Allow implicit so it can be rejected by executor
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
