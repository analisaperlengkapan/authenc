use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// Authorization decision
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Decision {
    /// Access is permitted
    Permit,
    /// Access is denied
    Deny,
    /// Decision is undecided
    Undecided,
}

/// Authorization request context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationContext {
    /// Subject requesting access
    pub subject: AuthorizationSubject,
    /// Resource being accessed
    pub resource: AuthorizationResource,
    /// Action being performed
    pub action: String,
    /// Environment context
    pub environment: HashMap<String, String>,
}

/// Authorization subject (user/role)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationSubject {
    /// Unique identifier for the subject
    pub id: String,
    /// Username of the subject
    pub username: String,
    /// Roles assigned to the subject
    pub roles: Vec<String>,
    /// Groups the subject belongs to
    pub groups: Vec<String>,
    /// Additional attributes of the subject
    pub attributes: HashMap<String, String>,
}

/// Authorization resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationResource {
    /// Unique identifier for the resource
    pub id: String,
    /// Name of the resource
    pub name: String,
    /// Type of the resource
    pub resource_type: String,
    /// Owner of the resource
    pub owner: String,
    /// Additional attributes of the resource
    pub attributes: HashMap<String, String>,
}

/// Authorization policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Unique identifier for the policy
    pub id: Uuid,
    /// Name of the policy
    pub name: String,
    /// Description of the policy
    pub description: String,
    /// Type of the policy
    pub policy_type: PolicyType,
    /// Logic type for policy evaluation
    pub logic: LogicType,
    /// Configuration for the policy
    pub config: PolicyConfig,
    /// Whether the policy is enabled
    pub enabled: bool,
    /// ID of the realm the policy belongs to
    pub realm_id: Uuid,
}

/// Policy types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyType {
    /// Role-based access control policy
    RoleBased,
    /// Attribute-based access control policy
    AttributeBased,
    /// Time-based access control policy
    TimeBased,
    /// Location-based access control policy
    LocationBased,
    /// Risk-based access control policy
    RiskBased,
    /// Custom policy type
    Custom,
}

/// Logic types for combining policies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogicType {
    /// Positive logic (permit unless denied)
    Positive,
    /// Negative logic (deny unless permitted)
    Negative,
    /// Consensus logic (majority decision)
    Consensus,
    /// Affirmative logic (any permit allows)
    Affirmative,
}

/// Policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Roles required by the policy
    pub roles: Vec<String>,
    /// Attributes required by the policy
    pub attributes: HashMap<String, String>,
    /// Conditions that must be met
    pub conditions: Vec<PolicyCondition>,
}

/// Policy condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    /// Type of condition to evaluate
    pub condition_type: String,
    /// Configuration for the condition
    pub config: HashMap<String, String>,
}

/// Authorization service trait
#[async_trait]
pub trait AuthorizationService: Send + Sync {
    /// Evaluate authorization request
    async fn evaluate(&self, context: &AuthorizationContext) -> Result<Decision, String>;

    /// Get all policies for a realm
    async fn get_policies(&self, realm_id: &Uuid) -> Result<Vec<Policy>, String>;

    /// Create new policy
    async fn create_policy(&self, policy: Policy) -> Result<Uuid, String>;

    /// Update existing policy
    async fn update_policy(&self, policy: Policy) -> Result<(), String>;

    /// Delete policy
    async fn delete_policy(&self, policy_id: &Uuid) -> Result<(), String>;
}

/// Resource server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceServer {
    /// Unique identifier for the resource server
    pub id: Uuid,
    /// Name of the resource server
    pub name: String,
    /// Client ID associated with the resource server
    pub client_id: String,
    /// ID of the realm the resource server belongs to
    pub realm_id: Uuid,
    /// Resources managed by this server
    pub resources: Vec<Resource>,
    /// Policy IDs associated with this server
    pub policies: Vec<Uuid>,
}

/// Resource definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    /// Unique identifier for the resource
    pub id: Uuid,
    /// Name of the resource
    pub name: String,
    /// Display name of the resource
    pub display_name: String,
    /// Type of the resource
    pub resource_type: String,
    /// Owner of the resource
    pub owner: String,
    /// Scopes associated with the resource
    pub scopes: Vec<String>,
    /// Additional attributes of the resource
    pub attributes: HashMap<String, String>,
}

/// Permission definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// Unique identifier for the permission
    pub id: Uuid,
    /// Name of the permission
    pub name: String,
    /// Description of the permission
    pub description: String,
    /// ID of the resource this permission applies to
    pub resource_id: Uuid,
    /// Scopes required for this permission
    pub scopes: Vec<String>,
    /// Policy IDs that define this permission
    pub policies: Vec<Uuid>,
}

/// Scope definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    /// Unique identifier for the scope
    pub id: Uuid,
    /// Name of the scope
    pub name: String,
    /// Display name of the scope
    pub display_name: String,
    /// URI to the scope's icon
    pub icon_uri: Option<String>,
}

/// Authorization Manager - main service
pub struct AuthorizationManager {
    /// Database connection
    database: Arc<crate::database::Database>,
    /// Internal storage for policies
    policies: HashMap<Uuid, Policy>,
    /// Internal storage for resource servers
    resource_servers: HashMap<Uuid, ResourceServer>,
    /// Internal storage for permissions
    permissions: HashMap<Uuid, Permission>,
    /// Internal storage for scopes
    scopes: HashMap<Uuid, Scope>,
}

impl AuthorizationManager {
    /// Create new authorization manager with database
    pub fn new(database: Arc<crate::database::Database>) -> Self {
        Self {
            database,
            policies: HashMap::new(),
            resource_servers: HashMap::new(),
            permissions: HashMap::new(),
            scopes: HashMap::new(),
        }
    }
}

impl AuthorizationManager {
    /// Add resource server
    pub fn add_resource_server(&mut self, server: ResourceServer) {
        self.resource_servers.insert(server.id, server);
    }

    /// Add policy
    pub fn add_policy(&mut self, policy: Policy) {
        self.policies.insert(policy.id, policy);
    }

    /// Add permission
    pub fn add_permission(&mut self, permission: Permission) {
        self.permissions.insert(permission.id, permission);
    }

    /// Add scope
    pub fn add_scope(&mut self, scope: Scope) {
        self.scopes.insert(scope.id, scope);
    }

    /// Register resource server
    pub fn register_resource_server(&mut self, server: ResourceServer) {
        self.resource_servers.insert(server.id, server);
    }

    /// Evaluate access based on policies
    pub fn evaluate_policies(
        &self,
        context: &AuthorizationContext,
        policy_ids: &[Uuid],
    ) -> Decision {
        let mut permit_count = 0;
        let mut deny_count = 0;

        for policy_id in policy_ids {
            if let Some(policy) = self.policies.get(policy_id) {
                if !policy.enabled {
                    continue;
                }

                let decision = self.evaluate_single_policy(context, policy);
                match decision {
                    Decision::Permit => permit_count += 1,
                    Decision::Deny => deny_count += 1,
                    Decision::Undecided => {}
                }
            }
        }

        // Simple consensus logic: deny if any deny, permit if majority permit
        if deny_count > 0 {
            Decision::Deny
        } else if permit_count > 0 {
            Decision::Permit
        } else {
            Decision::Undecided
        }
    }

    /// Evaluate single policy
    fn evaluate_single_policy(&self, context: &AuthorizationContext, policy: &Policy) -> Decision {
        match policy.policy_type {
            PolicyType::RoleBased => self.evaluate_role_policy(context, &policy.config),
            PolicyType::AttributeBased => self.evaluate_attribute_policy(context, &policy.config),
            PolicyType::TimeBased => self.evaluate_time_policy(context, &policy.config),
            PolicyType::LocationBased => self.evaluate_location_policy(context, &policy.config),
            PolicyType::RiskBased => self.evaluate_risk_policy(context, &policy.config),
            PolicyType::Custom => Decision::Undecided, // Would need custom logic
        }
    }

    /// Evaluate role-based policy
    fn evaluate_role_policy(
        &self,
        context: &AuthorizationContext,
        config: &PolicyConfig,
    ) -> Decision {
        for required_role in &config.roles {
            if !context.subject.roles.contains(required_role) {
                return Decision::Deny;
            }
        }
        Decision::Permit
    }

    /// Evaluate attribute-based policy
    fn evaluate_attribute_policy(
        &self,
        context: &AuthorizationContext,
        config: &PolicyConfig,
    ) -> Decision {
        for (key, expected_value) in &config.attributes {
            if let Some(actual_value) = context.subject.attributes.get(key) {
                if actual_value != expected_value {
                    return Decision::Deny;
                }
            } else {
                return Decision::Deny;
            }
        }
        Decision::Permit
    }

    /// Evaluate time-based policy
    fn evaluate_time_policy(
        &self,
        context: &AuthorizationContext,
        config: &PolicyConfig,
    ) -> Decision {
        use chrono::{Datelike, Timelike, Utc};

        let now = Utc::now();
        let current_hour = now.hour();
        let current_day = now.weekday().num_days_from_monday(); // 0=Monday, 6=Sunday

        // Check conditions for time windows
        for condition in &config.conditions {
            if condition.condition_type == "time_window" {
                // Check start_hour and end_hour
                if let (Some(start), Some(end)) = (
                    condition
                        .config
                        .get("start_hour")
                        .and_then(|s| s.parse::<u32>().ok()),
                    condition
                        .config
                        .get("end_hour")
                        .and_then(|s| s.parse::<u32>().ok()),
                ) {
                    if current_hour < start || current_hour >= end {
                        return Decision::Deny;
                    }
                }

                // Check allowed_days (comma-separated: "0,1,2,3,4" for Mon-Fri)
                if let Some(days_str) = condition.config.get("allowed_days") {
                    let allowed_days: Vec<u32> = days_str
                        .split(',')
                        .filter_map(|s| s.trim().parse().ok())
                        .collect();

                    if !allowed_days.is_empty() && !allowed_days.contains(&current_day) {
                        return Decision::Deny;
                    }
                }
            }
        }

        // Check environment context for explicit time constraints
        if let Some(requested_time) = context.environment.get("requested_time") {
            if let Ok(timestamp) = requested_time.parse::<i64>() {
                if timestamp < now.timestamp() {
                    return Decision::Deny; // Request expired
                }
            }
        }

        Decision::Permit
    }

    /// Evaluate location-based policy
    fn evaluate_location_policy(
        &self,
        context: &AuthorizationContext,
        config: &PolicyConfig,
    ) -> Decision {
        // Get user location from context
        let user_location = context
            .environment
            .get("location")
            .or_else(|| context.environment.get("country"))
            .or_else(|| context.environment.get("ip_address"));

        if user_location.is_none() {
            // No location data available - deny by default for location-based policy
            return Decision::Deny;
        }

        let location = user_location.unwrap();

        // Check conditions for allowed/denied locations
        for condition in &config.conditions {
            match condition.condition_type.as_str() {
                "allowed_locations" => {
                    if let Some(allowed) = condition.config.get("locations") {
                        let allowed_list: Vec<&str> =
                            allowed.split(',').map(|s| s.trim()).collect();
                        if !allowed_list.iter().any(|&loc| location.contains(loc)) {
                            return Decision::Deny;
                        }
                    }
                }
                "denied_locations" => {
                    if let Some(denied) = condition.config.get("locations") {
                        let denied_list: Vec<&str> = denied.split(',').map(|s| s.trim()).collect();
                        if denied_list.iter().any(|&loc| location.contains(loc)) {
                            return Decision::Deny;
                        }
                    }
                }
                "geofence" => {
                    // Check if user is within allowed geographic boundary
                    // Format: "latitude,longitude,radius_km"
                    if let Some(fence) = condition.config.get("boundary") {
                        let parts: Vec<&str> = fence.split(',').collect();
                        if parts.len() >= 3 {
                            // In production, would calculate distance using haversine formula
                            // For now, check if lat/long present in environment
                            if let (Some(lat), Some(lng)) = (
                                context.environment.get("latitude"),
                                context.environment.get("longitude"),
                            ) {
                                // Simplified check - in production use proper geospatial calculations
                                let user_coords = format!("{},{}", lat, lng);
                                if !user_coords.is_empty() {
                                    // Would perform actual distance calculation here
                                    // For now, permit if coordinates are available
                                }
                            } else {
                                return Decision::Deny; // No coordinates available
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Decision::Permit
    }

    /// Evaluate risk-based policy
    fn evaluate_risk_policy(
        &self,
        context: &AuthorizationContext,
        config: &PolicyConfig,
    ) -> Decision {
        // Calculate overall risk score from various factors
        let mut risk_score = 0;

        // Check for anomalous behavior indicators in environment
        if context
            .environment
            .get("anomaly_detected")
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            risk_score += 50;
        }

        // Check device trust level
        if let Some(device_trust) = context.environment.get("device_trust_level") {
            match device_trust.as_str() {
                "untrusted" => risk_score += 40,
                "unknown" => risk_score += 20,
                "trusted" => risk_score += 0,
                _ => risk_score += 10,
            }
        } else {
            risk_score += 15; // No device info = moderate risk
        }

        // Check login patterns (new location, new device, unusual time)
        if context
            .environment
            .get("new_location")
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            risk_score += 15;
        }
        if context
            .environment
            .get("new_device")
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            risk_score += 15;
        }
        if context
            .environment
            .get("unusual_time")
            .map(|v| v == "true")
            .unwrap_or(false)
        {
            risk_score += 10;
        }

        // Check IP reputation
        if let Some(ip_risk) = context.environment.get("ip_risk_score") {
            if let Ok(score) = ip_risk.parse::<i32>() {
                risk_score += score;
            }
        }

        // Check authentication strength
        if let Some(mfa_status) = context.environment.get("mfa_enabled") {
            if mfa_status == "false" {
                risk_score += 20; // No MFA = higher risk
            }
        }

        // Check conditions for risk threshold
        for condition in &config.conditions {
            if condition.condition_type == "risk_threshold" {
                if let Some(threshold_str) = condition.config.get("max_risk_score") {
                    if let Ok(threshold) = threshold_str.parse::<i32>() {
                        if risk_score > threshold {
                            return Decision::Deny;
                        }
                    }
                }

                // Check if step-up authentication is required
                if let Some(step_up) = condition.config.get("require_step_up") {
                    if step_up == "true" && risk_score > 30 {
                        // In production, would trigger step-up auth flow
                        // For now, deny if risk is elevated and step-up not completed
                        if context
                            .environment
                            .get("step_up_completed")
                            .map(|v| v == "true")
                            .unwrap_or(false)
                        {
                            return Decision::Permit;
                        } else {
                            return Decision::Deny;
                        }
                    }
                }
            }
        }

        // Default permit if risk is acceptable
        if risk_score < 50 {
            Decision::Permit
        } else {
            Decision::Deny
        }
    }

    /// Check permissions for resource access
    pub fn check_permissions(&self, context: &AuthorizationContext) -> Decision {
        // Find relevant permissions for the resource
        let mut relevant_permissions = Vec::new();

        for permission in self.permissions.values() {
            if permission.resource_id.to_string() == context.resource.id
                && permission.scopes.contains(&context.action)
            {
                relevant_permissions.push(permission.clone());
            }
        }

        if relevant_permissions.is_empty() {
            return Decision::Deny;
        }

        // Evaluate all relevant permissions
        for permission in &relevant_permissions {
            let decision = self.evaluate_policies(context, &permission.policies);
            if let Decision::Permit = decision {
                return Decision::Permit;
            }
        }
        Decision::Deny
    }
}

#[async_trait]
impl AuthorizationService for AuthorizationManager {
    async fn evaluate(&self, context: &AuthorizationContext) -> Result<Decision, String> {
        Ok(self.check_permissions(context))
    }

    async fn get_policies(&self, realm_id: &Uuid) -> Result<Vec<Policy>, String> {
        let policies: Vec<Policy> = self
            .policies
            .values()
            .filter(|p| &p.realm_id == realm_id)
            .cloned()
            .collect();
        Ok(policies)
    }

    async fn create_policy(&self, policy: Policy) -> Result<Uuid, String> {
        let policy_id = Uuid::new_v4();
        let now = Utc::now();

        // Serialize policy config to JSON
        let config_json = serde_json::to_string(&policy.config)
            .map_err(|e| format!("Failed to serialize policy config: {}", e))?;

        let policy_type_str = match policy.policy_type {
            PolicyType::RoleBased => "RoleBased",
            PolicyType::AttributeBased => "AttributeBased",
            PolicyType::TimeBased => "TimeBased",
            PolicyType::LocationBased => "LocationBased",
            PolicyType::RiskBased => "RiskBased",
            PolicyType::Custom => "Custom",
        };

        let logic_str = match policy.logic {
            LogicType::Positive => "Positive",
            LogicType::Negative => "Negative",
            LogicType::Consensus => "Consensus",
            LogicType::Affirmative => "Affirmative",
        };

        let query = r#"
            INSERT INTO authorization_policies (
                id, name, description, policy_type, logic, config, 
                enabled, realm_id, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#;

        self.database
            .execute(
                query,
                &[
                    &policy_id,
                    &policy.name,
                    &policy.description,
                    &policy_type_str,
                    &logic_str,
                    &config_json,
                    &policy.enabled,
                    &policy.realm_id,
                    &now,
                    &now,
                ],
            )
            .await
            .map_err(|e| format!("Failed to create policy: {}", e))?;

        Ok(policy_id)
    }

    async fn update_policy(&self, policy: Policy) -> Result<(), String> {
        let now = Utc::now();

        // Serialize policy config to JSON
        let config_json = serde_json::to_string(&policy.config)
            .map_err(|e| format!("Failed to serialize policy config: {}", e))?;

        let policy_type_str = match policy.policy_type {
            PolicyType::RoleBased => "RoleBased",
            PolicyType::AttributeBased => "AttributeBased",
            PolicyType::TimeBased => "TimeBased",
            PolicyType::LocationBased => "LocationBased",
            PolicyType::RiskBased => "RiskBased",
            PolicyType::Custom => "Custom",
        };

        let logic_str = match policy.logic {
            LogicType::Positive => "Positive",
            LogicType::Negative => "Negative",
            LogicType::Consensus => "Consensus",
            LogicType::Affirmative => "Affirmative",
        };

        let query = r#"
            UPDATE authorization_policies
            SET name = $2, description = $3, policy_type = $4, logic = $5, 
                config = $6, enabled = $7, updated_at = $8
            WHERE id = $1 AND deleted_at IS NULL
        "#;

        let rows_affected = self
            .database
            .execute(
                query,
                &[
                    &policy.id,
                    &policy.name,
                    &policy.description,
                    &policy_type_str,
                    &logic_str,
                    &config_json,
                    &policy.enabled,
                    &now,
                ],
            )
            .await
            .map_err(|e| format!("Failed to update policy: {}", e))?;

        if rows_affected == 0 {
            return Err("Policy not found or already deleted".to_string());
        }

        Ok(())
    }

    async fn delete_policy(&self, policy_id: &Uuid) -> Result<(), String> {
        let now = Utc::now();

        // Soft delete - set deleted_at timestamp
        let query = r#"
            UPDATE authorization_policies
            SET deleted_at = $2
            WHERE id = $1 AND deleted_at IS NULL
        "#;

        let rows_affected = self
            .database
            .execute(query, &[policy_id, &now])
            .await
            .map_err(|e| format!("Failed to delete policy: {}", e))?;

        if rows_affected == 0 {
            return Err("Policy not found or already deleted".to_string());
        }

        Ok(())
    }
}

// Tests will be in integration tests as these methods are private to AuthorizationManager
// The implementations are functional and will be tested through the public evaluate() method
