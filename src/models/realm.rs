use crate::error::AuthencError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Realm entity representing a tenant or namespace with enterprise features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Realm {
    pub id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub ssl_required: String, // "external", "none", "all"
    pub registration_allowed: bool,
    pub registration_email_as_username: bool,
    pub remember_me: bool,
    pub verify_email: bool,
    pub login_with_email_allowed: bool,
    pub duplicate_emails_allowed: bool,
    pub reset_password_allowed: bool,
    pub edit_username_allowed: bool,
    pub brute_force_protected: bool,
    pub max_failure_wait_seconds: i32,
    pub minimum_quick_login_wait_seconds: i32,
    pub wait_increment_seconds: i32,
    pub quick_login_check_milli_seconds: i64,
    pub max_delta_time_seconds: i32,
    pub failure_factor: i32,
    pub default_signature_algorithm: String,
    pub revoke_refresh_token: bool,
    pub refresh_token_max_reuse: i32,
    pub access_token_lifespan: i32,
    pub access_token_lifespan_for_implicit_flow: i32,
    pub sso_session_idle_timeout: i32,
    pub sso_session_max_lifespan: i32,
    pub sso_session_idle_timeout_remember_me: i32,
    pub sso_session_max_lifespan_remember_me: i32,
    pub offline_session_idle_timeout: i32,
    pub offline_session_max_lifespan: i32,
    pub client_session_idle_timeout: i32,
    pub client_session_max_lifespan: i32,
    pub access_code_lifespan: i32,
    pub access_code_lifespan_user_action: i32,
    pub access_code_lifespan_login: i32,
    pub action_token_generated_by_admin_lifespan: i32,
    pub action_token_generated_by_user_lifespan: i32,
    pub oauth2_device_code_lifespan: i32,
    pub oauth2_device_polling_interval: i32,
    pub attributes: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Realm creation request
#[derive(Debug, Deserialize)]
pub struct CreateRealmRequest {
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub attributes: Option<serde_json::Value>,
}

/// Realm update request
#[derive(Debug, Deserialize)]
pub struct UpdateRealmRequest {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub ssl_required: Option<String>,
    pub registration_allowed: Option<bool>,
    pub verify_email: Option<bool>,
    pub reset_password_allowed: Option<bool>,
    pub brute_force_protected: Option<bool>,
    pub attributes: Option<serde_json::Value>,
}

/// Realm response
#[derive(Debug, Serialize)]
pub struct RealmResponse {
    pub id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Realm> for RealmResponse {
    fn from(realm: Realm) -> Self {
        Self {
            id: realm.id,
            name: realm.name,
            display_name: realm.display_name,
            description: realm.description,
            enabled: realm.enabled,
            created_at: realm.created_at,
            updated_at: realm.updated_at,
        }
    }
}

impl Default for Realm {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: "master".to_string(),
            display_name: Some("Master".to_string()),
            description: Some("Master realm".to_string()),
            enabled: true,
            ssl_required: "external".to_string(),
            registration_allowed: false,
            registration_email_as_username: false,
            remember_me: true,
            verify_email: false,
            login_with_email_allowed: true,
            duplicate_emails_allowed: false,
            reset_password_allowed: true,
            edit_username_allowed: false,
            brute_force_protected: true,
            max_failure_wait_seconds: 900,
            minimum_quick_login_wait_seconds: 60,
            wait_increment_seconds: 60,
            quick_login_check_milli_seconds: 1000,
            max_delta_time_seconds: 60 * 60 * 12, // 12 hours
            failure_factor: 30,
            default_signature_algorithm: "RS256".to_string(),
            revoke_refresh_token: false,
            refresh_token_max_reuse: 0,
            access_token_lifespan: 300,                   // 5 minutes
            access_token_lifespan_for_implicit_flow: 900, // 15 minutes
            sso_session_idle_timeout: 1800,               // 30 minutes
            sso_session_max_lifespan: 36000,              // 10 hours
            sso_session_idle_timeout_remember_me: 0,
            sso_session_max_lifespan_remember_me: 0,
            offline_session_idle_timeout: 2592000, // 30 days
            offline_session_max_lifespan: 5184000, // 60 days
            client_session_idle_timeout: 0,
            client_session_max_lifespan: 0,
            access_code_lifespan: 60,                        // 1 minute
            access_code_lifespan_user_action: 300,           // 5 minutes
            access_code_lifespan_login: 1800,                // 30 minutes
            action_token_generated_by_admin_lifespan: 43200, // 12 hours
            action_token_generated_by_user_lifespan: 300,    // 5 minutes
            oauth2_device_code_lifespan: 600,                // 10 minutes
            oauth2_device_polling_interval: 5,
            attributes: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        }
    }
}

impl Realm {
    /// Create a new realm with default values
    pub fn new(name: String) -> Self {
        let mut realm = Self::default();
        realm.id = Uuid::new_v4();
        realm.name = name.clone();
        realm.display_name = Some(name);
        realm.created_at = Utc::now();
        realm.updated_at = Utc::now();
        realm
    }

    /// Update realm fields
    pub fn update(&mut self, request: UpdateRealmRequest) {
        if let Some(display_name) = request.display_name {
            self.display_name = Some(display_name);
        }
        if let Some(description) = request.description {
            self.description = Some(description);
        }
        if let Some(enabled) = request.enabled {
            self.enabled = enabled;
        }
        if let Some(ssl_required) = request.ssl_required {
            self.ssl_required = ssl_required;
        }
        if let Some(registration_allowed) = request.registration_allowed {
            self.registration_allowed = registration_allowed;
        }
        if let Some(verify_email) = request.verify_email {
            self.verify_email = verify_email;
        }
        if let Some(reset_password_allowed) = request.reset_password_allowed {
            self.reset_password_allowed = reset_password_allowed;
        }
        if let Some(brute_force_protected) = request.brute_force_protected {
            self.brute_force_protected = brute_force_protected;
        }
        if let Some(attributes) = request.attributes {
            self.attributes = Some(attributes);
        }
        self.updated_at = Utc::now();
    }

    /// Check if realm is active
    pub fn is_active(&self) -> bool {
        self.enabled && self.deleted_at.is_none()
    }

    /// Soft delete the realm
    pub fn delete(&mut self) {
        self.deleted_at = Some(Utc::now());
        self.updated_at = Utc::now();
    }

    /// Get realm attribute
    pub fn get_attribute(&self, key: &str) -> Option<&serde_json::Value> {
        self.attributes.as_ref()?.get(key)
    }

    /// Set realm attribute
    pub fn set_attribute(&mut self, key: String, value: serde_json::Value) {
        let mut attributes = self
            .attributes
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));
        if let serde_json::Value::Object(ref mut map) = attributes {
            map.insert(key, value);
        }
        self.attributes = Some(attributes);
        self.updated_at = Utc::now();
    }

    /// Remove realm attribute
    pub fn remove_attribute(&mut self, key: &str) {
        if let Some(serde_json::Value::Object(ref mut map)) = self.attributes {
            map.remove(key);
        }
        self.updated_at = Utc::now();
    }
}

impl TryFrom<tokio_postgres::Row> for Realm {
    type Error = AuthencError;

    fn try_from(row: tokio_postgres::Row) -> Result<Self, Self::Error> {
        Ok(Realm {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            display_name: row.try_get("display_name")?,
            description: row.try_get("description")?,
            enabled: row.try_get("enabled")?,
            ssl_required: row.try_get("ssl_required")?,
            registration_allowed: row.try_get("registration_allowed")?,
            registration_email_as_username: row.try_get("registration_email_as_username")?,
            remember_me: row.try_get("remember_me")?,
            verify_email: row.try_get("verify_email")?,
            login_with_email_allowed: row.try_get("login_with_email_allowed")?,
            duplicate_emails_allowed: row.try_get("duplicate_emails_allowed")?,
            reset_password_allowed: row.try_get("reset_password_allowed")?,
            edit_username_allowed: row.try_get("edit_username_allowed")?,
            brute_force_protected: row.try_get("brute_force_protected")?,
            max_failure_wait_seconds: row.try_get("max_failure_wait_seconds")?,
            minimum_quick_login_wait_seconds: row.try_get("minimum_quick_login_wait_seconds")?,
            wait_increment_seconds: row.try_get("wait_increment_seconds")?,
            quick_login_check_milli_seconds: row.try_get("quick_login_check_milli_seconds")?,
            max_delta_time_seconds: row.try_get("max_delta_time_seconds")?,
            failure_factor: row.try_get("failure_factor")?,
            default_signature_algorithm: row.try_get("default_signature_algorithm")?,
            revoke_refresh_token: row.try_get("revoke_refresh_token")?,
            refresh_token_max_reuse: row.try_get("refresh_token_max_reuse")?,
            access_token_lifespan: row.try_get("access_token_lifespan")?,
            access_token_lifespan_for_implicit_flow: row
                .try_get("access_token_lifespan_for_implicit_flow")?,
            sso_session_idle_timeout: row.try_get("sso_session_idle_timeout")?,
            sso_session_max_lifespan: row.try_get("sso_session_max_lifespan")?,
            sso_session_idle_timeout_remember_me: row
                .try_get("sso_session_idle_timeout_remember_me")?,
            sso_session_max_lifespan_remember_me: row
                .try_get("sso_session_max_lifespan_remember_me")?,
            offline_session_idle_timeout: row.try_get("offline_session_idle_timeout")?,
            offline_session_max_lifespan: row.try_get("offline_session_max_lifespan")?,
            client_session_idle_timeout: row.try_get("client_session_idle_timeout")?,
            client_session_max_lifespan: row.try_get("client_session_max_lifespan")?,
            access_code_lifespan: row.try_get("access_code_lifespan")?,
            access_code_lifespan_user_action: row.try_get("access_code_lifespan_user_action")?,
            access_code_lifespan_login: row.try_get("access_code_lifespan_login")?,
            action_token_generated_by_admin_lifespan: row
                .try_get("action_token_generated_by_admin_lifespan")?,
            action_token_generated_by_user_lifespan: row
                .try_get("action_token_generated_by_user_lifespan")?,
            oauth2_device_code_lifespan: row.try_get("oauth2_device_code_lifespan")?,
            oauth2_device_polling_interval: row.try_get("oauth2_device_polling_interval")?,
            attributes: {
                let json_str: Option<String> = row.try_get("attributes")?;
                json_str.and_then(|s| serde_json::from_str(&s).ok())
            },
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
            deleted_at: row.try_get("deleted_at")?,
        })
    }
}
