use authenc_api::error::{AuthencError, Result};
use authenc_api::models::audit::*;
use authenc_api::models::device::*;
use authenc_api::models::oauth2::*;
use authenc_api::models::organization::*;
use authenc_api::models::permission_ticket::*;
use authenc_api::models::realm::*;
use authenc_api::models::resource::*;
use authenc_api::models::resource_server::*;
use authenc_api::models::saml::*;
use authenc_api::models::scope::*;
use authenc_api::models::user::*;
use tokio_postgres::Row;

use crate::database::FromPostgresRow;

impl FromPostgresRow for Organization {
    fn from_row(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Organization {
            id: row.try_get("id").map_err(|e| AuthencError::database(format!("Failed to get id: {}", e)))?,
            name: row.try_get("name").map_err(|e| AuthencError::database(format!("Failed to get name: {}", e)))?,
            display_name: row.try_get("display_name").ok(),
            website_url: row.try_get("website_url").ok().or_else(|| row.try_get("url").ok()),
            logo_url: row.try_get("logo_url").ok(),
            owner_id: row.try_get("owner_id").map_err(|e| AuthencError::database(format!("Failed to get owner_id: {}", e)))?,
            realm_id: row.try_get("realm_id").ok(),
            enabled: row.try_get("enabled").unwrap_or(true),
            description: row.try_get("description").ok(),
            domain: row.try_get("domain").ok(),
            created_at: row.try_get("created_at").map_err(|e| AuthencError::database(format!("Failed to get created_at: {}", e)))?,
            updated_at: row.try_get("updated_at").map_err(|e| AuthencError::database(format!("Failed to get updated_at: {}", e)))?,
            deleted_at: row.try_get("deleted_at").ok(),
        })
    }
}

impl FromPostgresRow for PermissionTicket {
    fn from_row(row: tokio_postgres::Row) -> Result<Self> {
        Ok(PermissionTicket {
            id: row.try_get("id").map_err(|e| {
                AuthencError::database(format!("Failed to get id: {}", e))
            })?,
            resource_id: row.try_get("resource_id").map_err(|e| {
                AuthencError::database(format!("Failed to get resource_id: {}", e))
            })?,
            scope_id: row.try_get("scope_id").map_err(|e| {
                AuthencError::database(format!("Failed to get scope_id: {}", e))
            })?,
            owner: row.try_get("owner").map_err(|e| {
                AuthencError::database(format!("Failed to get owner: {}", e))
            })?,
            requester: row.try_get("requester").map_err(|e| {
                AuthencError::database(format!("Failed to get requester: {}", e))
            })?,
            granted: row.try_get("granted").map_err(|e| {
                AuthencError::database(format!("Failed to get granted: {}", e))
            })?,
            granted_timestamp: row.try_get("granted_timestamp").map_err(|e| {
                AuthencError::database(format!(
                    "Failed to get granted_timestamp: {}",
                    e
                ))
            })?,
            realm_id: row.try_get("realm_id").map_err(|e| {
                AuthencError::database(format!("Failed to get realm_id: {}", e))
            })?,
            resource_server_id: row.try_get("resource_server_id").map_err(|e| {
                AuthencError::database(format!(
                    "Failed to get resource_server_id: {}",
                    e
                ))
            })?,
            created_at: row.try_get("created_at").map_err(|e| {
                AuthencError::database(format!("Failed to get created_at: {}", e))
            })?,
            updated_at: row.try_get("updated_at").map_err(|e| {
                AuthencError::database(format!("Failed to get updated_at: {}", e))
            })?,
        })
    }
}

impl FromPostgresRow for Realm {
    fn from_row(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Realm {
            id: row.try_get("id").map_err(|e| AuthencError::database(e.to_string()))?,
            name: row.try_get("name").map_err(|e| AuthencError::database(e.to_string()))?,
            display_name: row.try_get("display_name").ok(),
            description: row.try_get("description").ok(),
            enabled: row.try_get("enabled").unwrap_or(true),
            registration_allowed: row.try_get("registration_allowed").unwrap_or(false),
            registration_email_as_username: row.try_get("registration_email_as_username").unwrap_or(false),
            verify_email: row.try_get("verify_email").unwrap_or(false),
            login_with_email_allowed: row.try_get("login_with_email_allowed").unwrap_or(true),
            duplicate_emails_allowed: row.try_get("duplicate_emails_allowed").unwrap_or(false),
            reset_password_allowed: row.try_get("reset_password_allowed").unwrap_or(true),
            edit_username_allowed: row.try_get("edit_username_allowed").unwrap_or(false),
            brute_force_protected: row.try_get("brute_force_protected").unwrap_or(true),
            max_failure_wait_seconds: row.try_get("max_failure_wait_seconds").unwrap_or(900),
            minimum_quick_login_wait_seconds: row.try_get("minimum_quick_login_wait_seconds").unwrap_or(60),
            wait_increment_seconds: row.try_get("wait_increment_seconds").unwrap_or(60),
            quick_login_check_milli_seconds: row.try_get("quick_login_check_milli_seconds").unwrap_or(1000),
            max_delta_time_seconds: row.try_get("max_delta_time_seconds").unwrap_or(43200),
            failure_factor: row.try_get("failure_factor").unwrap_or(30),
            default_signature_algorithm: row.try_get("default_signature_algorithm").unwrap_or_else(|_| "RS256".to_string()),
            revoke_refresh_token: row.try_get("revoke_refresh_token").unwrap_or(false),
            refresh_token_max_reuse: row.try_get("refresh_token_max_reuse").unwrap_or(0),
            access_token_lifespan: row.try_get("access_token_lifespan").unwrap_or(300),
            access_token_lifespan_for_implicit_flow: row.try_get("access_token_lifespan_for_implicit_flow").unwrap_or(900),
            sso_session_idle_timeout: row.try_get("sso_session_idle_timeout").unwrap_or(1800),
            sso_session_max_lifespan: row.try_get("sso_session_max_lifespan").unwrap_or(36000),
            sso_session_idle_timeout_remember_me: row.try_get("sso_session_idle_timeout_remember_me").unwrap_or(0),
            sso_session_max_lifespan_remember_me: row.try_get("sso_session_max_lifespan_remember_me").unwrap_or(0),
            offline_session_idle_timeout: row.try_get("offline_session_idle_timeout").unwrap_or(2592000),
            offline_session_max_lifespan: row.try_get("offline_session_max_lifespan").unwrap_or(5184000),
            client_session_idle_timeout: row.try_get("client_session_idle_timeout").unwrap_or(0),
            client_session_max_lifespan: row.try_get("client_session_max_lifespan").unwrap_or(0),
            access_code_lifespan: row.try_get("access_code_lifespan").unwrap_or(60),
            access_code_lifespan_user_action: row.try_get("access_code_lifespan_user_action").unwrap_or(300),
            access_code_lifespan_login: row.try_get("access_code_lifespan_login").unwrap_or(1800),
            action_token_generated_by_admin_lifespan: row.try_get("action_token_generated_by_admin_lifespan").unwrap_or(43200),
            action_token_generated_by_user_lifespan: row.try_get("action_token_generated_by_user_lifespan").unwrap_or(300),
            oauth2_device_code_lifespan: row.try_get("oauth2_device_code_lifespan").unwrap_or(600),
            oauth2_device_polling_interval: row.try_get("oauth2_device_polling_interval").unwrap_or(5),
            attributes: {
                let json_str: Option<String> = row.try_get("attributes").map_err(|e| AuthencError::database(e.to_string()))?;
                match json_str {
                    Some(s) => serde_json::from_str(&s).ok(),
                    None => None,
                }
            },
            ssl_required: row.try_get("ssl_required").unwrap_or_else(|_| "external".to_string()),
            remember_me: row.try_get("remember_me").unwrap_or(false),
            created_at: row.try_get("created_at").map_err(|e| AuthencError::database(e.to_string()))?,
            updated_at: row.try_get("updated_at").map_err(|e| AuthencError::database(e.to_string()))?,
            deleted_at: row.try_get("deleted_at").ok(),
        })
    }
}

impl FromPostgresRow for Resource {
    fn from_row(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Resource {
            id: row.try_get("id").map_err(|e| AuthencError::database(format!("Failed to get id: {}", e)))?,
            name: row.try_get("name").map_err(|e| AuthencError::database(format!("Failed to get name: {}", e)))?,
            display_name: row.try_get("display_name").map_err(|e| AuthencError::database(format!("Failed to get display_name: {}", e)))?,
            uris: {
                let uris_str: Option<String> = row.try_get("uris").map_err(|e| AuthencError::database(format!("Failed to get uris: {}", e)))?;
                match uris_str {
                    Some(s) => serde_json::from_str(&s).unwrap_or_default(),
                    None => Vec::new(),
                }
            },
            icon_uri: row.try_get("icon_uri").map_err(|e| AuthencError::database(format!("Failed to get icon_uri: {}", e)))?,
            resource_type: row.try_get("resource_type").map_err(|e| AuthencError::database(format!("Failed to get resource_type: {}", e)))?,
            owner: row.try_get("owner").map_err(|e| AuthencError::database(format!("Failed to get owner: {}", e)))?,
            enabled: row.try_get("enabled").map_err(|e| AuthencError::database(format!("Failed to get enabled: {}", e)))?,
            realm_id: row.try_get("realm_id").map_err(|e| AuthencError::database(format!("Failed to get realm_id: {}", e)))?,
            resource_server_id: row.try_get("resource_server_id").map_err(|e| AuthencError::database(format!("Failed to get resource_server_id: {}", e)))?,
            scopes: {
                let scopes_str: Option<String> = row.try_get("scopes").map_err(|e| AuthencError::database(format!("Failed to get scopes: {}", e)))?;
                match scopes_str {
                    Some(s) => serde_json::from_str(&s).unwrap_or_default(),
                    None => Vec::new(),
                }
            },
            attributes: {
                let json_str: Option<String> = row.try_get("attributes").map_err(|e| AuthencError::database(format!("Failed to get attributes: {}", e)))?;
                match json_str {
                    Some(s) => serde_json::from_str(&s).unwrap_or_default(),
                    None => std::collections::HashMap::new(),
                }
            },
            created_at: row.try_get("created_at").map_err(|e| AuthencError::database(format!("Failed to get created_at: {}", e)))?,
            updated_at: row.try_get("updated_at").map_err(|e| AuthencError::database(format!("Failed to get updated_at: {}", e)))?,
        })
    }
}

impl FromPostgresRow for ResourceServer {
    fn from_row(row: tokio_postgres::Row) -> Result<Self> {
        Ok(ResourceServer {
            id: row.try_get("id").map_err(|e| AuthencError::database(format!("Failed to get id: {}", e)))?,
            client_id: row.try_get("client_id").map_err(|e| AuthencError::database(format!("Failed to get client_id: {}", e)))?,
            name: row.try_get("name").map_err(|e| AuthencError::database(format!("Failed to get name: {}", e)))?,
            description: row.try_get("description").ok(),
            enabled: row.try_get("enabled").unwrap_or(true),
            allow_remote_resource_management: row.try_get("allow_remote_resource_management").map_err(|e| AuthencError::database(format!("Failed to get allow_remote_resource_management: {}", e)))?,
            policy_enforcement_mode: {
                let mode: String = row.try_get("policy_enforcement_mode").map_err(|e| AuthencError::database(format!("Failed to get policy_enforcement_mode: {}", e)))?;
                match mode.as_str() {
                    "ENFORCING" => PolicyEnforcementMode::Enforcing,
                    "PERMISSIVE" => PolicyEnforcementMode::Permissive,
                    "DISABLED" => PolicyEnforcementMode::Disabled,
                    _ => PolicyEnforcementMode::Enforcing,
                }
            },
            decision_strategy: {
                let strategy: String = row.try_get("decision_strategy").map_err(|e| AuthencError::database(format!("Failed to get decision_strategy: {}", e)))?;
                match strategy.as_str() {
                    "AFFIRMATIVE" => DecisionStrategy::Affirmative,
                    "UNANIMOUS" => DecisionStrategy::Unanimous,
                    "CONSENSUS" => DecisionStrategy::Consensus,
                    _ => DecisionStrategy::Unanimous,
                }
            },
            realm_id: row.try_get("realm_id").map_err(|e| AuthencError::database(format!("Failed to get realm_id: {}", e)))?,
            created_at: row.try_get("created_at").map_err(|e| AuthencError::database(format!("Failed to get created_at: {}", e)))?,
            updated_at: row.try_get("updated_at").map_err(|e| AuthencError::database(format!("Failed to get updated_at: {}", e)))?,
        })
    }
}

impl FromPostgresRow for Scope {
    fn from_row(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Scope {
            id: row.try_get("id").map_err(|e| AuthencError::database(format!("Failed to get id: {}", e)))?,
            name: row.try_get("name").map_err(|e| AuthencError::database(format!("Failed to get name: {}", e)))?,
            display_name: row.try_get("display_name").map_err(|e| AuthencError::database(format!("Failed to get display_name: {}", e)))?,
            icon_uri: row.try_get("icon_uri").map_err(|e| AuthencError::database(format!("Failed to get icon_uri: {}", e)))?,
            realm_id: row.try_get("realm_id").map_err(|e| AuthencError::database(format!("Failed to get realm_id: {}", e)))?,
            resource_server_id: row.try_get("resource_server_id").map_err(|e| AuthencError::database(format!("Failed to get resource_server_id: {}", e)))?,
            created_at: row.try_get("created_at").map_err(|e| AuthencError::database(format!("Failed to get created_at: {}", e)))?,
            updated_at: row.try_get("updated_at").map_err(|e| AuthencError::database(format!("Failed to get updated_at: {}", e)))?,
        })
    }
}

impl FromPostgresRow for IdentityProvider {
    fn from_row(row: tokio_postgres::Row) -> Result<Self> {
        Ok(IdentityProvider {
            id: row.try_get("id").map_err(|e| AuthencError::database(e.to_string()))?,
            alias: row.try_get("alias").map_err(|e| AuthencError::database(e.to_string()))?,
            display_name: row.try_get("display_name").ok(),
            provider_id: row.try_get("provider_id").map_err(|e| AuthencError::database(e.to_string()))?,
            enabled: row.try_get("enabled").unwrap_or(true),
            trust_email: row.try_get("trust_email").unwrap_or(false),
            store_token: row.try_get("store_token").unwrap_or(false),
            add_read_token_role_on_create: row.try_get("add_read_token_role_on_create").unwrap_or(false),
            authenticate_by_default: row.try_get("authenticate_by_default").unwrap_or(false),
            link_only: row.try_get("link_only").unwrap_or(false),
            first_broker_login_flow_id: row.try_get("first_broker_login_flow_alias").ok(),
            post_broker_login_flow_id: row.try_get("post_broker_login_flow_alias").ok(),
            config: {
                let json_str: Option<String> = row.try_get("config").map_err(|e| AuthencError::database(e.to_string()))?;
                match json_str {
                    Some(s) => serde_json::from_str(&s).unwrap_or_else(|_| serde_json::json!({})),
                    None => serde_json::json!({}),
                }
            },
            realm_id: row.try_get("realm_id").ok(),
            organization_id: row.try_get("organization_id").ok(),
            created_at: row.try_get("created_at").map_err(|e| AuthencError::database(e.to_string()))?,
            updated_at: row.try_get("updated_at").map_err(|e| AuthencError::database(e.to_string()))?,
        })
    }
}

impl FromPostgresRow for User {
    fn from_row(row: tokio_postgres::Row) -> Result<Self> {
        Ok(User {
            id: row.try_get("id").map_err(|e| AuthencError::database(e.to_string()))?,
            username: row.try_get("username").map_err(|e| AuthencError::database(e.to_string()))?,
            email: row.try_get("email").map_err(|e| AuthencError::database(e.to_string()))?,
            email_verified: row.try_get("email_verified").unwrap_or(false),
            first_name: row.try_get("first_name").ok(),
            last_name: row.try_get("last_name").ok(),
            phone_number: row.try_get("phone_number").ok(),
            phone_verified: row.try_get("phone_verified").unwrap_or(false),
            password_hash: row.try_get("password_hash").ok(),
            totp_secret: row.try_get("totp_secret").ok(),
            totp_backup_codes: {
                let codes: Option<Vec<String>> = row.try_get("totp_backup_codes").ok();
                Some(codes.unwrap_or_default())
            },
            webauthn_enabled: row.try_get("webauthn_enabled").unwrap_or(false),
            account_locked: row.try_get("account_locked").unwrap_or(false),
            account_locked_until: row.try_get("account_locked_until").ok(),
            failed_login_attempts: row.try_get("failed_login_attempts").unwrap_or(0),
            last_login_at: row.try_get("last_login_at").ok(),
            last_failed_login_at: row.try_get("last_failed_login_at").ok(),
            password_changed_at: row.try_get("password_changed_at").ok(),
            password_expires_at: row.try_get("password_expires_at").ok(),
            require_password_change: row.try_get("require_password_change").unwrap_or(false),
            realm_id: row.try_get("realm_id").ok(),
            organization_id: row.try_get("organization_id").ok(),
            attributes: {
                let json_str: Option<String> = row.try_get("attributes").ok();
                match json_str {
                    Some(s) => serde_json::from_str(&s).ok(),
                    None => None,
                }
            },
            enabled: row.try_get("enabled").unwrap_or(true),
            federated: row.try_get("federated").unwrap_or(false),
            created_at: row.try_get("created_at").map_err(|e| AuthencError::database(e.to_string()))?,
            updated_at: row.try_get("updated_at").map_err(|e| AuthencError::database(e.to_string()))?,
            deleted_at: row.try_get("deleted_at").ok(),
            login_count: row.try_get("login_count").unwrap_or(0),
        })
    }
}

impl FromPostgresRow for Device {
    fn from_row(row: tokio_postgres::Row) -> Result<Self> {
        Ok(Device {
            id: row.try_get("id").map_err(|e| AuthencError::database(e.to_string()))?,
            user_id: row.try_get("user_id").map_err(|e| AuthencError::database(e.to_string()))?,
            device_name: row.try_get("device_name").ok(),
            device_fingerprint: row.try_get("device_fingerprint").map_err(|e| AuthencError::database(e.to_string()))?,
            trust_score: row.try_get("trust_score").unwrap_or(0.0),
            risk_level: row.try_get("risk_level").unwrap_or_else(|_| "unknown".to_string()),
            os: row.try_get("os").ok(),
            os_version: row.try_get("os_version").ok(),
            browser: row.try_get("browser").ok(),
            browser_version: row.try_get("browser_version").ok(),
            ip_address: row.try_get("ip_address").ok(),
            user_agent: row.try_get("user_agent").ok(),
            location_data: {
                let json_str: Option<String> = row.try_get("location_data").ok();
                match json_str {
                    Some(s) => serde_json::from_str(&s).ok(),
                    None => None,
                }
            },
            security_features: {
                let json_str: Option<String> = row.try_get("security_features").ok();
                match json_str {
                    Some(s) => serde_json::from_str(&s).ok(),
                    None => None,
                }
            },
            last_seen_at: row.try_get("last_seen_at").map_err(|e| AuthencError::database(e.to_string()))?,
            first_seen_at: row.try_get("first_seen_at").map_err(|e| AuthencError::database(e.to_string()))?,
            created_at: row.try_get("created_at").map_err(|e| AuthencError::database(e.to_string()))?,
            updated_at: row.try_get("updated_at").map_err(|e| AuthencError::database(e.to_string()))?,
        })
    }
}

impl FromPostgresRow for OAuth2Client {
    fn from_row(row: tokio_postgres::Row) -> Result<Self> {
        Ok(OAuth2Client {
            id: row.try_get("id").map_err(|e| AuthencError::database(e.to_string()))?,
            client_id: row.try_get("client_id").map_err(|e| AuthencError::database(e.to_string()))?,
            client_secret_hash: row.try_get("client_secret_hash").map_err(|e| AuthencError::database(e.to_string()))?,
            client_name: row.try_get("client_name").map_err(|e| AuthencError::database(e.to_string()))?,
            client_type: row.try_get("client_type").map_err(|e| AuthencError::database(e.to_string()))?,
            redirect_uris: row.try_get("redirect_uris").map_err(|e| AuthencError::database(e.to_string()))?,
            scopes: row.try_get("scopes").map_err(|e| AuthencError::database(e.to_string()))?,
            grant_types: row.try_get("grant_types").map_err(|e| AuthencError::database(e.to_string()))?,
            response_types: row.try_get("response_types").map_err(|e| AuthencError::database(e.to_string()))?,
            token_endpoint_auth_method: row.try_get("token_endpoint_auth_method").map_err(|e| AuthencError::database(e.to_string()))?,
            owner_id: row.try_get("owner_id").map_err(|e| AuthencError::database(e.to_string()))?,
            realm_id: row.try_get("realm_id").map_err(|e| AuthencError::database(e.to_string()))?,
            enabled: row.try_get("enabled").map_err(|e| AuthencError::database(e.to_string()))?,
            created_at: row.try_get("created_at").map_err(|e| AuthencError::database(e.to_string()))?,
            updated_at: row.try_get("updated_at").map_err(|e| AuthencError::database(e.to_string()))?,
            deleted_at: row.try_get("deleted_at").map_err(|e| AuthencError::database(e.to_string()))?,
        })
    }
}

impl FromPostgresRow for OAuth2AuthorizationCode {
    fn from_row(row: tokio_postgres::Row) -> Result<Self> {
        Ok(OAuth2AuthorizationCode {
            id: row.try_get("id").map_err(|e| AuthencError::database(e.to_string()))?,
            code: row.try_get("code").map_err(|e| AuthencError::database(e.to_string()))?,
            client_id: row.try_get("client_id").map_err(|e| AuthencError::database(e.to_string()))?,
            user_id: row.try_get("user_id").map_err(|e| AuthencError::database(e.to_string()))?,
            redirect_uri: row.try_get("redirect_uri").map_err(|e| AuthencError::database(e.to_string()))?,
            scopes: row.try_get("scopes").map_err(|e| AuthencError::database(e.to_string()))?,
            code_challenge: row.try_get("code_challenge").map_err(|e| AuthencError::database(e.to_string()))?,
            code_challenge_method: row.try_get("code_challenge_method").map_err(|e| AuthencError::database(e.to_string()))?,
            expires_at: row.try_get("expires_at").map_err(|e| AuthencError::database(e.to_string()))?,
            used: row.try_get("used").map_err(|e| AuthencError::database(e.to_string()))?,
            created_at: row.try_get("created_at").map_err(|e| AuthencError::database(e.to_string()))?,
        })
    }
}

impl FromPostgresRow for OAuth2AccessToken {
    fn from_row(row: tokio_postgres::Row) -> Result<Self> {
        Ok(OAuth2AccessToken {
            id: row.try_get("id").map_err(|e| AuthencError::database(e.to_string()))?,
            token_hash: row.try_get("token_hash").map_err(|e| AuthencError::database(e.to_string()))?,
            refresh_token_hash: row.try_get("refresh_token_hash").map_err(|e| AuthencError::database(e.to_string()))?,
            client_id: row.try_get("client_id").map_err(|e| AuthencError::database(e.to_string()))?,
            user_id: row.try_get("user_id").map_err(|e| AuthencError::database(e.to_string()))?,
            scopes: row.try_get("scopes").map_err(|e| AuthencError::database(e.to_string()))?,
            expires_at: row.try_get("expires_at").map_err(|e| AuthencError::database(e.to_string()))?,
            refresh_expires_at: row.try_get("refresh_expires_at").map_err(|e| AuthencError::database(e.to_string()))?,
            revoked: row.try_get("revoked").map_err(|e| AuthencError::database(e.to_string()))?,
            revoked_at: row.try_get("revoked_at").map_err(|e| AuthencError::database(e.to_string()))?,
            created_at: row.try_get("created_at").map_err(|e| AuthencError::database(e.to_string()))?,
            last_used_at: row.try_get("last_used_at").map_err(|e| AuthencError::database(e.to_string()))?,
            session_id: row.try_get("session_id").map_err(|e| AuthencError::database(e.to_string()))?,
        })
    }
}

impl FromPostgresRow for OrganizationInvitation {
    fn from_row(row: tokio_postgres::Row) -> Result<Self> {
        Ok(OrganizationInvitation {
            id: row.try_get("id").map_err(|e| AuthencError::database(e.to_string()))?,
            organization_id: row.try_get("organization_id").map_err(|e| AuthencError::database(e.to_string()))?,
            email: row.try_get("email").map_err(|e| AuthencError::database(e.to_string()))?,
            role: row.try_get("role").map_err(|e| AuthencError::database(e.to_string()))?,
            invited_by: row.try_get("invited_by").map_err(|e| AuthencError::database(e.to_string()))?,
            token_hash: row.try_get("token_hash").map_err(|e| AuthencError::database(e.to_string()))?,
            expires_at: row.try_get("expires_at").map_err(|e| AuthencError::database(e.to_string()))?,
            accepted_at: row.try_get("accepted_at").map_err(|e| AuthencError::database(e.to_string()))?,
            accepted_by: row.try_get("accepted_by").map_err(|e| AuthencError::database(e.to_string()))?,
            created_at: row.try_get("created_at").map_err(|e| AuthencError::database(e.to_string()))?,
        })
    }
}

impl FromPostgresRow for SamlServiceProvider {
    fn from_row(row: tokio_postgres::Row) -> Result<Self> {
        Ok(SamlServiceProvider {
            id: row.try_get("id").map_err(|e| AuthencError::database(e.to_string()))?,
            entity_id: row.try_get("entity_id").map_err(|e| AuthencError::database(e.to_string()))?,
            metadata_url: row.try_get("metadata_url").ok(),
            metadata_xml: row.try_get("metadata_xml").ok(),
            signing_certificate: row.try_get("signing_certificate").ok(),
            encryption_certificate: row.try_get("encryption_certificate").ok(),
            assertion_consumer_service_url: row.try_get("assertion_consumer_service_url").map_err(|e| AuthencError::database(e.to_string()))?,
            single_logout_service_url: row.try_get("single_logout_service_url").ok(),
            name_id_format: row.try_get("name_id_format").unwrap_or_else(|_| "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".to_string()),
            enabled: row.try_get("enabled").unwrap_or(true),
            realm_id: row.try_get("realm_id").ok(),
            created_at: row.try_get("created_at").map_err(|e| AuthencError::database(e.to_string()))?,
            updated_at: row.try_get("updated_at").map_err(|e| AuthencError::database(e.to_string()))?,
            deleted_at: row.try_get("deleted_at").ok(),
        })
    }
}

impl FromPostgresRow for SamlSession {
    fn from_row(row: tokio_postgres::Row) -> Result<Self> {
        Ok(SamlSession {
            id: row.try_get("id").map_err(|e| AuthencError::database(e.to_string()))?,
            session_id: row.try_get("session_id").map_err(|e| AuthencError::database(e.to_string()))?,
            user_id: row.try_get("user_id").map_err(|e| AuthencError::database(e.to_string()))?,
            identity_provider_id: row.try_get("identity_provider_id").map_err(|e| AuthencError::database(e.to_string()))?,
            service_provider_id: row.try_get("service_provider_id").ok(),
            name_id: row.try_get("name_id").map_err(|e| AuthencError::database(e.to_string()))?,
            name_id_format: row.try_get("name_id_format").map_err(|e| AuthencError::database(e.to_string()))?,
            session_index: row.try_get("session_index").ok(),
            authn_instant: row.try_get("authn_instant").map_err(|e| AuthencError::database(e.to_string()))?,
            expires_at: row.try_get("expires_at").map_err(|e| AuthencError::database(e.to_string()))?,
            created_at: row.try_get("created_at").map_err(|e| AuthencError::database(e.to_string()))?,
        })
    }
}
