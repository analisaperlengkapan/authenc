// LDAP Identity Provider Implementation

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use ldap3::{LdapConnAsync, Scope, SearchEntry};
use std::collections::HashMap;

use super::{AuthRequest, AuthResponse, IdentityProvider, IdentityProviderConfig, UserInfo};

/// LDAP Identity Provider
pub struct LdapIdentityProvider {
    /// Provider configuration
    config: IdentityProviderConfig,
    /// LDAP server URL
    url: String,
    /// Base DN for searches
    base_dn: String,
    /// Bind DN for initial connection (optional)
    bind_dn: Option<String>,
    /// Bind password for initial connection (optional)
    bind_password: Option<String>,
    /// User search filter template (e.g. "(uid={})")
    user_search_filter: String,
}

impl LdapIdentityProvider {
    /// Create new LDAP identity provider
    pub async fn new(config: IdentityProviderConfig) -> Result<Self> {
        let url = config
            .config
            .get("url")
            .ok_or_else(|| anyhow!("Missing url in LDAP config"))?
            .clone();

        let base_dn = config
            .config
            .get("base_dn")
            .ok_or_else(|| anyhow!("Missing base_dn in LDAP config"))?
            .clone();

        let bind_dn = config.config.get("bind_dn").cloned();
        let bind_password = config.config.get("bind_password").cloned();

        let user_search_filter = config
            .config
            .get("user_search_filter")
            .cloned()
            .unwrap_or_else(|| "(uid={})".to_string());

        Ok(Self {
            config,
            url,
            base_dn,
            bind_dn,
            bind_password,
            user_search_filter,
        })
    }

    /// Connect to LDAP server
    async fn connect(&self) -> Result<(ldap3::LdapConnAsync, ldap3::Ldap)> {
        let (conn, ldap) = LdapConnAsync::new(&self.url).await?;
        Ok((conn, ldap))
    }

    /// Map LDAP attributes to UserInfo
    fn map_attributes(&self, entry: &SearchEntry) -> UserInfo {
        let mut user_info = UserInfo {
            id: entry.dn.clone(),
            username: None,
            email: None,
            first_name: None,
            last_name: None,
            groups: vec![],
            roles: vec![],
            attributes: HashMap::new(),
        };

        // Get attribute mapping from config
        let username_attr = self
            .config
            .config
            .get("username_attr")
            .map(|s| s.as_str())
            .unwrap_or("uid");
        let email_attr = self
            .config
            .config
            .get("email_attr")
            .map(|s| s.as_str())
            .unwrap_or("mail");
        let first_name_attr = self
            .config
            .config
            .get("first_name_attr")
            .map(|s| s.as_str())
            .unwrap_or("givenName");
        let last_name_attr = self
            .config
            .config
            .get("last_name_attr")
            .map(|s| s.as_str())
            .unwrap_or("sn");
        let group_attr = self
            .config
            .config
            .get("group_attr")
            .map(|s| s.as_str())
            .unwrap_or("memberOf");

        for (attr_name, values) in &entry.attrs {
            let value = values.first().cloned().unwrap_or_default();

            if attr_name.eq_ignore_ascii_case(username_attr) {
                user_info.username = Some(value.clone());
            } else if attr_name.eq_ignore_ascii_case(email_attr) {
                user_info.email = Some(value.clone());
            } else if attr_name.eq_ignore_ascii_case(first_name_attr) {
                user_info.first_name = Some(value.clone());
            } else if attr_name.eq_ignore_ascii_case(last_name_attr) {
                user_info.last_name = Some(value.clone());
            } else if attr_name.eq_ignore_ascii_case(group_attr) {
                user_info.groups = values.clone();
            } else {
                // Store other attributes
                user_info.attributes.insert(attr_name.clone(), value);
            }
        }

        // If username is still missing, try to infer from DN or use id
        if user_info.username.is_none() {
            user_info.username = Some(entry.dn.clone());
        }

        user_info
    }
}

/// Escape value for use in LDAP filter
fn escape_ldap_filter_value(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '*' => escaped.push_str("\\2a"),
            '(' => escaped.push_str("\\28"),
            ')' => escaped.push_str("\\29"),
            '\\' => escaped.push_str("\\5c"),
            '\0' => escaped.push_str("\\00"),
            _ => escaped.push(c),
        }
    }
    escaped
}

#[async_trait]
impl IdentityProvider for LdapIdentityProvider {
    async fn authenticate(&self, request: &AuthRequest) -> Result<AuthResponse> {
        let username = match &request.username {
            Some(u) if !u.is_empty() => u,
            _ => return Ok(AuthResponse {
                success: false,
                user_id: None,
                username: None,
                email: None,
                groups: vec![],
                roles: vec![],
                attributes: HashMap::new(),
                token: None,
                refresh_token: None,
                expires_at: None,
                error: Some("Username required".to_string()),
            }),
        };

        let password = match &request.password {
            Some(p) if !p.is_empty() => p,
            _ => return Ok(AuthResponse {
                success: false,
                user_id: None,
                username: None,
                email: None,
                groups: vec![],
                roles: vec![],
                attributes: HashMap::new(),
                token: None,
                refresh_token: None,
                expires_at: None,
                error: Some("Password required".to_string()),
            }),
        };

        // 1. Connect
        let (conn, mut ldap) = match self.connect().await {
            Ok(c) => c,
            Err(e) => return Ok(AuthResponse {
                success: false,
                user_id: None,
                username: None,
                email: None,
                groups: vec![],
                roles: vec![],
                attributes: HashMap::new(),
                token: None,
                refresh_token: None,
                expires_at: None,
                error: Some(format!("Failed to connect to LDAP: {}", e)),
            }),
        };

        // Spawn connection driver
        ldap3::drive!(conn);

        // 2. Bind (Service Account or Anonymous)
        if let (Some(dn), Some(pw)) = (&self.bind_dn, &self.bind_password) {
            if let Err(e) = ldap.simple_bind(dn, pw).await {
                return Ok(AuthResponse {
                    success: false,
                    user_id: None,
                    username: None,
                    email: None,
                    groups: vec![],
                    roles: vec![],
                    attributes: HashMap::new(),
                    token: None,
                    refresh_token: None,
                    expires_at: None,
                    error: Some(format!("LDAP bind failed (service account): {}", e)),
                });
            }
        } else {
             // Try anonymous bind
             if let Err(e) = ldap.simple_bind("", "").await {
                 tracing::debug!("Anonymous bind failed: {}", e);
             }
        }

        // 3. Search for user
        let escaped_username = escape_ldap_filter_value(username);
        let filter = self.user_search_filter.replace("{}", &escaped_username);

        let attrs = vec!["*", "+"];

        let search_result = match ldap.search(
            &self.base_dn,
            Scope::Subtree,
            &filter,
            attrs
        ).await {
            Ok(res) => res.0,
            Err(e) => return Ok(AuthResponse {
                success: false,
                user_id: None,
                username: None,
                email: None,
                groups: vec![],
                roles: vec![],
                attributes: HashMap::new(),
                token: None,
                refresh_token: None,
                expires_at: None,
                error: Some(format!("LDAP search failed: {}", e)),
            }),
        };

        if search_result.is_empty() {
             return Ok(AuthResponse {
                success: false,
                user_id: None,
                username: None,
                email: None,
                groups: vec![],
                roles: vec![],
                attributes: HashMap::new(),
                token: None,
                refresh_token: None,
                expires_at: None,
                error: Some("User not found".to_string()),
            });
        }

        // Find first entry result (skip referrals for now)
        let mut entry_opt: Option<SearchEntry> = None;
        for res in search_result {
            entry_opt = Some(SearchEntry::construct(res));
            break;
        }

        let entry = match entry_opt {
            Some(e) => e,
            None => return Ok(AuthResponse {
                success: false,
                user_id: None,
                username: None,
                email: None,
                groups: vec![],
                roles: vec![],
                attributes: HashMap::new(),
                token: None,
                refresh_token: None,
                expires_at: None,
                error: Some("User not found (only referrals returned)".to_string()),
            }),
        };

        let user_dn = entry.dn.clone();

        // 4. Authenticate (Bind as User)
        if let Err(e) = ldap.simple_bind(&user_dn, password).await {
             return Ok(AuthResponse {
                success: false,
                user_id: None,
                username: None,
                email: None,
                groups: vec![],
                roles: vec![],
                attributes: HashMap::new(),
                token: None,
                refresh_token: None,
                expires_at: None,
                error: Some(format!("Authentication failed: Invalid credentials ({})", e)),
            });
        }

        // 5. Success - Map attributes
        let user_info = self.map_attributes(&entry);

        Ok(AuthResponse {
            success: true,
            user_id: Some(user_info.id),
            username: user_info.username,
            email: user_info.email,
            groups: user_info.groups,
            roles: user_info.roles,
            attributes: user_info.attributes,
            token: None,
            refresh_token: None,
            expires_at: None,
            error: None,
        })
    }

    async fn get_user_info(&self, _token: &str) -> Result<UserInfo> {
        Err(anyhow!("get_user_info not supported for LDAP provider"))
    }

    async fn validate_token(&self, _token: &str) -> Result<bool> {
        Ok(false)
    }

    async fn logout(&self, _token: &str) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_ldap_filter() {
        assert_eq!(escape_ldap_filter_value("test"), "test");
        assert_eq!(escape_ldap_filter_value("test*user"), "test\\2auser");
        assert_eq!(escape_ldap_filter_value("test(user)"), "test\\28user\\29");
        assert_eq!(escape_ldap_filter_value("test\\user"), "test\\5cuser");
        assert_eq!(escape_ldap_filter_value("test\0user"), "test\\00user");
    }
}
