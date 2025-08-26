//! Secreton-based vault provider for Authenc
// Integrates with the custom Rust-based Secreton secret manager

use super::{Secret, Vault};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

pub struct SecretonClient {
    endpoint: String,
    token: String,
    client: Client,
}

impl SecretonClient {
    pub fn new(endpoint: String, token: String) -> Self {
        SecretonClient {
            endpoint,
            token,
            client: Client::new(),
        }
    }

    pub async fn get_secret(&self, key: &str, realm: Option<&str>) -> Option<String> {
        let url = if let Some(realm) = realm {
            format!("{}/v1/secret/data/{}/{}", self.endpoint, realm, key)
        } else {
            format!("{}/v1/secret/data/{}", self.endpoint, key)
        };
        let req = self.client.get(&url).bearer_auth(&self.token);
        let resp = req.send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        #[derive(Deserialize)]
        struct SecretResp {
            data: Option<std::collections::HashMap<String, String>>,
        }
        let secret_resp: SecretResp = resp.json().await.ok()?;
        secret_resp.data?.values().next().cloned()
    }
}

pub struct SecretonVault {
    client: SecretonClient,
}

impl SecretonVault {
    pub fn new(client: SecretonClient) -> Self {
        SecretonVault { client }
    }
}

#[async_trait]
impl Vault for SecretonVault {
    async fn get_secret(&self, key: &str, realm: Option<&str>) -> Option<Secret> {
        if let Some(value) = self.client.get_secret(key, realm).await {
            Some(Secret {
                value,
                metadata: None,
            })
        } else {
            None
        }
    }
}
