use crate::models::audit_log::AuditLog;
use crate::services::audit::AuditLogSink;
use reqwest::Client;
use serde_json::json;

/// Elasticsearch audit log sink for SIEM integration
pub struct ElasticsearchAuditLogSink {
    /// HTTP client for sending requests to Elasticsearch
    client: Client,
    /// Elasticsearch endpoint URL
    endpoint: String,
    /// Index name for audit logs
    index: String,
    /// Optional authentication credentials
    auth: Option<(String, String)>,
}

impl ElasticsearchAuditLogSink {
    /// Create new Elasticsearch audit log sink
    ///
    /// # Arguments
    /// * `endpoint` - Elasticsearch endpoint URL (e.g., "http://localhost:9200")
    /// * `index` - Index name for audit logs (e.g., "authenc-audit-logs")
    /// * `username` - Optional username for basic auth
    /// * `password` - Optional password for basic auth
    pub fn new(
        endpoint: &str,
        index: &str,
        username: Option<&str>,
        password: Option<&str>,
    ) -> Self {
        let client = Client::new();
        let auth = match (username, password) {
            (Some(u), Some(p)) => Some((u.to_string(), p.to_string())),
            _ => None,
        };

        Self {
            client,
            endpoint: endpoint.trim_end_matches('/').to_string(),
            index: index.to_string(),
            auth,
        }
    }

    /// Create audit logs index with proper mappings if it doesn't exist
    pub async fn ensure_index(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let index_url = format!("{}/{}", self.endpoint, self.index);

        // Check if index exists
        let response = self.client.head(&index_url).send().await?;

        if response.status().as_u16() == 404 {
            // Create index with mappings
            let mapping = json!({
                "mappings": {
                    "properties": {
                        "timestamp": {
                            "type": "date",
                            "format": "strict_date_optional_time"
                        },
                        "event": {
                            "type": "text"
                        },
                        "user_id": {
                            "type": "keyword"
                        },
                        "client_id": {
                            "type": "keyword"
                        },
                        "status": {
                            "type": "keyword"
                        },
                        "detail": {
                            "type": "text"
                        }
                    }
                },
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1
                }
            });

            let mut request = self.client.put(&index_url).json(&mapping);

            if let Some((ref username, ref password)) = self.auth {
                request = request.basic_auth(username, Some(password));
            }

            let response = request.send().await?;
            if !response.status().is_success() {
                let error_text = response.text().await?;
                return Err(format!("Failed to create Elasticsearch index: {}", error_text).into());
            }
        }

        Ok(())
    }
}

impl AuditLogSink for ElasticsearchAuditLogSink {
    /// Send audit log to Elasticsearch
    ///
    /// # Arguments
    /// * `log` - The audit log entry to send
    fn send(&self, log: &AuditLog) {
        let client = self.client.clone();
        let endpoint = self.endpoint.clone();
        let index = self.index.clone();
        let auth = self.auth.clone();
        let log = log.clone();

        tokio::spawn(async move {
            let document_url = format!("{}/{}/_doc", endpoint, index);

            let document = json!({
                "timestamp": log.timestamp.to_rfc3339(),
                "event": log.event,
                "user_id": log.user_id,
                "client_id": log.client_id,
                "status": log.status,
                "detail": log.detail
            });

            let mut request = client.post(&document_url).json(&document);

            if let Some((ref username, ref password)) = auth {
                request = request.basic_auth(username, Some(password));
            }

            match request.send().await {
                Ok(response) => {
                    if !response.status().is_success() {
                        eprintln!(
                            "Failed to send audit log to Elasticsearch: HTTP {}",
                            response.status()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Failed to send audit log to Elasticsearch: {}", e);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::audit_log::AuditLog;

    #[tokio::test]
    async fn test_elasticsearch_sink_creation() {
        let sink = ElasticsearchAuditLogSink::new(
            "http://localhost:9200",
            "test-audit-logs",
            Some("elastic"),
            Some("password"),
        );

        assert_eq!(sink.endpoint, "http://localhost:9200");
        assert_eq!(sink.index, "test-audit-logs");
        assert_eq!(
            sink.auth,
            Some(("elastic".to_string(), "password".to_string()))
        );
    }

    #[tokio::test]
    async fn test_elasticsearch_sink_no_auth() {
        let sink =
            ElasticsearchAuditLogSink::new("http://localhost:9200", "test-audit-logs", None, None);

        assert_eq!(sink.endpoint, "http://localhost:9200");
        assert_eq!(sink.index, "test-audit-logs");
        assert_eq!(sink.auth, None);
    }

    #[test]
    fn test_audit_log_serialization() {
        let log = AuditLog {
            timestamp: chrono::Utc::now(),
            event: "User login".to_string(),
            user_id: Some("user123".to_string()),
            client_id: Some("client123".to_string()),
            status: "success".to_string(),
            detail: Some("Login successful".to_string()),
        };

        let json = serde_json::to_string(&log).unwrap();
        assert!(json.contains("user123"));
        assert!(json.contains("User login"));
        assert!(json.contains("success"));
    }
}
