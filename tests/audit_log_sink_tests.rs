
#[cfg(test)]
mod tests {
    use authenc::services::audit_log_sink::{AuditLogSink, FileAuditLogSink};
    #[cfg(feature = "reqwest")]
    use authenc::services::audit_log_sink::SplunkAuditLogSink;
    use authenc::models::audit_log::AuditLog;
    use chrono::Utc;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use serde_json::Value;

    // Helper to create a dummy audit log
    fn create_test_log() -> AuditLog {
        AuditLog {
            timestamp: Utc::now(),
            event: "test_event".to_string(),
            user_id: Some("user1".to_string()),
            client_id: Some("client1".to_string()),
            status: "success".to_string(),
            detail: Some("detail".to_string()),
        }
    }

    #[tokio::test]
    async fn test_file_audit_log_sink() {
        let temp_dir = tempfile::tempdir().unwrap();
        let file_path = temp_dir.path().join("audit.log");
        let sink = FileAuditLogSink::new(file_path.clone());

        let log = create_test_log();
        sink.send(&log);

        // Wait for async write to complete
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut file = tokio::fs::File::open(&file_path).await.unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).await.unwrap();

        let logged_json: Value = serde_json::from_str(&content).unwrap();
        assert_eq!(logged_json["event"], "test_event");
        assert_eq!(logged_json["user_id"], "user1");
    }

    #[cfg(feature = "reqwest")]
    #[tokio::test]
    async fn test_splunk_audit_log_sink() {
        use axum::{routing::post, Router, Json};
        use std::sync::{Arc, Mutex};

        let received_payload = Arc::new(Mutex::new(None));
        let received_payload_clone = received_payload.clone();

        // Mock Splunk HEC server
        let app = Router::new().route("/services/collector", post(move |Json(payload): Json<Value>| {
            let received_payload = received_payload_clone.clone();
            async move {
                let mut guard = received_payload.lock().unwrap();
                *guard = Some(payload);
                "ok"
            }
        }));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("http://{}/services/collector", addr);
        let sink = SplunkAuditLogSink::new(url, "token123".to_string());

        let log = create_test_log();
        sink.send(&log);

        // Wait for async request
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let guard = received_payload.lock().unwrap();
            if guard.is_some() {
                break;
            }
        }

        let guard = received_payload.lock().unwrap();
        let payload = guard.as_ref().expect("Did not receive payload in Splunk mock");

        assert_eq!(payload["event"]["event"], "test_event");
        assert_eq!(payload["sourcetype"], "_json");
    }
}
