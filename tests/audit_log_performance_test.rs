use authenc::services::stores::pg_audit_log_store::PgAuditLogStore;
use authenc::models::audit_log::{AuditLog, AuditLogFilter};
use authenc::services::stores::audit_log_store::AuditLogStore;
use chrono::Utc;
use std::env;

#[tokio::test]
#[ignore] // Requires running Postgres container: docker run -d -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres
async fn test_audit_log_search_performance() {
    let db_url = env::var("TEST_DATABASE_URL");
    if db_url.is_err() {
        println!("Skipping test: TEST_DATABASE_URL not set");
        return;
    }
    let db_url = db_url.unwrap();

    // Create store
    let store = PgAuditLogStore::new(&db_url).await.expect("Failed to create store");

    // Initialize DB (create table)
    let (client, connection) = tokio_postgres::connect(&db_url, tokio_postgres::NoTls).await.expect("Failed to connect");
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    client.execute("DROP TABLE IF EXISTS audit_logs", &[]).await.expect("Failed to drop table");
    client.execute("
        CREATE TABLE audit_logs (
            timestamp TIMESTAMPTZ,
            event TEXT,
            user_id TEXT,
            client_id TEXT,
            status TEXT,
            detail TEXT,
            realm_id UUID
        )
    ", &[]).await.expect("Failed to create table");

    // Insert data
    let mut logs = Vec::new();
    for i in 0..1000 {
        logs.push(AuditLog {
            timestamp: Utc::now(),
            event: format!("event_{}", i),
            user_id: Some(format!("user_{}", i % 10)),
            client_id: Some("client_1".to_string()),
            status: if i % 2 == 0 { "success".to_string() } else { "failure".to_string() },
            detail: None,
        });
    }

    for log in &logs {
        store.add_log(log).await.expect("Failed to add log");
    }

    // Query all logs
    let start = std::time::Instant::now();
    let filter = AuditLogFilter::default();
    let (all_logs, count) = store.query(&filter).await.expect("Failed to get all logs");
    let duration_all = start.elapsed();
    assert_eq!(count, 1000);
    println!("Fetching all 1000 logs took {:?}", duration_all);

    // Filter test
    let filter = AuditLogFilter {
        user_id: Some("user_0".to_string()),
        ..Default::default()
    };
    let (filtered, _) = store.query(&filter).await.expect("Failed to filter");
    // user_0 should appear for indices 0, 10, 20... 990.
    assert_eq!(filtered.len(), 100);

    // Clean up
    client.execute("DROP TABLE IF EXISTS audit_logs", &[]).await.expect("Failed to cleanup table");
}
