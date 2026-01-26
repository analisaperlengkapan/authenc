use authenc::services::pg_audit_log_store::PgAuditLogStore;
use authenc::models::audit_log::{AuditLog, AuditLogFilter, Pagination};
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

    // Benchmark ALL (via search with no params)
    let start = std::time::Instant::now();
    let all_logs = store.search(None, None).await.expect("Failed to get all logs");
    let duration_all = start.elapsed();
    assert_eq!(all_logs.len(), 1000);
    println!("Fetching all 1000 logs took {:?}", duration_all);

    // Benchmark Page (limit 50)
    let start = std::time::Instant::now();
    let page = store.search(None, Some(Pagination { limit: 50, offset: 0 })).await.expect("Failed to get page");
    let duration_page = start.elapsed();
    assert_eq!(page.len(), 50);
    println!("Fetching 50 logs took {:?}", duration_page);

    // Filter test
    let filter = AuditLogFilter {
        user_id: Some("user_0".to_string()),
        ..Default::default()
    };
    let filtered = store.search(Some(filter), None).await.expect("Failed to filter");
    // user_0 should appear for indices 0, 10, 20... 990.
    // Total 100 times.
    assert_eq!(filtered.len(), 100);

    // Filter + Pagination
    let filter = AuditLogFilter {
        user_id: Some("user_0".to_string()),
        ..Default::default()
    };
    let page_filtered = store.search(Some(filter), Some(Pagination { limit: 10, offset: 0 })).await.expect("Failed to filter page");
    assert_eq!(page_filtered.len(), 10);

    // Clean up
    client.execute("DROP TABLE IF EXISTS audit_logs", &[]).await.expect("Failed to cleanup table");
}
