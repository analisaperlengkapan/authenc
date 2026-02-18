use authenc::services::stores::pg_audit_log_store::PgAuditLogStore;

#[tokio::test]
async fn audit_log_store_init_fails_with_invalid_url() {
    let result = PgAuditLogStore::new("invalid://url").await;
    assert!(result.is_err());
}
