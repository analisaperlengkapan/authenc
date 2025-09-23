use authenc::app::AppState;
use authenc::AppConfig;
use authenc::services::stores::user_store::UserStoreTrait;
use std::sync::Arc;

#[tokio::test]
#[ignore = "Requires PostgreSQL database to be running"]
async fn app_state_initializes_all_services() {
    let config = Arc::new(AppConfig::default());
    let state = AppState::new((*config).clone())
        .await
        .expect("AppState::new should succeed");
    assert!(Arc::ptr_eq(&state.config, &config));
    assert!(state.user_store.get_all().await.unwrap().is_empty());
    // Just check all fields are Some/Arc (not None)
    assert!(Arc::strong_count(&state.user_store) > 0);
    assert!(Arc::strong_count(&state.session_store) > 0);
    assert!(Arc::strong_count(&state.totp_store) > 0);
    assert!(Arc::strong_count(&state.brute_force_protector) > 0);
    assert!(Arc::strong_count(&state.anomaly_detector) > 0);
    assert!(Arc::strong_count(&state.federation_registry) > 0);
    assert!(Arc::strong_count(&state.audit_log_store) > 0);
    assert!(Arc::strong_count(&state.realm_store) > 0);
    assert!(Arc::strong_count(&state.role_store) > 0);
    assert!(Arc::strong_count(&state.permission_store) > 0);
}
