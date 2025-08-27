//! Common test utilities shared across integration tests.
use authenc::AppConfig;

pub async fn build_test_config() -> AppConfig {
    AppConfig::default()
}
