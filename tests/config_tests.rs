use authenc::AppConfig;
use std::env;

#[test]
fn default_config_sane() {
    let cfg = AppConfig::default();
    assert!(cfg.server.port > 0);
    assert!(cfg.security.password_min_length >= 8);
}

#[test]
fn env_override_port() {
    env::set_var("AUTHENC_PORT", "9090");
    let cfg = AppConfig::from_env().unwrap();
    assert_eq!(cfg.server.port, 9090);
    env::remove_var("AUTHENC_PORT");
}
