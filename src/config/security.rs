//! Security Configuration Module
//!
//! This module provides a centralized configuration system for all security-related
//! middleware and features in the Authenc system. It allows for easy configuration
//! and management of security settings across the application.

use std::sync::Arc;

use crate::middleware::*;
use crate::services::pg_audit_log_store::PgAuditLogStore;

/// Comprehensive security configuration for the Authenc system
#[derive(Clone, Debug)]
pub struct SecurityConfig {
    /// Security headers configuration
    pub headers: SecurityHeadersConfig,
    /// CSRF protection configuration
    pub csrf: CsrfConfig,
    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,
    /// Input validation configuration
    pub input_validation: InputValidationConfig,
    /// Security monitoring configuration
    pub monitoring: SecurityMonitoringConfig,
}

impl SecurityConfig {
    /// Create a new security configuration with default secure settings
    pub fn secure_defaults() -> Self {
        Self {
            headers: SecurityHeadersConfig::secure(),
            csrf: CsrfConfig::secure(),
            rate_limit: RateLimitConfig::secure(),
            input_validation: InputValidationConfig::secure(),
            monitoring: SecurityMonitoringConfig::secure(),
        }
    }

    /// Create a new security configuration with development-friendly settings
    pub fn development_defaults() -> Self {
        Self {
            headers: SecurityHeadersConfig::development(),
            csrf: CsrfConfig {
                enabled: false, // Disable CSRF in development for easier testing
                ..CsrfConfig::secure()
            },
            rate_limit: RateLimitConfig::development(),
            input_validation: InputValidationConfig::development(),
            monitoring: SecurityMonitoringConfig::development(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self::secure_defaults()
    }
}

/// Enhanced security headers configuration
#[derive(Clone, Debug)]
pub struct SecurityHeadersConfig {
    /// Whether to enable enhanced security headers
    pub enabled: bool,
    /// HSTS max age in seconds
    pub hsts_max_age: u32,
    /// Whether to include subdomains in HSTS
    pub hsts_include_subdomains: bool,
    /// Whether to enable HSTS preload
    pub hsts_preload: bool,
    /// Content Security Policy directives
    pub csp_directives: Vec<String>,
}

impl SecurityHeadersConfig {
    /// Secure defaults for production
    pub fn secure() -> Self {
        Self {
            enabled: true,
            hsts_max_age: 31536000, // 1 year
            hsts_include_subdomains: true,
            hsts_preload: true,
            csp_directives: vec![
                "default-src 'self'".to_string(),
                "script-src 'self' 'unsafe-inline'".to_string(),
                "style-src 'self' 'unsafe-inline'".to_string(),
                "img-src 'self' data: https:".to_string(),
                "font-src 'self' data:".to_string(),
                "connect-src 'self'".to_string(),
                "media-src 'none'".to_string(),
                "object-src 'none'".to_string(),
                "frame-src 'none'".to_string(),
                "frame-ancestors 'none'".to_string(),
                "form-action 'self'".to_string(),
                "upgrade-insecure-requests".to_string(),
                "block-all-mixed-content".to_string(),
            ],
        }
    }

    /// Development-friendly settings
    pub fn development() -> Self {
        Self {
            enabled: true,
            hsts_max_age: 0, // Disable HSTS in development
            hsts_include_subdomains: false,
            hsts_preload: false,
            csp_directives: vec![
                "default-src 'self' 'unsafe-eval' 'unsafe-inline'".to_string(),
                "script-src 'self' 'unsafe-eval' 'unsafe-inline'".to_string(),
                "style-src 'self' 'unsafe-inline'".to_string(),
                "img-src 'self' data: https: http:".to_string(),
                "font-src 'self' data:".to_string(),
                "connect-src 'self' ws: http:".to_string(),
            ],
        }
    }
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self::secure()
    }
}

/// Enhanced CSRF configuration
impl CsrfConfig {
    /// Secure defaults for production
    pub fn secure() -> Self {
        Self {
            enabled: true,
            header_name: "X-CSRF-Token".to_string(),
            cookie_name: "csrf_token".to_string(),
            token_length: 32,
            excluded_paths: vec![
                "/health".to_string(),
                "/health/ready".to_string(),
                "/health/live".to_string(),
                "/metrics".to_string(),
                "/api/docs".to_string(),
            ],
        }
    }
}

/// Enhanced rate limiting configuration
impl RateLimitConfig {
    /// Secure defaults for production
    pub fn secure() -> Self {
        Self {
            requests_per_minute: 60,
            excluded_paths: vec![
                "/health".to_string(),
                "/health/ready".to_string(),
                "/health/live".to_string(),
                "/metrics".to_string(),
                "/favicon.ico".to_string(),
            ],
            enabled: true,
            progressive_delays: true,
            base_delay_ms: 1000,
            max_delay_ms: 30000, // 30 seconds max delay
        }
    }

    /// Development-friendly settings
    pub fn development() -> Self {
        Self {
            requests_per_minute: 1000, // Much higher limit for development
            enabled: true,
            progressive_delays: false, // Disable delays in development
            ..Self::secure()
        }
    }
}

/// Enhanced input validation configuration
impl InputValidationConfig {
    /// Secure defaults for production
    pub fn secure() -> Self {
        Self {
            enabled: true,
            max_query_param_length: 2048,
            max_header_length: 4096,
            max_request_body_size: 1024 * 1024, // 1MB
            block_suspicious_patterns: true,
            validate_content_type: true,
            allowed_content_types: vec![
                "application/json".to_string(),
                "application/x-www-form-urlencoded".to_string(),
                "multipart/form-data".to_string(),
                "text/plain".to_string(),
            ],
        }
    }

    /// Development-friendly settings
    pub fn development() -> Self {
        Self {
            max_request_body_size: 10 * 1024 * 1024, // 10MB for development
            validate_content_type: false, // More permissive in development
            ..Self::secure()
        }
    }
}

/// Enhanced security monitoring configuration
impl SecurityMonitoringConfig {
    /// Secure defaults for production
    pub fn secure() -> Self {
        Self {
            enabled: true,
            suspicious_threshold_rpm: 100,
            monitored_paths: vec![
                "/auth/login".to_string(),
                "/auth/register".to_string(),
                "/auth/logout".to_string(),
                "/account".to_string(),
                "/admin".to_string(),
                "/api".to_string(),
            ],
            log_auth_attempts: true,
            log_authz_failures: true,
        }
    }

    /// Development-friendly settings
    pub fn development() -> Self {
        Self {
            enabled: true,
            log_auth_attempts: false, // Less logging in development
            log_authz_failures: true,
            ..Self::secure()
        }
    }
}

/// Security middleware stack builder
pub struct SecurityMiddlewareStack {
    config: SecurityConfig,
    audit_store: Option<Arc<PgAuditLogStore>>,
}

impl SecurityMiddlewareStack {
    /// Create a new security middleware stack
    pub fn new(
        config: SecurityConfig,
        audit_store: Option<Arc<PgAuditLogStore>>,
    ) -> Self {
        Self { config, audit_store }
    }

    /// Build the complete security middleware stack
    pub fn build(&self) -> Vec<SecurityMiddleware> {
        let mut stack = Vec::new();

        // Security monitoring (should be first to capture all requests)
        if self.config.monitoring.enabled {
            stack.push(SecurityMiddleware::SecurityMonitoring {
                state: Arc::new(SecurityMonitoringState::new(
                    self.config.monitoring.clone(),
                    self.audit_store.clone(),
                )),
            });
        }

        // Input validation
        if self.config.input_validation.enabled {
            stack.push(SecurityMiddleware::InputValidation {
                config: Arc::new(self.config.input_validation.clone()),
            });
        }

        // Rate limiting
        if self.config.rate_limit.enabled {
            stack.push(SecurityMiddleware::RateLimiting {
                state: Arc::new(RateLimiterState::new(self.config.rate_limit.clone())),
            });
        }

        // CSRF protection
        if self.config.csrf.enabled {
            stack.push(SecurityMiddleware::CsrfProtection {
                state: Arc::new(CsrfState::new(self.config.csrf.clone())),
            });
        }

        // Security headers (should be last to add headers to all responses)
        if self.config.headers.enabled {
            stack.push(SecurityMiddleware::SecurityHeaders);
        }

        stack
    }
}

/// Enum representing different security middleware types
pub enum SecurityMiddleware {
    SecurityMonitoring {
        state: Arc<SecurityMonitoringState>,
    },
    InputValidation {
        config: Arc<InputValidationConfig>,
    },
    RateLimiting {
        state: Arc<RateLimiterState>,
    },
    CsrfProtection {
        state: Arc<CsrfState>,
    },
    SecurityHeaders,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_defaults() {
        let config = SecurityConfig::secure_defaults();
        assert!(config.headers.enabled);
        assert!(config.csrf.enabled);
        assert!(config.rate_limit.enabled);
        assert!(config.input_validation.enabled);
        assert!(config.monitoring.enabled);
    }

    #[test]
    fn test_development_defaults() {
        let config = SecurityConfig::development_defaults();
        assert!(config.headers.enabled);
        assert!(!config.csrf.enabled); // Disabled in development
        assert!(config.rate_limit.enabled);
        assert!(config.input_validation.enabled);
        assert!(config.monitoring.enabled);
    }

    #[test]
    fn test_security_middleware_stack() {
        let config = SecurityConfig::secure_defaults();
        let stack = SecurityMiddlewareStack::new(config, None);
        let middleware = stack.build();

        // Should have 5 middleware components in secure mode
        assert_eq!(middleware.len(), 5);

        match &middleware[0] {
            SecurityMiddleware::SecurityMonitoring { .. } => {}
            _ => panic!("First middleware should be security monitoring"),
        }

        match &middleware[4] {
            SecurityMiddleware::SecurityHeaders => {}
            _ => panic!("Last middleware should be security headers"),
        }
    }
}
