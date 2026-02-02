use serde::{Deserialize, Serialize};

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Whether rate limiting is enabled
    pub enabled: bool,
    /// Requests per second allowed
    pub requests_per_second: u32,
    /// Burst size allowed
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            requests_per_second: 10,
            burst_size: 20,
        }
    }
}

/// CSRF protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfConfig {
    /// Whether CSRF protection is enabled
    pub enabled: bool,
    /// Cookie name for CSRF token
    pub cookie_name: String,
    /// Header name for CSRF token
    pub header_name: String,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cookie_name: "XSRF-TOKEN".to_string(),
            header_name: "X-XSRF-TOKEN".to_string(),
        }
    }
}

/// Input validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputValidationConfig {
    /// Whether input validation is enabled
    pub enabled: bool,
    /// Maximum request body size in bytes
    pub max_body_size: usize,
}

impl Default for InputValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_body_size: 1024 * 1024, // 1MB
        }
    }
}

/// Security monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMonitoringConfig {
    /// Whether security monitoring is enabled
    pub enabled: bool,
    /// Alert on suspicious activity
    pub alert_on_suspicious: bool,
}

impl Default for SecurityMonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            alert_on_suspicious: true,
        }
    }
}

/// Enhanced security headers configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
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
                "default-src 'self' 'unsafe-inline' 'unsafe-eval'".to_string(),
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'".to_string(),
                "style-src 'self' 'unsafe-inline'".to_string(),
                "img-src 'self' data: https:".to_string(),
                "font-src 'self' data:".to_string(),
                "connect-src 'self' ws: http: https:".to_string(),
            ],
        }
    }
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self::secure()
    }
}

/// Comprehensive security configuration for the Authenc system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityMiddlewareConfig {
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

impl SecurityMiddlewareConfig {
    /// Create a new security configuration with default secure settings
    pub fn secure_defaults() -> Self {
        Self {
            headers: SecurityHeadersConfig::secure(),
            csrf: CsrfConfig::default(),
            rate_limit: RateLimitConfig::default(),
            input_validation: InputValidationConfig::default(),
            monitoring: SecurityMonitoringConfig::default(),
        }
    }

    /// Create a new security configuration with development-friendly settings
    pub fn development_defaults() -> Self {
        Self {
            headers: SecurityHeadersConfig::development(),
            csrf: CsrfConfig {
                enabled: false, // Disable CSRF in development for easier testing
                ..CsrfConfig::default()
            },
            rate_limit: RateLimitConfig::default(),
            input_validation: InputValidationConfig::default(),
            monitoring: SecurityMonitoringConfig::default(),
        }
    }
}

impl Default for SecurityMiddlewareConfig {
    fn default() -> Self {
        Self::secure_defaults()
    }
}
