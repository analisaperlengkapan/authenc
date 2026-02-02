use axum::{
    body::Body,
    extract::Request,
    http::{Response, StatusCode, header},
    middleware::Next,
};
use regex::Regex;
use std::sync::Arc;
use tracing::{debug, warn};

/// Configuration for input validation middleware
#[derive(Clone, Debug, serde::Deserialize)]
pub struct InputValidationConfig {
    /// Whether to enable input validation
    pub enabled: bool,
    /// Maximum length for query parameters
    pub max_query_param_length: usize,
    /// Maximum length for headers
    pub max_header_length: usize,
    /// Maximum request body size in bytes
    pub max_request_body_size: usize,
    /// Whether to block suspicious patterns
    pub block_suspicious_patterns: bool,
    /// Whether to validate content type headers
    pub validate_content_type: bool,
    /// Allowed content types for requests with bodies
    pub allowed_content_types: Vec<String>,
}

impl Default for InputValidationConfig {
    fn default() -> Self {
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
}

/// Middleware that validates input for security issues
pub async fn input_validation_middleware(
    config: Arc<InputValidationConfig>,
    request: Request,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    if !config.enabled {
        return Ok(next.run(request).await);
    }

    // Validate query parameters
    if let Some(query) = request.uri().query() {
        if query.len() > config.max_query_param_length {
            warn!("Query string too long: {} bytes", query.len());
            return Err(StatusCode::BAD_REQUEST);
        }

        if config.block_suspicious_patterns {
            // URL decode the query string before checking for suspicious patterns
            let decoded_query = urlencoding::decode(query)
                .unwrap_or_else(|_| query.into())
                .to_string();
            if contains_suspicious_patterns(&decoded_query) {
                warn!("Suspicious pattern detected in query: {}", query);
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    }

    // Validate headers
    for (name, value) in request.headers() {
        if let Ok(value_str) = value.to_str() {
            if value_str.len() > config.max_header_length {
                warn!("Header {} too long: {} bytes", name, value_str.len());
                return Err(StatusCode::BAD_REQUEST);
            }

            // Check for suspicious patterns in specific headers
            if (name.as_str() == header::USER_AGENT.as_str()
                || name.as_str() == header::REFERER.as_str())
                && config.block_suspicious_patterns
                && contains_suspicious_patterns(value_str)
            {
                warn!(
                    "Suspicious pattern detected in header {}: {}",
                    name, value_str
                );
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    }

    // Validate content type for requests with bodies
    if config.validate_content_type && has_request_body(&request) {
        if let Some(content_type) = request.headers().get("content-type") {
            if let Ok(content_type_str) = content_type.to_str() {
                let is_allowed = config
                    .allowed_content_types
                    .iter()
                    .any(|allowed| content_type_str.starts_with(allowed));

                if !is_allowed {
                    warn!("Invalid content type: {}", content_type_str);
                    return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
                }
            } else {
                warn!("Invalid content type header encoding");
                return Err(StatusCode::BAD_REQUEST);
            }
        } else {
            warn!("Missing content type for request with body");
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    // Check request body size
    if let Some(content_length) = request.headers().get("content-length")
        && let Ok(length_str) = content_length.to_str()
            && let Ok(length) = length_str.parse::<usize>()
                && length > config.max_request_body_size {
                    warn!("Request body too large: {} bytes", length);
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }

    debug!("Input validation passed");
    Ok(next.run(request).await)
}

/// Check if input contains suspicious patterns that might indicate attacks
fn contains_suspicious_patterns(input: &str) -> bool {
    // Common SQL injection patterns
    let sql_patterns = [
        r"(?i)(union\s+select)",
        r"(?i)(select\s+.*\s+from)",
        r"(?i)(drop\s+table)",
        r"(?i)(--\s*|\#)",
        r"(?i)(;\s*(drop|delete|update|insert))",
    ];

    // XSS patterns
    let xss_patterns = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"vbscript:",
        r"onload\s*=",
        r"onerror\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
    ];

    // Path traversal patterns
    let path_patterns = [r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"%2e%2e%5c"];

    let all_patterns = sql_patterns
        .iter()
        .chain(xss_patterns.iter())
        .chain(path_patterns.iter());

    for pattern in all_patterns {
        if let Ok(regex) = Regex::new(pattern)
            && regex.is_match(input) {
                return true;
            }
    }

    false
}

/// Check if the request method typically has a body
fn has_request_body(request: &Request) -> bool {
    matches!(
        request.method(),
        &axum::http::Method::POST | &axum::http::Method::PUT | &axum::http::Method::PATCH
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_input_validation() {
        let config = Arc::new(InputValidationConfig::default());

        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                input_validation_middleware(config.clone(), req, next)
            }));

        // Test normal request
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test request with suspicious SQL pattern
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/?param=1%27%20UNION%20SELECT%20%2A%20FROM%20users--")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Test request with XSS pattern
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/?param=%3Cscript%3Ealert%28%27xss%27%29%3C%2Fscript%3E")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_suspicious_patterns() {
        assert!(contains_suspicious_patterns("SELECT * FROM users"));
        assert!(contains_suspicious_patterns(
            "<script>alert('xss')</script>"
        ));
        assert!(contains_suspicious_patterns("../../../etc/passwd"));
        assert!(!contains_suspicious_patterns("normal text"));
    }

    #[tokio::test]
    async fn test_input_validation_disabled() {
        let config = Arc::new(InputValidationConfig {
            enabled: false,
            ..Default::default()
        });

        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                input_validation_middleware(config.clone(), req, next)
            }));

        // Even suspicious requests should pass when disabled
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/?param=1%27%20UNION%20SELECT%20%2A%20FROM%20users--")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_query_param_length_limit() {
        let config = Arc::new(InputValidationConfig {
            max_query_param_length: 10,
            ..Default::default()
        });

        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                input_validation_middleware(config.clone(), req, next)
            }));

        // Query string exceeding limit should be rejected
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/?param=verylongparameterthatshouldfail")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_header_length_limit() {
        let config = Arc::new(InputValidationConfig {
            max_header_length: 10,
            ..Default::default()
        });

        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                input_validation_middleware(config.clone(), req, next)
            }));

        // Header exceeding limit should be rejected
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("user-agent", "verylonguseragentstringthatshouldfail")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_content_type_validation() {
        let config = Arc::new(InputValidationConfig::default());

        let app = Router::new()
            .route("/", axum::routing::post(|| async { "Hello, world!" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                input_validation_middleware(config.clone(), req, next)
            }));

        // Missing content type should be rejected
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Invalid content type should be rejected
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "text/html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

        // Valid content type should be accepted
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_request_body_size_limit() {
        let config = Arc::new(InputValidationConfig {
            max_request_body_size: 100,
            ..Default::default()
        });

        let app = Router::new()
            .route("/", axum::routing::post(|| async { "Hello, world!" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                input_validation_middleware(config.clone(), req, next)
            }));

        // Request body exceeding limit should be rejected
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("content-type", "application/json")
                    .header("content-length", "200")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_suspicious_patterns_in_headers() {
        let config = Arc::new(InputValidationConfig::default());

        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                input_validation_middleware(config.clone(), req, next)
            }));

        // Suspicious pattern in User-Agent should be rejected
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("user-agent", "malicious<script>alert('xss')</script>")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Suspicious pattern in Referer should be rejected
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("referer", "http://evil.com'; DROP TABLE users--")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_content_type_validation_disabled() {
        let config = Arc::new(InputValidationConfig {
            validate_content_type: false,
            ..Default::default()
        });

        let app = Router::new()
            .route("/", axum::routing::post(|| async { "Hello, world!" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                input_validation_middleware(config.clone(), req, next)
            }));

        // Request without content type should be accepted when validation disabled
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_suspicious_patterns_disabled() {
        let config = Arc::new(InputValidationConfig {
            block_suspicious_patterns: false,
            ..Default::default()
        });

        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(axum::middleware::from_fn(move |req, next| {
                input_validation_middleware(config.clone(), req, next)
            }));

        // Suspicious patterns should be allowed when blocking disabled
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/?param=1%27%20UNION%20SELECT%20%2A%20FROM%20users--")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_has_request_body() {
        let get_request = Request::builder()
            .method("GET")
            .uri("/")
            .body(Body::empty())
            .unwrap();
        assert!(!has_request_body(&get_request));

        let post_request = Request::builder()
            .method("POST")
            .uri("/")
            .body(Body::empty())
            .unwrap();
        assert!(has_request_body(&post_request));

        let put_request = Request::builder()
            .method("PUT")
            .uri("/")
            .body(Body::empty())
            .unwrap();
        assert!(has_request_body(&put_request));

        let patch_request = Request::builder()
            .method("PATCH")
            .uri("/")
            .body(Body::empty())
            .unwrap();
        assert!(has_request_body(&patch_request));

        let delete_request = Request::builder()
            .method("DELETE")
            .uri("/")
            .body(Body::empty())
            .unwrap();
        assert!(!has_request_body(&delete_request));
    }

    #[test]
    fn test_input_validation_config_defaults() {
        let config = InputValidationConfig::default();

        assert!(config.enabled);
        assert_eq!(config.max_query_param_length, 2048);
        assert_eq!(config.max_header_length, 4096);
        assert_eq!(config.max_request_body_size, 1024 * 1024);
        assert!(config.block_suspicious_patterns);
        assert!(config.validate_content_type);
        assert!(
            config
                .allowed_content_types
                .contains(&"application/json".to_string())
        );
        assert!(
            config
                .allowed_content_types
                .contains(&"text/plain".to_string())
        );
    }

    #[test]
    fn test_suspicious_patterns_comprehensive() {
        // SQL injection patterns
        assert!(contains_suspicious_patterns(
            "UNION SELECT password FROM users"
        ));
        assert!(contains_suspicious_patterns("DROP TABLE users"));
        assert!(contains_suspicious_patterns(
            "SELECT * FROM admin; DROP TABLE users"
        ));
        assert!(contains_suspicious_patterns("SELECT * FROM users--"));
        assert!(contains_suspicious_patterns("SELECT * FROM users #"));

        // XSS patterns
        assert!(contains_suspicious_patterns(
            "<script src='evil.js'></script>"
        ));
        assert!(contains_suspicious_patterns("javascript:alert('xss')"));
        assert!(contains_suspicious_patterns("vbscript:msgbox('xss')"));
        assert!(contains_suspicious_patterns("<img onload=alert('xss')>"));
        assert!(contains_suspicious_patterns("<img onerror=alert('xss')>"));
        assert!(contains_suspicious_patterns(
            "<iframe src='evil.com'></iframe>"
        ));
        assert!(contains_suspicious_patterns(
            "<object data='evil.swf'></object>"
        ));

        // Path traversal patterns
        assert!(contains_suspicious_patterns("../../../etc/passwd"));
        assert!(contains_suspicious_patterns(
            "..\\..\\..\\windows\\system32"
        ));
        assert!(contains_suspicious_patterns(
            "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ));
        assert!(contains_suspicious_patterns(
            "%2e%2e%5c%2e%2e%5cwindows%5csystem32"
        ));

        // Safe patterns
        assert!(!contains_suspicious_patterns("normal query parameter"));
        assert!(!contains_suspicious_patterns("user input with spaces"));
        assert!(!contains_suspicious_patterns("email@domain.com"));
        assert!(!contains_suspicious_patterns("https://example.com/path"));
    }
}
