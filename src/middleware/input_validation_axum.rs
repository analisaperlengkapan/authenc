use axum::{
    body::Body,
    extract::Request,
    http::{header, Response, StatusCode},
    middleware::Next,
};
use regex::Regex;
use std::sync::Arc;
use tracing::{debug, warn};

/// Configuration for input validation middleware
#[derive(Clone, Debug)]
pub struct InputValidationConfig {
    /// Whether to enable input validation
    pub enabled: bool,
    /// Maximum length for query parameters
    pub max_query_param_length: usize,
    /// Maximum length for headers
    pub max_header_length: usize,
    /// Whether to block suspicious patterns
    pub block_suspicious_patterns: bool,
}

impl Default for InputValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_query_param_length: 2048,
            max_header_length: 4096,
            block_suspicious_patterns: true,
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
            let decoded_query = urlencoding::decode(query).unwrap_or_else(|_| query.into()).to_string();
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
            if (name.as_str() == header::USER_AGENT.as_str() || name.as_str() == header::REFERER.as_str())
                && config.block_suspicious_patterns && contains_suspicious_patterns(value_str) {
                    warn!("Suspicious pattern detected in header {}: {}", name, value_str);
                    return Err(StatusCode::BAD_REQUEST);
                }
        }
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
    let path_patterns = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e%5c",
    ];

    let all_patterns = sql_patterns
        .iter()
        .chain(xss_patterns.iter())
        .chain(path_patterns.iter());

    for pattern in all_patterns {
        if let Ok(regex) = Regex::new(pattern) {
            if regex.is_match(input) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
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
        assert!(contains_suspicious_patterns("<script>alert('xss')</script>"));
        assert!(contains_suspicious_patterns("../../../etc/passwd"));
        assert!(!contains_suspicious_patterns("normal text"));
    }
}
