use axum::{
    body::Body,
    extract::Request,
    http::{HeaderValue, Response, header},
    middleware::Next,
};

/// Middleware that adds comprehensive security headers to responses
///
/// This middleware adds various security headers to HTTP responses to help protect
/// against common web vulnerabilities such as XSS, clickjacking, content sniffing,
/// and other modern web security threats. The headers include:
/// - Strict-Transport-Security: Enforces HTTPS connections
/// - X-Frame-Options: Prevents clickjacking attacks
/// - X-Content-Type-Options: Prevents MIME type sniffing
/// - X-XSS-Protection: Enables XSS filtering in browsers
/// - Referrer-Policy: Controls referrer information
/// - Permissions-Policy: Restricts browser features and APIs
/// - Cross-Origin-Embedder-Policy: Enables cross-origin isolation
/// - Cross-Origin-Opener-Policy: Protects against certain cross-origin attacks
/// - Cross-Origin-Resource-Policy: Controls cross-origin resource sharing
/// - Cache-Control, Pragma, Expires: Prevents caching of sensitive content
/// - Content-Security-Policy: Restricts resource loading to prevent XSS
pub async fn security_headers_middleware(request: Request, next: Next) -> Response<Body> {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Transport Security
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
    );

    // Clickjacking Protection
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));

    // MIME Type Sniffing Protection
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );

    // XSS Protection
    headers.insert(
        header::X_XSS_PROTECTION,
        HeaderValue::from_static("1; mode=block"),
    );

    // Referrer Policy
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Permissions Policy (formerly Feature Policy)
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), accelerometer=(), gyroscope=(), ambient-light-sensor=(), autoplay=(), encrypted-media=(), fullscreen=(self), picture-in-picture=()"
        ),
    );

    // Cross-Origin Policies
    headers.insert(
        "Cross-Origin-Embedder-Policy",
        HeaderValue::from_static("require-corp"),
    );
    headers.insert(
        "Cross-Origin-Opener-Policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "Cross-Origin-Resource-Policy",
        HeaderValue::from_static("same-origin"),
    );

    // Cache Control for Security
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(
            "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0",
        ),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));

    // Enhanced Content Security Policy
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self' 'unsafe-inline'; \
             style-src 'self' 'unsafe-inline'; \
             img-src 'self' data: https:; \
             font-src 'self' data:; \
             connect-src 'self'; \
             media-src 'none'; \
             object-src 'none'; \
             frame-src 'none'; \
             frame-ancestors 'none'; \
             form-action 'self'; \
             upgrade-insecure-requests; \
             block-all-mixed-content;",
        ),
    );

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::Request,
        http::StatusCode,
        routing::{Router, get},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_security_headers() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(tower_http::trace::TraceLayer::new_for_http())
            .layer(
                tower::ServiceBuilder::new()
                    .layer(tower_http::add_extension::AddExtensionLayer::new(())),
            )
            .layer(
                tower::ServiceBuilder::new()
                    .layer(axum::middleware::from_fn(security_headers_middleware)),
            );

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        assert!(headers.contains_key(header::STRICT_TRANSPORT_SECURITY));
        assert!(headers.contains_key(header::X_FRAME_OPTIONS));
        assert!(headers.contains_key(header::X_CONTENT_TYPE_OPTIONS));
        assert!(headers.contains_key(header::X_XSS_PROTECTION));
        assert!(headers.contains_key(header::CACHE_CONTROL));
        assert!(headers.contains_key(header::PRAGMA));
        assert!(headers.contains_key(header::EXPIRES));
        assert!(headers.contains_key(header::CONTENT_SECURITY_POLICY));
    }

    #[tokio::test]
    async fn test_security_headers_values() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();

        // Check specific header values
        assert_eq!(
            headers.get(header::STRICT_TRANSPORT_SECURITY).unwrap(),
            "max-age=31536000; includeSubDomains; preload"
        );
        assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert_eq!(
            headers.get(header::X_XSS_PROTECTION).unwrap(),
            "1; mode=block"
        );
        assert_eq!(
            headers.get("Referrer-Policy").unwrap(),
            "strict-origin-when-cross-origin"
        );
        assert_eq!(
            headers.get("Cross-Origin-Embedder-Policy").unwrap(),
            "require-corp"
        );
        assert_eq!(
            headers.get("Cross-Origin-Opener-Policy").unwrap(),
            "same-origin"
        );
        assert_eq!(
            headers.get("Cross-Origin-Resource-Policy").unwrap(),
            "same-origin"
        );
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0"
        );
        assert_eq!(headers.get(header::PRAGMA).unwrap(), "no-cache");
        assert_eq!(headers.get(header::EXPIRES).unwrap(), "0");
    }

    #[tokio::test]
    async fn test_security_headers_with_different_response_types() {
        let app = Router::new()
            .route(
                "/json",
                get(|| async { axum::Json(serde_json::json!({"message": "hello"})) }),
            )
            .route("/text", get(|| async { "Plain text response" }))
            .route(
                "/html",
                get(|| async { axum::response::Html("<html><body>Hello</body></html>") }),
            )
            .route(
                "/error",
                get(|| async { (StatusCode::NOT_FOUND, "Not found") }),
            )
            .layer(axum::middleware::from_fn(security_headers_middleware));

        // Test JSON response
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/json").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .contains_key(header::STRICT_TRANSPORT_SECURITY)
        );

        // Test text response
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/text").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(header::X_FRAME_OPTIONS));

        // Test HTML response
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/html").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .contains_key(header::CONTENT_SECURITY_POLICY)
        );

        // Test error response
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/error")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        // Security headers should still be added to error responses
        assert!(
            response
                .headers()
                .contains_key(header::STRICT_TRANSPORT_SECURITY)
        );
    }

    #[tokio::test]
    async fn test_security_headers_permissions_policy() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        let permissions_policy = headers.get("Permissions-Policy").unwrap().to_str().unwrap();

        // Check that all expected permissions are restricted
        assert!(permissions_policy.contains("camera=()"));
        assert!(permissions_policy.contains("microphone=()"));
        assert!(permissions_policy.contains("geolocation=()"));
        assert!(permissions_policy.contains("payment=()"));
        assert!(permissions_policy.contains("usb=()"));
        assert!(permissions_policy.contains("magnetometer=()"));
        assert!(permissions_policy.contains("accelerometer=()"));
        assert!(permissions_policy.contains("gyroscope=()"));
        assert!(permissions_policy.contains("ambient-light-sensor=()"));
        assert!(permissions_policy.contains("autoplay=()"));
        assert!(permissions_policy.contains("encrypted-media=()"));
        assert!(permissions_policy.contains("fullscreen=(self)"));
        assert!(permissions_policy.contains("picture-in-picture=()"));
    }

    #[tokio::test]
    async fn test_security_headers_csp_detailed() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        let csp = headers
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();

        // Check CSP contains expected directives
        assert!(csp.contains("default-src 'self'"));
        assert!(csp.contains("script-src 'self' 'unsafe-inline'"));
        assert!(csp.contains("style-src 'self' 'unsafe-inline'"));
        assert!(csp.contains("img-src 'self' data: https:"));
        assert!(csp.contains("font-src 'self' data:"));
        assert!(csp.contains("connect-src 'self'"));
        assert!(csp.contains("media-src 'none'"));
        assert!(csp.contains("object-src 'none'"));
        assert!(csp.contains("frame-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("form-action 'self'"));
        assert!(csp.contains("upgrade-insecure-requests"));
        assert!(csp.contains("block-all-mixed-content"));
    }

    #[tokio::test]
    async fn test_security_headers_no_duplicates() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();

        // Ensure headers are not duplicated
        assert_eq!(
            headers
                .get_all(header::STRICT_TRANSPORT_SECURITY)
                .iter()
                .count(),
            1
        );
        assert_eq!(headers.get_all(header::X_FRAME_OPTIONS).iter().count(), 1);
        assert_eq!(
            headers
                .get_all(header::X_CONTENT_TYPE_OPTIONS)
                .iter()
                .count(),
            1
        );
        assert_eq!(headers.get_all(header::X_XSS_PROTECTION).iter().count(), 1);
        assert_eq!(headers.get_all(header::CACHE_CONTROL).iter().count(), 1);
        assert_eq!(headers.get_all(header::PRAGMA).iter().count(), 1);
        assert_eq!(headers.get_all(header::EXPIRES).iter().count(), 1);
        assert_eq!(
            headers
                .get_all(header::CONTENT_SECURITY_POLICY)
                .iter()
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn test_security_headers_with_existing_headers() {
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    let mut response =
                        axum::response::Response::new(axum::body::Body::from("Hello"));
                    response.headers_mut().insert(
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("max-age=3600"),
                    );
                    response
                }),
            )
            .layer(axum::middleware::from_fn(security_headers_middleware));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Security headers should override existing headers
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0"
        );
    }
}
