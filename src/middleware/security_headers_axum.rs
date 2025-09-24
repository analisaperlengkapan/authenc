use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue, Response},
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
        HeaderValue::from_static("no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0"),
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
        routing::{get, Router},
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
}
