use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue, Response},
    middleware::Next,
};

/// Middleware that adds security headers to responses
pub async fn security_headers_middleware(request: Request, next: Next) -> Response<Body> {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Security Headers
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_XSS_PROTECTION,
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, proxy-revalidate"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));

    // Content Security Policy
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; \
             script-src 'self'; \
             style-src 'self'; \
             img-src 'self' data:; \
             font-src 'self' data:; \
             connect-src 'self';",
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
