use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue, Method, Response},
    middleware::Next,
};
use tower_http::cors::{AllowOrigin, CorsLayer};

/// Create a CORS layer with default configuration
///
/// This function creates a CORS layer that allows cross-origin requests from any origin
/// with common HTTP methods and headers. It's configured for development and testing
/// environments where strict CORS policies are not required.
pub fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::any())
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
            Method::HEAD,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::ACCEPT_ENCODING,
        ])
        .allow_credentials(false)
}

/// Middleware that adds CORS headers to responses
///
/// This middleware adds Cross-Origin Resource Sharing (CORS) headers to HTTP responses
/// to allow web browsers to make cross-origin requests. The headers include:
/// - Access-Control-Allow-Origin: Allows requests from any origin
/// - Access-Control-Allow-Methods: Allows common HTTP methods
/// - Access-Control-Allow-Headers: Allows any headers
/// - Access-Control-Allow-Credentials: Allows credentials in requests
/// - Access-Control-Max-Age: Caches preflight response for 24 hours
pub async fn cors_middleware(request: Request<Body>, next: Next) -> Response<Body> {
    let response = next.run(request).await;

    // Add CORS headers
    let (mut parts, body) = response.into_parts();

    let headers = &mut parts.headers;
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    headers.insert(
        header::ACCESS_CONTROL_MAX_AGE,
        HeaderValue::from_static("86400"), // 24 hours
    );

    Response::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::Request, http::StatusCode, routing::get, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_cors_headers() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(cors_layer());

        // Test preflight request
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/")
                    .header("origin", "https://example.com")
                    .header("access-control-request-method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "*"
        );
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_METHODS)
                .unwrap(),
            "GET,POST,PUT,PATCH,DELETE,OPTIONS,HEAD"
        );
    }
}
