use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue, Method, Response},
    middleware::Next,
};
use std::time::Duration;
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
            header::ACCESS_CONTROL_REQUEST_METHOD,
            header::ACCESS_CONTROL_REQUEST_HEADERS,
        ])
        .max_age(Duration::from_secs(86400))
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

    #[tokio::test]
    async fn test_cors_middleware_function() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(axum::middleware::from_fn(cors_middleware));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        assert_eq!(
            headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "*"
        );
        assert_eq!(
            headers.get(header::ACCESS_CONTROL_ALLOW_METHODS).unwrap(),
            "GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD"
        );
        assert_eq!(
            headers.get(header::ACCESS_CONTROL_ALLOW_HEADERS).unwrap(),
            "*"
        );
        assert_eq!(
            headers
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .unwrap(),
            "true"
        );
        assert_eq!(
            headers.get(header::ACCESS_CONTROL_MAX_AGE).unwrap(),
            "86400"
        );
    }

    #[tokio::test]
    async fn test_cors_layer_configuration() {
        let layer = cors_layer();

        // Test that the layer allows the expected methods via preflight
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(layer);

        // Test GET preflight
        let response = app
            .clone()
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

        // Test POST preflight
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/")
                    .header("origin", "https://example.com")
                    .header("access-control-request-method", "POST")
                    .header("access-control-request-headers", "content-type")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test PUT preflight
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/")
                    .header("origin", "https://example.com")
                    .header("access-control-request-method", "PUT")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test DELETE preflight
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/")
                    .header("origin", "https://example.com")
                    .header("access-control-request-method", "DELETE")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_cors_with_different_origins() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(cors_layer());

        // Test with different origins
        let origins = vec![
            "https://example.com",
            "http://localhost:3000",
            "https://app.example.com",
            "null", // For local file access
        ];

        for origin in origins {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri("/")
                        .header("origin", origin)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            // Since we allow any origin, the response should have "*" as allow-origin
            assert_eq!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .unwrap(),
                "*"
            );
        }
    }

    #[tokio::test]
    async fn test_cors_preflight_with_custom_headers() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(cors_layer());

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/")
                    .header("origin", "https://example.com")
                    .header("access-control-request-method", "POST")
                    .header(
                        "access-control-request-headers",
                        "content-type,authorization",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let headers = response.headers();
        assert_eq!(
            headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "*"
        );
        assert!(headers.get(header::ACCESS_CONTROL_ALLOW_METHODS).is_some());
        assert!(headers.get(header::ACCESS_CONTROL_ALLOW_HEADERS).is_some());
        assert_eq!(
            headers.get(header::ACCESS_CONTROL_MAX_AGE).unwrap(),
            "86400"
        );
    }

    #[tokio::test]
    async fn test_cors_with_actual_request() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(cors_layer());

        // Make an actual request (not preflight)
        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/")
                    .header("origin", "https://example.com")
                    .header("authorization", "Bearer token123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // CORS headers should still be present on actual requests
        let headers = response.headers();
        assert_eq!(
            headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "*"
        );
        // Credentials are not allowed when origin is "*"
        // assert_eq!(headers.get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS).unwrap(), "true");
    }

    #[tokio::test]
    async fn test_cors_middleware_preserves_response() {
        let app = Router::new()
            .route(
                "/json",
                get(|| async {
                    axum::Json(serde_json::json!({"message": "hello", "status": "success"}))
                }),
            )
            .route(
                "/error",
                get(|| async { (StatusCode::NOT_FOUND, "Not found") }),
            )
            .layer(axum::middleware::from_fn(cors_middleware));

        // Test successful JSON response
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/json").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));

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
        // CORS headers should still be added to error responses
        assert!(response
            .headers()
            .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN));
    }
}
