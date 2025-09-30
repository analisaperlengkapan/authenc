use axum::{
    body::Body,
    extract::Request,
    http::{Response, StatusCode},
    middleware::Next,
};
use std::time::Duration;
use tokio::time::timeout;
use tracing::warn;

/// Default timeout duration (30 seconds)
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Middleware that adds a timeout to requests
pub async fn timeout_middleware(request: Request, next: Next) -> Response<Body> {
    // Get the timeout from the request extensions or use the default
    let timeout_duration = request
        .extensions()
        .get::<Duration>()
        .copied()
        .unwrap_or(DEFAULT_TIMEOUT);

    // Apply the timeout
    match timeout(timeout_duration, next.run(request)).await {
        Ok(response) => response,
        Err(_) => {
            // Timeout occurred
            Response::builder()
                .status(StatusCode::REQUEST_TIMEOUT)
                .body(Body::from("Request timed out"))
                .unwrap()
        }
    }
}

/// Layer that adds a timeout to requests
#[derive(Clone, Debug)]
pub struct TimeoutLayer {
    timeout: Duration,
}

impl TimeoutLayer {
    /// Create a new timeout layer with the given duration
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

impl<S> tower::Layer<S> for TimeoutLayer {
    type Service = TimeoutMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TimeoutMiddleware {
            inner,
            timeout: self.timeout,
        }
    }
}

/// Middleware that adds a timeout to requests
#[derive(Clone, Debug)]
pub struct TimeoutMiddleware<S> {
    inner: S,
    timeout: Duration,
}

impl<S, ReqBody> tower::Service<Request<ReqBody>> for TimeoutMiddleware<S>
where
    S: tower::Service<Request<ReqBody>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
        // Clone the inner service and timeout
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let timeout_duration = self.timeout;

        // Insert the timeout into the request extensions
        request.extensions_mut().insert(timeout_duration);

        Box::pin(async move {
            let future = inner.call(request);
            match tokio::time::timeout(timeout_duration, future).await {
                Ok(result) => result,
                Err(_) => {
                    warn!(
                        "Request timed out after {} seconds",
                        timeout_duration.as_secs()
                    );
                    Ok(Response::builder()
                        .status(StatusCode::REQUEST_TIMEOUT)
                        .body(Body::from("Request timed out"))
                        .unwrap())
                }
            }
        })
    }
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
    use std::time::Duration;
    use tokio::time::sleep;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_timeout_middleware() {
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    // Sleep for longer than the timeout
                    sleep(Duration::from_secs(2)).await;
                    "Hello, world!"
                }),
            )
            .layer(TimeoutLayer::new(Duration::from_millis(100)));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn test_timeout_not_triggered() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(TimeoutLayer::new(Duration::from_secs(1)));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_timeout_with_different_durations() {
        // Test with very short timeout
        let app = Router::new()
            .route(
                "/short",
                get(|| async {
                    sleep(Duration::from_millis(200)).await;
                    "Should timeout"
                }),
            )
            .layer(TimeoutLayer::new(Duration::from_millis(50)));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/short")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);

        // Test with longer timeout
        let app = Router::new()
            .route(
                "/long",
                get(|| async {
                    sleep(Duration::from_millis(50)).await;
                    "Should succeed"
                }),
            )
            .layer(TimeoutLayer::new(Duration::from_millis(200)));

        let response = app
            .oneshot(Request::builder().uri("/long").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_timeout_middleware_function() {
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    sleep(Duration::from_millis(200)).await;
                    "Should timeout"
                }),
            )
            .layer(axum::middleware::from_fn(timeout_middleware));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        // Should use default timeout (30 seconds), so this should succeed
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_timeout_with_custom_extension() {
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    sleep(Duration::from_millis(200)).await;
                    "Should timeout"
                }),
            )
            .layer(axum::middleware::from_fn(
                |mut req: Request, next: Next| async move {
                    // Set a very short timeout via extension
                    req.extensions_mut().insert(Duration::from_millis(50));
                    timeout_middleware(req, next).await
                },
            ));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn test_timeout_response_body() {
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    sleep(Duration::from_millis(200)).await;
                    "Should timeout"
                }),
            )
            .layer(TimeoutLayer::new(Duration::from_millis(50)));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);

        // Check that the response body contains the timeout message
        let body = response.into_body();
        let bytes = http_body_util::BodyExt::collect(body)
            .await
            .unwrap()
            .to_bytes();
        let body_str = String::from_utf8(bytes.to_vec()).unwrap();
        assert_eq!(body_str, "Request timed out");
    }

    #[tokio::test]
    async fn test_timeout_layer_creation() {
        let layer = TimeoutLayer::new(Duration::from_secs(10));
        assert_eq!(layer.timeout, Duration::from_secs(10));
    }

    #[tokio::test]
    async fn test_timeout_middleware_debug() {
        let layer = TimeoutLayer::new(Duration::from_secs(5));
        let debug_str = format!("{:?}", layer);
        assert!(debug_str.contains("TimeoutLayer"));
        assert!(debug_str.contains("5s"));
    }

    #[tokio::test]
    async fn test_timeout_boundary_condition() {
        // Test timeout that occurs exactly at the boundary
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    sleep(Duration::from_millis(100)).await;
                    "Completed just in time"
                }),
            )
            .layer(TimeoutLayer::new(Duration::from_millis(150)));

        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        // Should succeed since sleep is shorter than timeout
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_multiple_requests_with_timeout() {
        let app = Router::new()
            .route("/fast", get(|| async { "Fast response" }))
            .route(
                "/slow",
                get(|| async {
                    sleep(Duration::from_millis(200)).await;
                    "Slow response"
                }),
            )
            .layer(TimeoutLayer::new(Duration::from_millis(50)));

        // Fast request should succeed
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/fast").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Slow request should timeout
        let response = app
            .oneshot(Request::builder().uri("/slow").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
    }
}
