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
}
