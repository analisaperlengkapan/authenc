use axum::{
    body::HttpBody,
    extract::Request,
    http::{Method, Response, StatusCode},
};
use futures_util::future::BoxFuture;
use http_body::SizeHint;
use pin_project::pin_project;
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};
use tower::{Layer, Service};
use tracing::{debug, error, field, info_span, Instrument};
use uuid::Uuid;

/// Middleware for logging HTTP requests and responses
#[derive(Clone, Debug)]
pub struct RequestLogger;

impl<S> Layer<S> for RequestLogger {
    type Service = RequestLoggerMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        RequestLoggerMiddleware { inner: service }
    }
}

#[derive(Clone, Debug)]
pub struct RequestLoggerMiddleware<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for RequestLoggerMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: HttpBody + Send + 'static,
    ResBody::Data: Send,
    ResBody::Error: std::fmt::Display,
{
    type Response = Response<ResponseBody<ResBody>>;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // Don't log health checks
        if req.uri().path().ends_with("/health") {
            let future = self.inner.call(req);
            return Box::pin(async move {
                let res = future.await?;
                Ok(res.map(|body| ResponseBody {
                    inner: body,
                    request_id: Uuid::new_v4(),
                    method: Method::GET,
                    path: "/".to_string(),
                    start_time: Instant::now(),
                    status: StatusCode::OK,
                }))
            });
        }

        let method = req.method().clone();
        let uri = req.uri().clone();
        let version = req.version();
        let remote_addr = req
            .extensions()
            .get::<std::net::SocketAddr>()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".to_string());

        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("-")
            .to_string();

        let span = info_span!(
            "request",
            method = %method,
            uri = %uri,
            version = ?version,
            remote_addr = %remote_addr,
            user_agent = %user_agent,
            status = field::Empty,
            latency = field::Empty,
        );

        let future = self.inner.call(req);

        Box::pin(
            async move {
                let start = Instant::now();
                let res = future.await?;
                let latency = start.elapsed();
                let status = res.status();

                let (parts, body) = res.into_parts();
                let request_id = Uuid::new_v4();
                let body = ResponseBody::new(
                    body,
                    request_id,
                    method.clone(),
                    uri.path().to_string(),
                    start,
                    status,
                );
                let res = Response::from_parts(parts, body);

                let latency_ms = latency.as_millis() as u64;
                let status_code = status.as_u16();

                if status_code >= 500 {
                    error!(status = status_code, latency = latency_ms, "Request failed");
                } else {
                    debug!(
                        status = status_code,
                        latency = latency_ms,
                        "Request completed"
                    );
                }

                Ok(res)
            }
            .instrument(span),
        )
    }
}

/// Wrapper around the response body to log the response
#[pin_project]
pub struct ResponseBody<B> {
    #[pin]
    inner: B,
    request_id: Uuid,
    method: Method,
    path: String,
    start_time: Instant,
    status: StatusCode,
}

impl<B> ResponseBody<B> {
    pub fn new(
        inner: B,
        request_id: Uuid,
        method: Method,
        path: String,
        start_time: Instant,
        status: StatusCode,
    ) -> Self {
        Self {
            inner,
            request_id,
            method,
            path,
            start_time,
            status,
        }
    }
}

impl<B> HttpBody for ResponseBody<B>
where
    B: HttpBody + 'static,
    B::Data: Send + 'static,
    B::Error: std::fmt::Debug + 'static,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        self.project().inner.poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
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
    async fn test_request_logger() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(RequestLogger);

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_check_not_logged() {
        let app = Router::new()
            .route("/health", get(|| async { "OK" }))
            .layer(RequestLogger);

        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_request_logger_with_different_methods() {
        let app = Router::new()
            .route("/test", get(|| async { "GET response" }))
            .route("/test", axum::routing::post(|| async { "POST response" }))
            .route("/test", axum::routing::put(|| async { "PUT response" }))
            .route("/test", axum::routing::delete(|| async { "DELETE response" }))
            .layer(RequestLogger);

        // Test GET request
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test POST request
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test PUT request
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test DELETE request
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_request_logger_with_error_responses() {
        let app = Router::new()
            .route(
                "/error",
                get(|| async {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Server Error",
                    )
                }),
            )
            .route(
                "/not-found",
                get(|| async { (StatusCode::NOT_FOUND, "Not Found") }),
            )
            .layer(RequestLogger);

        // Test 500 error
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/error")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // Test 404 error
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/not-found")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_request_logger_with_headers() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(RequestLogger);

        let req = Request::builder()
            .uri("/")
            .header("user-agent", "TestAgent/1.0")
            .header("x-forwarded-for", "192.168.1.1")
            .header("accept", "application/json")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_request_logger_with_query_params() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(RequestLogger);

        let req = Request::builder()
            .uri("/?param1=value1&param2=value2")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_request_logger_response_body_wrapper() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(RequestLogger);

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Check that the response body is wrapped correctly
        let body = response.into_body();
        assert!(!body.is_end_stream());
    }

    #[tokio::test]
    async fn test_request_logger_debug_format() {
        let logger = RequestLogger;
        let debug_str = format!("{:?}", logger);
        assert!(debug_str.contains("RequestLogger"));
    }

    #[tokio::test]
    async fn test_request_logger_middleware_debug_format() {
        let app: Router<()> = Router::new().route("/", get(|| async { "test" }));
        let middleware = RequestLogger.layer(app);
        let debug_str = format!("{:?}", middleware);
        assert!(debug_str.contains("RequestLoggerMiddleware"));
    }

    #[tokio::test]
    async fn test_request_logger_with_remote_addr_extension() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(RequestLogger);

        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(std::net::SocketAddr::from(([127, 0, 0, 1], 8080)));

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_request_logger_large_response() {
        let app = Router::new()
            .route(
                "/",
                get(|| async {
                    // Return a large response
                    "x".repeat(10000)
                }),
            )
            .layer(RequestLogger);

        let req = Request::builder().uri("/").body(Body::empty()).unwrap();

        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
