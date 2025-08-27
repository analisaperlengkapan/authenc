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
}
