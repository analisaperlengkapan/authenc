//! Axum-specific rate limiting middleware

use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use tower::Service;
use tracing::{debug, error, warn};

use crate::error::AuthencError;

/// Configuration for rate limiting
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum number of requests allowed per minute
    pub requests_per_minute: u64,
    /// Path patterns to exclude from rate limiting
    pub excluded_paths: Vec<String>,
    /// Whether to enable rate limiting (default: true)
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60, // 1 request per second by default
            excluded_paths: vec![
                "/health".to_string(),
                "/health/ready".to_string(),
                "/health/live".to_string(),
                "/metrics".to_string(),
            ],
            enabled: true,
        }
    }
}

/// Rate limiter state
#[derive(Clone)]
pub struct RateLimiterState {
    config: RateLimitConfig,
    // Using DashMap for concurrent access
    counters: Arc<DashMap<String, (AtomicU64, Instant)>>,
}

impl RateLimiterState {
    /// Create a new rate limiter state with the given configuration
    ///
    /// # Arguments
    /// * `config` - Configuration for rate limiting
    ///
    /// # Returns
    /// A new `RateLimiterState` instance with a background cleanup task
    pub fn new(config: RateLimitConfig) -> Self {
        let state = Self {
            config: config.clone(),
            counters: Arc::new(DashMap::with_capacity(10_000)), // Pre-allocate space for counters
        };

        // Spawn a background task to clean up old rate limit counters
        if state.config.enabled {
            let counters = state.counters.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    let now = Instant::now();
                    let one_minute_ago = now - Duration::from_secs(60);

                    counters.retain(|_, (_, timestamp)| {
                        // Keep entries that are less than 1 minute old
                        *timestamp > one_minute_ago
                    });
                }
            });
        }

        state
    }

    /// Check if a request should be rate limited
    ///
    /// # Arguments
    /// * `path` - The request path
    /// * `ip` - The client IP address
    ///
    /// # Returns
    /// `Ok(())` if the request is allowed, `Err(AuthencError::RateLimitExceeded)` if rate limited
    pub fn check_rate_limit(&self, path: &str, ip: &str) -> Result<(), AuthencError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Skip rate limiting for excluded paths
        if self
            .config
            .excluded_paths
            .iter()
            .any(|p| path.starts_with(p))
        {
            debug!(%ip, %path, "Path excluded from rate limiting");
            return Ok(());
        }

        let key = format!("{}:{}", ip, path);
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);

        // Get or create the counter for this IP and path
        let mut entry = self.counters.entry(key.clone()).or_insert_with(|| {
            debug!(%ip, %path, "New rate limit counter created");
            (AtomicU64::new(0), now)
        });

        // Reset counter if more than 1 minute has passed
        if entry.1 < one_minute_ago {
            debug!(%ip, %path, "Rate limit counter reset");
            entry.0.store(0, Ordering::Relaxed);
            entry.1 = now;
        }

        // Increment and check rate limit
        let count = entry.0.fetch_add(1, Ordering::Relaxed) + 1;

        if count > self.config.requests_per_minute {
            warn!(
                %ip,
                %path,
                count,
                limit = self.config.requests_per_minute,
                "Rate limit exceeded"
            );
            return Err(AuthencError::RateLimitExceeded);
        }

        debug!(%ip, %path, count, "Request within rate limit");
        Ok(())
    }
}

/// Middleware function for rate limiting
///
/// This middleware checks if the request should be rate limited based on the client's IP and request path.
/// If rate limited, it returns a 429 Too Many Requests response with appropriate headers.
///
/// # Arguments
/// * `ConnectInfo(addr)` - The client's connection info (contains IP address)
/// * `State(state)` - The shared rate limiter state
/// * `request` - The incoming HTTP request
/// * `next` - The next middleware in the chain
///
/// # Returns
/// The response from the next middleware, or a 429 response if rate limited
pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<RateLimiterState>>,
    request: Request,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    let path = request.uri().path();
    let ip = addr.ip().to_string();

    match state.check_rate_limit(path, &ip) {
        Ok(_) => {
            let response = next.run(request).await;
            Ok(response)
        }
        Err(AuthencError::RateLimitExceeded) => Err(StatusCode::TOO_MANY_REQUESTS),
        Err(_) => {
            error!(%ip, %path, "Unexpected error in rate limiting");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Create a rate limit layer
pub fn rate_limit_layer(config: RateLimitConfig) -> RateLimitLayer {
    RateLimitLayer::new(RateLimiterState::new(config))
}

/// Layer for applying rate limiting
#[derive(Clone)]
pub struct RateLimitLayer {
    state: Arc<RateLimiterState>,
}

impl RateLimitLayer {
    /// Create a new rate limit layer
    pub fn new(state: RateLimiterState) -> Self {
        Self {
            state: Arc::new(state),
        }
    }
}

impl<S> tower::Layer<S> for RateLimitLayer {
    type Service = RateLimitMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RateLimitMiddleware {
            inner,
            state: self.state.clone(),
        }
    }
}

/// Middleware that enforces rate limiting
#[derive(Clone)]
pub struct RateLimitMiddleware<S> {
    inner: S,
    state: Arc<RateLimiterState>,
}

impl<S, B> Service<Request<B>> for RateLimitMiddleware<S>
where
    S: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let path = req.uri().path().to_string();
        let ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let state = self.state.clone();
        let future = self.inner.call(req);

        Box::pin(async move {
            match state.check_rate_limit(&path, &ip) {
                Ok(_) => future.await,
                Err(AuthencError::RateLimitExceeded) => {
                    let retry_after = 60; // 1 minute
                    Ok((
                        StatusCode::TOO_MANY_REQUESTS,
                        [
                            ("retry-after", retry_after.to_string()),
                            (
                                "x-ratelimit-limit",
                                state.config.requests_per_minute.to_string(),
                            ),
                            ("x-ratelimit-remaining", "0".to_string()),
                        ],
                        "Rate limit exceeded. Please try again later.",
                    )
                        .into_response())
                }
                Err(_) => {
                    error!(%ip, %path, "Unexpected error in rate limiting");
                    Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
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
        extract::ConnectInfo,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use tower::{Service, ServiceExt};

    #[tokio::test]
    async fn test_rate_limiting() {
        // Create a test config with low limits
        let config = RateLimitConfig {
            requests_per_minute: 2,
            excluded_paths: vec!["/health".to_string()],
            enabled: true,
        };

        let state = RateLimiterState::new(config);

        // First request should succeed
        assert!(state.check_rate_limit("/", "127.0.0.1").is_ok());

        // Second request should succeed
        assert!(state.check_rate_limit("/", "127.0.0.1").is_ok());

        // Third request should be rate limited
        assert!(state.check_rate_limit("/", "127.0.0.1").is_err());

        // Health check should not be rate limited
        assert!(state.check_rate_limit("/health", "127.0.0.1").is_ok());

        // Different IP should not be rate limited
        assert!(state.check_rate_limit("/", "192.168.1.1").is_ok());
    }
}
