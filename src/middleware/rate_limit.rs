use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    body::BoxBody,
    Error, HttpResponse,
};
use futures::future::{ok, Ready};
use futures::Future;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// Rate limiting middleware with configurable limits (global per-IP)
pub struct RateLimiter {
    requests_per_minute: u32,
    storage: Arc<Mutex<HashMap<String, ClientData>>>,
}

#[derive(Clone)]
struct ClientData {
    requests: Vec<Instant>,
    last_request: Instant,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self { requests_per_minute, storage: Arc::new(Mutex::new(HashMap::new())) }
    }

    fn check_rate_limit(&self, client_ip: &str) -> bool {
        let mut storage = match self.storage.lock() { Ok(s) => s, Err(p) => { log::error!("Rate limiter mutex poisoned"); p.into_inner() } };
        let now = Instant::now();
        let window_start = now - Duration::from_secs(60);
        let client_data = storage.entry(client_ip.to_string()).or_insert_with(|| ClientData { requests: Vec::new(), last_request: now });
        client_data.requests.retain(|&t| t > window_start);
        if client_data.requests.len() >= self.requests_per_minute as usize {
            log::warn!("Rate limit exceeded for client {}: {} requests/min", client_ip, client_data.requests.len());
            return false;
        }
        client_data.requests.push(now);
        client_data.last_request = now;
        let cleanup_threshold = now - Duration::from_secs(300);
        storage.retain(|_, data| data.last_request > cleanup_threshold);
        true
    }
}

impl<S> Transform<S, ServiceRequest> for RateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimiterMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RateLimiterMiddleware { service, rate_limiter: self.clone() })
    }
}

impl Clone for RateLimiter { fn clone(&self) -> Self { Self { requests_per_minute: self.requests_per_minute, storage: Arc::clone(&self.storage) } } }

pub struct RateLimiterMiddleware<S> { service: S, rate_limiter: RateLimiter }

impl<S> Service<ServiceRequest> for RateLimiterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { self.service.poll_ready(ctx) }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let client_ip = req.connection_info().realip_remote_addr().unwrap_or("unknown").to_string();
        if req.path().starts_with("/health") || req.path() == "/metrics" {
            let fut = self.service.call(req);
            return Box::pin(async move { fut.await });
        }
        if !self.rate_limiter.check_rate_limit(&client_ip) {
            let response = HttpResponse::TooManyRequests()
                .append_header(("Retry-After", "60"))
                .json(serde_json::json!({"error": {"code": "RATE_LIMIT_EXCEEDED", "message": "Too many requests. Please try again later.", "retry_after": 60}}));
            let (parts, _) = req.into_parts();
            let sr = ServiceResponse::new(parts, response.map_into_boxed_body());
            return Box::pin(async move { Ok(sr) });
        }
        let fut = self.service.call(req);
        Box::pin(async move { fut.await })
    }
}

/// Path-specific rate limiter
pub struct PathRateLimiter {
    limits: HashMap<String, u32>,
    storage: Arc<Mutex<HashMap<String, HashMap<String, ClientData>>>>,
}

impl PathRateLimiter {
    pub fn new() -> Self {
        let mut limits = HashMap::new();
        limits.insert("/v1/auth/login".to_string(), 5);
        limits.insert("/v1/auth/".to_string(), 10);
        limits.insert("/v1/users".to_string(), 30);
        Self { limits, storage: Arc::new(Mutex::new(HashMap::new())) }
    }
    pub fn with_limits(limits: HashMap<String, u32>) -> Self { Self { limits, storage: Arc::new(Mutex::new(HashMap::new())) } }

    fn check_path_rate_limit(&self, path: &str, client_ip: &str) -> bool {
        let limit = self.limits.iter().find(|(p, _)| path.starts_with(p.as_str())).map(|(_, l)| *l);
        let Some(requests_per_minute) = limit else { return true; };
        let mut storage = match self.storage.lock() { Ok(s) => s, Err(p) => { log::error!("Path rate limiter mutex poisoned"); p.into_inner() } };
        let path_storage = storage.entry(path.to_string()).or_insert_with(HashMap::new);
        let now = Instant::now();
        let window_start = now - Duration::from_secs(60);
        let client_data = path_storage.entry(client_ip.to_string()).or_insert_with(|| ClientData { requests: Vec::new(), last_request: now });
        client_data.requests.retain(|&t| t > window_start);
        if client_data.requests.len() >= requests_per_minute as usize {
            log::warn!("Path rate limit exceeded for {} on {}: {}", client_ip, path, client_data.requests.len());
            return false;
        }
        client_data.requests.push(now);
        client_data.last_request = now;
        let cleanup_threshold = now - Duration::from_secs(300);
        path_storage.retain(|_, d| d.last_request > cleanup_threshold);
        storage.retain(|_, ps| !ps.is_empty());
        true
    }
}
impl Clone for PathRateLimiter { fn clone(&self) -> Self { Self { limits: self.limits.clone(), storage: Arc::clone(&self.storage) } } }

impl<S> Transform<S, ServiceRequest> for PathRateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = PathRateLimiterMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(PathRateLimiterMiddleware { service, rate_limiter: self.clone() })
    }
}

pub struct PathRateLimiterMiddleware<S> { service: S, rate_limiter: PathRateLimiter }

impl<S> Service<ServiceRequest> for PathRateLimiterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { self.service.poll_ready(ctx) }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let client_ip = req.connection_info().realip_remote_addr().unwrap_or("unknown").to_string();
        let path = req.path().to_string();
        if !self.rate_limiter.check_path_rate_limit(&path, &client_ip) {
            let response = HttpResponse::TooManyRequests()
                .append_header(("Retry-After", "60"))
                .json(serde_json::json!({"error": {"code": "PATH_RATE_LIMIT_EXCEEDED", "message": format!("Too many requests to {}. Please try again later.", path), "retry_after": 60}}));
            let (parts, _) = req.into_parts();
            let sr = ServiceResponse::new(parts, response.map_into_boxed_body());
            return Box::pin(async move { Ok(sr) });
        }
        let fut = self.service.call(req);
        Box::pin(async move { fut.await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App, HttpResponse};

    async fn test_handler() -> HttpResponse { HttpResponse::Ok().body("OK") }

    #[actix_web::test]
    async fn test_rate_limiter() {
        let app = test::init_service(App::new().wrap(RateLimiter::new(2)).route("/test", web::get().to(test_handler))).await;
        for _ in 0..2 { let req = test::TestRequest::get().uri("/test").to_request(); let resp = test::call_service(&app, req).await; assert_eq!(resp.status(), 200); }
        let req = test::TestRequest::get().uri("/test").to_request();
        let resp = test::call_service(&app, req).await; assert_eq!(resp.status(), 429);
    }

    #[actix_web::test]
    async fn test_health_check_bypass() {
        let app = test::init_service(App::new().wrap(RateLimiter::new(1)).route("/health", web::get().to(test_handler)).route("/test", web::get().to(test_handler))).await;
        for _ in 0..5 { let req = test::TestRequest::get().uri("/health").to_request(); let resp = test::call_service(&app, req).await; assert_eq!(resp.status(), 200); }
    }

    #[actix_web::test]
    async fn test_path_rate_limiter() {
        let mut limits = HashMap::new(); limits.insert("/auth".to_string(), 1);
        let app = test::init_service(App::new().wrap(PathRateLimiter::with_limits(limits)).route("/auth/login", web::post().to(test_handler)).route("/other", web::get().to(test_handler))).await;
        let req = test::TestRequest::post().uri("/auth/login").to_request(); let resp = test::call_service(&app, req).await; assert_eq!(resp.status(), 200);
        let req = test::TestRequest::post().uri("/auth/login").to_request(); let resp = test::call_service(&app, req).await; assert_eq!(resp.status(), 429);
        let req = test::TestRequest::get().uri("/other").to_request(); let resp = test::call_service(&app, req).await; assert_eq!(resp.status(), 200);
    }
}
