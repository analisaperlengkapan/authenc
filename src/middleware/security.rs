use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    body::BoxBody,
    Error, HttpResponse,
};
use futures::future::{ok, Ready};
use futures::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Security headers middleware to add common security headers
#[derive(Default)]
pub struct SecurityHeaders;

impl<S> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = SecurityHeadersMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(SecurityHeadersMiddleware { service })
    }
}

pub struct SecurityHeadersMiddleware<S> {
    service: S,
}

impl<S> Service<ServiceRequest> for SecurityHeadersMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let is_https = req.connection_info().scheme() == "https";
        let fut = self.service.call(req);
        Box::pin(async move {
            let mut res = fut.await?;
            let headers = res.headers_mut();
            headers.insert(
                actix_web::http::header::HeaderName::from_static("x-frame-options"),
                actix_web::http::header::HeaderValue::from_static("DENY"),
            );
            headers.insert(
                actix_web::http::header::HeaderName::from_static("x-content-type-options"),
                actix_web::http::header::HeaderValue::from_static("nosniff"),
            );
            headers.insert(
                actix_web::http::header::HeaderName::from_static("x-xss-protection"),
                actix_web::http::header::HeaderValue::from_static("1; mode=block"),
            );
            headers.insert(
                actix_web::http::header::HeaderName::from_static("referrer-policy"),
                actix_web::http::header::HeaderValue::from_static("strict-origin-when-cross-origin"),
            );
            headers.insert(
                actix_web::http::header::HeaderName::from_static("content-security-policy"),
                actix_web::http::header::HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
            );
            if is_https {
                headers.insert(
                    actix_web::http::header::HeaderName::from_static("strict-transport-security"),
                    actix_web::http::header::HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
                );
            }
            Ok(res)
        })
    }
}

/// Request sanitization middleware
pub struct RequestSanitizer;

impl<S> Transform<S, ServiceRequest> for RequestSanitizer
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type InitError = ();
    type Transform = RequestSanitizerMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RequestSanitizerMiddleware { service })
    }
}

pub struct RequestSanitizerMiddleware<S> {
    service: S,
}

impl<S> Service<ServiceRequest> for RequestSanitizerMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if let Err(response) = validate_request(&req) {
            let (parts, _) = req.into_parts();
            let sr: ServiceResponse<BoxBody> = ServiceResponse::new(parts, response.map_into_boxed_body());
            return Box::pin(async move { Ok(sr) });
        }
        let fut = self.service.call(req);
        Box::pin(async move { fut.await })
    }
}

/// Validate incoming request for security issues
fn validate_request(req: &ServiceRequest) -> Result<(), HttpResponse> {
    // Check for SQL injection patterns in query parameters
    let query_string = req.query_string();
    if !query_string.is_empty() {
        let suspicious_patterns = [
            "union", "select", "drop", "insert", "delete", "update",
            "--", "/*", "*/", "xp_", "sp_cmdshell", "'", "\"",
        ];
        let query_lower = query_string.to_lowercase();
        for pattern in &suspicious_patterns {
            if query_lower.contains(pattern) {
                log::warn!(
                    "Suspicious query parameter detected from {}: {}",
                    req.connection_info().realip_remote_addr().unwrap_or("unknown"),
                    query_string
                );
                return Err(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": {"code": "INVALID_REQUEST", "message": "Request contains invalid characters"}
                })));
            }
        }
    }

    // Content-Length guard
    const MAX_CONTENT_LENGTH: usize = 10 * 1024 * 1024; // 10MB
    if let Some(content_length) = req.headers().get(actix_web::http::header::CONTENT_LENGTH) {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(length) = length_str.parse::<usize>() {
                if length > MAX_CONTENT_LENGTH {
                    log::warn!(
                        "Request with excessive content length from {}: {} bytes",
                        req.connection_info().realip_remote_addr().unwrap_or("unknown"),
                        length
                    );
                    return Err(HttpResponse::PayloadTooLarge().json(serde_json::json!({
                        "error": {"code": "PAYLOAD_TOO_LARGE", "message": "Request payload exceeds maximum allowed size"}
                    })));
                }
            }
        }
    }

    // User-Agent patterns (log only)
    if let Some(user_agent) = req.headers().get(actix_web::http::header::USER_AGENT) {
        if let Ok(ua_str) = user_agent.to_str() {
            let suspicious_ua_patterns = [
                "sqlmap", "nmap", "nikto", "burp", "owasp", "zap", "bot", "crawler", "spider", "scanner",
            ];
            let ua_lower = ua_str.to_lowercase();
            for pattern in &suspicious_ua_patterns {
                if ua_lower.contains(pattern) {
                    log::info!(
                        "Suspicious User-Agent detected from {}: {}",
                        req.connection_info().realip_remote_addr().unwrap_or("unknown"),
                        ua_str
                    );
                    break;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App, HttpResponse};

    async fn test_handler() -> HttpResponse { HttpResponse::Ok().body("OK") }

    #[actix_web::test]
    async fn test_security_headers() {
        let app = test::init_service(
            App::new()
                .wrap(SecurityHeaders::default())
                .route("/test", web::get().to(test_handler))
        ).await;
        let req = test::TestRequest::get().uri("/test").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        assert!(resp.headers().contains_key("x-frame-options"));
        assert!(resp.headers().contains_key("x-content-type-options"));
        assert!(resp.headers().contains_key("x-xss-protection"));
    }

    #[actix_web::test]
    async fn test_request_validation() {
        let req = test::TestRequest::get().uri("/test?param=union%20select").to_srv_request();
        let result = validate_request(&req);
        assert!(result.is_err());
    }

    #[actix_web::test]
    async fn test_payload_size_validation() {
        let req = test::TestRequest::post()
            .uri("/test")
            .insert_header(("Content-Length", "20971520"))
            .to_srv_request();
        let result = validate_request(&req);
        assert!(result.is_err());
    }
}
