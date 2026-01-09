use std::{
    future::{Future, ready},
    pin::Pin,
    task::{Context, Poll},
};

use axum::{
    body::Body,
    extract::Request,
    http::{Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use tower::Service;
use tracing::error;

use crate::error::AuthencError;

/// Middleware that enforces role-based access control
#[derive(Clone)]
pub struct RequireRole<S> {
    /// The inner service to wrap with RBAC protection
    inner: S,
    /// The role required to access the protected resource
    required_role: String,
}

/// RBAC middleware service
#[derive(Clone)]
pub struct RbacMiddleware<S> {
    /// The inner service to wrap with RBAC protection
    inner: S,
    /// The role required to access the protected resource
    required_role: String,
}

impl<S> RequireRole<S> {
    /// Create a new RBAC middleware that requires the specified role
    pub fn new(inner: S, required_role: &str) -> Self {
        Self {
            inner,
            required_role: required_role.to_string(),
        }
    }
}

impl<S, B> Service<Request<B>> for RequireRole<S>
where
    S: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        use crate::middleware::auth::AuthUser;

        // Get the authenticated user from request extensions
        let user = req.extensions().get::<AuthUser>();

        match user {
            Some(user) => {
                // Check if user has the required role
                if user.roles.contains(&self.required_role)
                    || user.roles.contains(&"admin".to_string())
                {
                    let fut = self.inner.call(req);
                    Box::pin(fut)
                } else {
                    let error =
                        AuthencError::forbidden(format!("Requires role: {}", self.required_role));
                    let response = error.into_response();
                    Box::pin(ready(Ok(response)))
                }
            }
            None => {
                // No user in request extensions, which means auth middleware wasn't run or failed
                error!("RBAC middleware used without proper authentication");
                let error = AuthencError::internal(
                    "Server misconfiguration: RBAC without authentication".to_string(),
                );
                let response = error.into_response();
                Box::pin(ready(Ok(response)))
            }
        }
    }
}

/// RBAC middleware function
pub async fn rbac_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    // Extract user claims from request extensions
    let claims = request
        .extensions()
        .get::<crate::models::user::UserClaims>();

    if claims.is_none() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let response = next.run(request).await;
    Ok(response)
}

/// RBAC layer
// Simplified RBAC layer type alias
pub type RbacLayer<S> = RequireRole<S>;

impl<S> RbacMiddleware<S> {
    /// Create a new RBAC middleware instance with required role
    ///
    /// This constructor creates an RBAC (Role-Based Access Control) middleware
    /// that will validate that incoming requests have the specified required role.
    /// The middleware will check user authentication and role assignments before
    /// allowing access to protected routes.
    ///
    /// # Arguments
    /// * `inner` - The inner service that will be wrapped by RBAC protection
    /// * `required_role` - The role name that users must have to access the route
    ///
    /// # Returns
    /// A new `RbacMiddleware` instance configured with the required role
    ///
    /// # Security Considerations
    /// - Role names should be validated to prevent injection attacks
    /// - Consider using role hierarchies for more flexible access control
    /// - Combine with authentication middleware for complete security
    /// - Log access denials for security monitoring
    ///
    /// # Example
    /// # Example
    /// ```rust
    /// use authenc::middleware::rbac::RbacMiddleware;
    /// use tower::service_fn;
    /// use std::convert::Infallible;
    /// use axum::http::Request;
    ///
    /// // Create a simple service for demonstration
    /// let service = service_fn(|_req: Request<axum::body::Body>| async { Ok::<_, Infallible>(axum::http::Response::new(axum::body::Body::empty())) });
    /// let middleware = RbacMiddleware::new(service, "admin".to_string());
    /// ```
    pub fn new(inner: S, required_role: String) -> Self {
        Self {
            inner,
            required_role,
        }
    }
}

impl<S, B> Service<Request<B>> for RbacMiddleware<S>
where
    S: Service<Request<B>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        use crate::middleware::auth::AuthUser;

        // Get the authenticated user from request extensions
        let user = req.extensions().get::<AuthUser>();

        match user {
            Some(user) => {
                // Check if user has the required role
                if user.roles.contains(&self.required_role)
                    || user.roles.contains(&"admin".to_string())
                {
                    let fut = self.inner.call(req);
                    Box::pin(fut)
                } else {
                    let error =
                        AuthencError::forbidden(format!("Requires role: {}", self.required_role));
                    let response = error.into_response();
                    Box::pin(ready(Ok(response)))
                }
            }
            None => {
                // No user in request extensions, which means auth middleware wasn't run or failed
                error!("RBAC middleware used without proper authentication");
                let error = AuthencError::internal(
                    "Server misconfiguration: RBAC without authentication".to_string(),
                );
                let response = error.into_response();
                Box::pin(ready(Ok(response)))
            }
        }
    }
}

/// Layer that applies the RBAC middleware
#[derive(Clone)]
pub struct RequireRoleLayer {
    /// The role required to access the protected resource
    role: String,
}

impl RequireRoleLayer {
    /// Create a new RBAC layer that requires the specified role
    pub fn new(role: &str) -> Self {
        Self {
            role: role.to_string(),
        }
    }
}

impl<S> tower::Layer<S> for RequireRoleLayer {
    type Service = RequireRole<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireRole::new(inner, &self.role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        routing::get,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_rbac_middleware() {
        use crate::middleware::auth::AuthUser;

        // Create a test service with RBAC protection
        let app = Router::new()
            .route("/admin", get(|| async { "Admin Area" }))
            .layer(RequireRoleLayer::new("admin"));

        // Create a user with admin role
        let admin_user = AuthUser {
            id: "1".to_string(),
            email: "admin@example.com".to_string(),
            roles: vec!["admin".to_string()],
        };

        // Create a regular user
        let regular_user = AuthUser {
            id: "2".to_string(),
            email: "user@example.com".to_string(),
            roles: vec!["user".to_string()],
        };

        // Test with admin user
        let mut request = Request::builder()
            .uri("/admin")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(admin_user);

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Test with regular user (should be forbidden)
        let mut request = Request::builder()
            .uri("/admin")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(regular_user);

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
