use actix_web::body::BoxBody;
use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures::future::{ok, LocalBoxFuture, Ready};
// use std::rc::Rc;
use crate::handlers::session::Claims;
use crate::services::session_store::SessionStore;
use jsonwebtoken::{decode, DecodingKey, Validation};
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Clone)]
pub struct AuthMiddleware {
    pub session_store: Arc<SessionStore>,
}

impl<S> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Transform = AuthMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthMiddlewareService {
            service: Arc::new(service),
            session_store: self.session_store.clone(),
        })
    }
}

pub struct AuthMiddlewareService<S> {
    service: Arc<S>,
    session_store: Arc<SessionStore>,
}

impl<S> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error> + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let session_store = self.session_store.clone();
        let svc = self.service.clone();
        Box::pin(async move {
            let token = req
                .headers()
                .get("Authorization")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "));
            let secret = std::env::var("AUTHENCE_JWT_SECRET")
                .unwrap_or_else(|_| "dev_secret_key_change_me".to_string());
            if let Some(token) = token {
                let decoded = decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(secret.as_bytes()),
                    &Validation::default(),
                );
                if let Ok(data) = decoded {
                    // Check if session is still valid
                    match session_store.get_user_id(token) {
                        Ok(Some(_)) => {
                            req.extensions_mut().insert(data.claims);
                            return svc.call(req).await;
                        }
                        _ => {}
                    }
                }
            }
            let (req, _pl) = req.into_parts();
            let resp = HttpResponse::Unauthorized().finish().map_into_boxed_body();
            Ok(ServiceResponse::new(req, resp))
        })
    }
}
