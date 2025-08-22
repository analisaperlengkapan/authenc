use actix_web::body::BoxBody;
use actix_web::{
    dev::{forward_ready, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures::future::{ok, LocalBoxFuture, Ready};
// unused imports removed
use crate::handlers::oidc_jwt::OidcIdTokenClaims;
use crate::handlers::oidc_keys::RSA_KEYPAIR;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use rsa::pkcs8::EncodePublicKey;
use std::rc::Rc;

#[derive(Clone)]
pub struct RequireRole {
    pub required: &'static str,
}

impl<S> Transform<S, ServiceRequest> for RequireRole
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>
        + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Transform = RequireRoleMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RequireRoleMiddleware {
            service: Rc::new(service),
            required: self.required,
        })
    }
}

pub struct RequireRoleMiddleware<S> {
    service: Rc<S>,
    required: &'static str,
}

impl<S> actix_web::dev::Service<ServiceRequest> for RequireRoleMiddleware<S>
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<BoxBody>, Error = Error>
        + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let required = self.required;
        let svc = self.service.clone();
        Box::pin(async move {
            // Perform authz BEFORE calling inner service
            let headers = req.headers();
            let auth = headers.get("Authorization").and_then(|v| v.to_str().ok());
            if let Some(auth) = auth {
                if let Some(token) = auth.strip_prefix("Bearer ") {
                    let pubkey = rsa::RsaPublicKey::from(&*RSA_KEYPAIR);
                    let pubkey_pem = pubkey.to_public_key_pem(Default::default()).unwrap();
                    let key = DecodingKey::from_rsa_pem(pubkey_pem.as_bytes()).unwrap();
                    let mut validation = Validation::new(Algorithm::RS256);
                    validation.validate_exp = true;
                    if let Ok(data) =
                        jsonwebtoken::decode::<OidcIdTokenClaims>(token, &key, &validation)
                    {
                        if let Some(role) = data.claims.role {
                            if role == required {
                                return svc.call(req).await;
                            }
                        }
                    }
                }
            }
            // Unauthorized: return 403 response
            let (req_head, _pl) = req.into_parts();
            let resp = actix_web::HttpResponse::Forbidden()
                .finish()
                .map_into_boxed_body();
            Ok(ServiceResponse::new(req_head, resp))
        })
    }
}
