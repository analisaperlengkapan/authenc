use actix_web::{dev::Payload, Error, FromRequest, HttpRequest};
use futures::future::{ready, Ready};
use crate::crypto::jwt::{self, Claims};

pub struct AuthBearer(pub Claims);

impl FromRequest for AuthBearer {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if let Some(auth_header) = req.headers().get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    if let Ok(claims) = jwt::verify_jwt(token) {
                        return ready(Ok(AuthBearer(claims)));
                    }
                }
            }
        }
        ready(Err(actix_web::error::ErrorUnauthorized("Missing or invalid token")))
    }
}
