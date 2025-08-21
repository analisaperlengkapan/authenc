use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use std::fmt;

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: u16,
    pub message: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(actix_web::http::StatusCode::from_u16(self.code).unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR))
            .json(self)
    }
}
