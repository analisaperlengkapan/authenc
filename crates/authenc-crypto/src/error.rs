use authenc_core::error::{AuthencError as CoreError, Result as CoreResult};

pub type AuthencError = CoreError;
pub type Result<T> = CoreResult<T>;

pub trait AuthencErrorExt {
    fn crypto<T: Into<String>>(message: T) -> Self;
}

impl AuthencErrorExt for AuthencError {
    fn crypto<T: Into<String>>(message: T) -> Self {
        Self::InternalError {
            message: format!("Crypto error: {}", message.into()),
        }
    }
}
