use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, errors::Result};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH, Duration};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

const SECRET: &[u8] = b"supersecretkey";

pub fn generate_jwt(user_id: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = SystemTime::now()
        .checked_add(Duration::from_secs(60 * 60))
        .unwrap()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expiration,
    };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(SECRET))
}

pub fn verify_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let data = decode::<Claims>(token, &DecodingKey::from_secret(SECRET), &Validation::default())?;
    Ok(data.claims)
}
