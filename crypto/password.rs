use argon2::{self, Config};
use rand::Rng;

pub fn hash_password(password: &str) -> Result<String, argon2::Error> {
    let salt: [u8; 16] = rand::thread_rng().gen();
    let config = Config::default();
    argon2::hash_encoded(password.as_bytes(), &salt, &config)
}

pub fn verify_password(hash: &str, password: &str) -> Result<bool, argon2::Error> {
    argon2::verify_encoded(hash, password.as_bytes())
}
