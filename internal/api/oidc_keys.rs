use once_cell::sync::Lazy;
use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::{EncodePublicKey, EncodePrivateKey}};
use rand::thread_rng;

// Generate or load a static RSA keypair for OIDC
pub static RSA_KEYPAIR: Lazy<RsaPrivateKey> = Lazy::new(|| {
    // In production: load from file/env, rotate securely
    RsaPrivateKey::new(&mut thread_rng(), 2048).expect("Failed to generate RSA key")
});

pub fn get_public_pem() -> String {
    let pubkey = RsaPublicKey::from(RSA_KEYPAIR.clone());
    pubkey.to_public_key_pem(Default::default()).unwrap()
}

pub fn get_private_pem() -> String {
    RSA_KEYPAIR.to_pkcs8_pem(Default::default()).unwrap().to_string()
}
