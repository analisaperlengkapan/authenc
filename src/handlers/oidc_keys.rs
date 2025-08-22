use once_cell::sync::Lazy;
use rand::thread_rng;
use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey, RsaPublicKey,
};

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
    RSA_KEYPAIR
        .to_pkcs8_pem(Default::default())
        .unwrap()
        .to_string()
}
