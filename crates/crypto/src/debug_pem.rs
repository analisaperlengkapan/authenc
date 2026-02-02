use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use p256::{PublicKey, SecretKey};
use rand::rngs::OsRng;
use p256::ecdsa::SigningKey;

fn main() {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = PublicKey::from(verifying_key);
    let secret_key = SecretKey::from(&signing_key);
    
    let public_pem = public_key.to_public_key_pem(Default::default()).unwrap();
    let private_pem = secret_key.to_pkcs8_pem(Default::default()).unwrap();
    
    println!("Public PEM:");
    println!("{}", public_pem);
    println!("\nPrivate PEM:");
    println!("{:?}", private_pem);
    
    println!("\nPublic PEM ends with: {:?}", public_pem.ends_with("-----END PUBLIC KEY-----"));
    println!("Private PEM ends with: {:?}", private_pem.to_string().ends_with("-----END PRIVATE KEY-----"));
}
