#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::crypto::pqc::mldsa::SecretKey as MldsaSecretKey;
use authenc::crypto::pqc::mlkem::SecretKey as MlkemSecretKey;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }

    let message = &data[0..32];

    // Test ML-DSA signing
    if let Ok((pk, sk)) = MldsaSecretKey::new() {
        if let Ok(signature) = sk.sign(message) {
            let _ = pk.verify(message, &signature);
        }
    }

    // Test ML-KEM encryption
    if let Ok((pk, sk)) = MlkemSecretKey::new() {
        if let Ok((ciphertext, _shared_secret)) = pk.encapsulate() {
            let _ = sk.decapsulate(&ciphertext);
        }
    }
});