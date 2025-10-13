#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::crypto::ed25519_keys::{sign_ed25519, verify_ed25519};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Try to sign data with Ed25519
    let signature = sign_ed25519(data);
    
    // Try to verify the signature
    let _ = verify_ed25519(data, &signature);
});