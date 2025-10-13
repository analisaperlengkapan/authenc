#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::crypto::ecdsa_keys::{EcdsaJwk, EcdsaJwkSet};
use serde_json;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test ECDSA JWK parsing with fuzzed data
    if let Ok(json_str) = std::str::from_utf8(data) {
        // Try to parse as individual JWK
        let _ = serde_json::from_str::<EcdsaJwk>(json_str);

        // Try to parse as JWK set
        let _ = serde_json::from_str::<EcdsaJwkSet>(json_str);
    }

    // Test JWK creation with fuzzed parameters
    if data.len() >= 32 {
        // Use first 32 bytes as mock key material
        let mock_key_data = &data[..32];

        // Try to create a verifying key from mock data (this will likely fail for invalid keys)
        use p256::ecdsa::VerifyingKey;
        if let Ok(verifying_key) = VerifyingKey::from_sec1_bytes(mock_key_data) {
            let _ = EcdsaJwk::from_verifying_key(&verifying_key, "test-kid");
        }
    }
});