#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::models::token::JwtClaims;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Convert fuzzer input to string for JWT claims parsing
    if let Ok(claims_str) = std::str::from_utf8(data) {
        // Test JWT claims deserialization
        let _result: Result<JwtClaims, _> = serde_json::from_str(claims_str);
    }
});