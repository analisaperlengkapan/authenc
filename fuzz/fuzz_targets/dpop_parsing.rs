#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::crypto::dpop::DPoPProof;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Convert fuzzer input to string for DPoP JWT parsing
    if let Ok(dpop_jwt) = std::str::from_utf8(data) {
        // Test DPoP proof parsing
        let _result = DPoPProof::from_jwt_string(dpop_jwt);
    }
});