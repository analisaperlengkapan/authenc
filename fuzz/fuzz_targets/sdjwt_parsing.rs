#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::crypto::sdjwt::SdJwt;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Convert fuzzer input to string for SD-JWT parsing
    if let Ok(sd_jwt_str) = std::str::from_utf8(data) {
        // Test SD-JWT parsing
        let _result = SdJwt::from_string(sd_jwt_str);
    }
});