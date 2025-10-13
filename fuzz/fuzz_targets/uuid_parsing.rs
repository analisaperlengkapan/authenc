#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Convert fuzzer input to string for UUID parsing
    if let Ok(uuid_str) = std::str::from_utf8(data) {
        // Test UUID parsing
        let _result = uuid::Uuid::parse_str(uuid_str);
    }
});