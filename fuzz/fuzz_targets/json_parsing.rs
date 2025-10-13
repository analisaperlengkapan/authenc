#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Convert fuzzer input to string for JSON parsing
    if let Ok(json_str) = std::str::from_utf8(data) {
        // Test JSON parsing with serde_json
        let _result: Result<serde_json::Value, _> = serde_json::from_str(json_str);
    }
});