#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Convert fuzzer input to string for URL parsing
    if let Ok(url_str) = std::str::from_utf8(data) {
        // Test URL parsing
        let _result = url::Url::parse(url_str);
    }
});