#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // Split data into pattern and input
    let split_point = data.len() / 2;
    let pattern_bytes = &data[0..split_point];
    let input_bytes = &data[split_point..];

    if let (Ok(pattern), Ok(input)) = (
        std::str::from_utf8(pattern_bytes),
        std::str::from_utf8(input_bytes)
    ) {
        // Test regex compilation and matching
        if let Ok(regex) = regex::Regex::new(pattern) {
            let _ = regex.is_match(input);
        }
    }
});