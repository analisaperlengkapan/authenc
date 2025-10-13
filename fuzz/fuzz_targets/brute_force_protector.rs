#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::services::brute_force_protector::BruteForceProtector;
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use first byte to determine max_attempts (1-10)
    let max_attempts = (data[0] as usize % 10) + 1;

    // Use second byte to determine window_secs (1-300)
    let window_secs = if data.len() > 1 {
        (data[1] as u64 % 300) + 1
    } else {
        60
    };

    let protector = BruteForceProtector::new(max_attempts, window_secs);

    // Use remaining data as key for attempts (only if we have at least 3 bytes)
    if data.len() > 2 {
        let key_data = &data[2..];
        if let Ok(key) = std::str::from_utf8(key_data) {
            // Register multiple attempts
            for _ in 0..max_attempts + 1 {
                let _ = protector.register_attempt(key);
            }
        }
    }
});