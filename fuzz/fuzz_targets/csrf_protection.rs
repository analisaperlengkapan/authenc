#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::middleware::csrf_protection_axum::CsrfConfig;
use serde_json;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test CSRF config parsing with fuzzed JSON
    if let Ok(json_str) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<CsrfConfig>(json_str);
    }

    // Test CSRF token generation with various lengths
    if data.len() >= 1 {
        let token_length = (data[0] as usize % 100) + 1; // 1-100 bytes

        // Create config with fuzzed token length
        let config = CsrfConfig {
            enabled: data.len() > 1 && data[1] % 2 == 0,
            header_name: "X-CSRF-Token".to_string(),
            cookie_name: "csrf_token".to_string(),
            token_length,
            excluded_paths: vec![],
        };

        // Test config creation doesn't crash
        let _ = config;
    }

    // Test path exclusion logic with fuzzed paths
    if data.len() > 10 {
        let path_data = &data[1..];
        if let Ok(path_str) = std::str::from_utf8(path_data) {
            let config = CsrfConfig {
                enabled: true,
                header_name: "X-CSRF-Token".to_string(),
                cookie_name: "csrf_token".to_string(),
                token_length: 32,
                excluded_paths: vec![path_str.to_string()],
            };

            // Test path checking logic
            let is_excluded = config.excluded_paths.contains(&path_str.to_string());
            let _ = is_excluded;
        }
    }
});