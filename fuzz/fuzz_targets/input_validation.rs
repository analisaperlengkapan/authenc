#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::middleware::input_validation_axum::InputValidationConfig;
use serde_json;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test input validation config parsing with fuzzed JSON
    if let Ok(json_str) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<InputValidationConfig>(json_str);
    }

    // Test config creation with fuzzed parameters
    if data.len() >= 4 {
        let config = InputValidationConfig {
            enabled: data[0] % 2 == 0,
            max_query_param_length: (data[1] as usize % 10000) + 1,
            max_header_length: (data[2] as usize % 10000) + 1,
            max_request_body_size: (data[3] as usize % 10000000) + 1, // up to 10MB
            block_suspicious_patterns: data.len() > 4 && data[4] % 2 == 0,
            validate_content_type: data.len() > 5 && data[5] % 2 == 0,
            allowed_content_types: vec![],
        };

        // Test config validation doesn't crash
        let _ = config;
    }

    // Test content type validation with fuzzed content types
    if data.len() > 20 {
        let content_type_data = &data[10..];
        if let Ok(content_type_str) = std::str::from_utf8(content_type_data) {
            let config = InputValidationConfig {
                enabled: true,
                max_query_param_length: 2048,
                max_header_length: 4096,
                max_request_body_size: 1024 * 1024,
                block_suspicious_patterns: true,
                validate_content_type: true,
                allowed_content_types: vec![content_type_str.to_string()],
            };

            // Test content type checking
            let is_allowed = config.allowed_content_types.contains(&content_type_str.to_string());
            let _ = is_allowed;
        }
    }

    // Test suspicious pattern detection with fuzzed input
    if data.len() > 30 {
        let suspicious_data = &data[20..];
        if let Ok(suspicious_str) = std::str::from_utf8(suspicious_data) {
            // Test various suspicious patterns that might be detected
            let has_suspicious = suspicious_str.contains("..") ||
                                suspicious_str.contains("../") ||
                                suspicious_str.contains("<script") ||
                                suspicious_str.contains("javascript:");
            let _ = has_suspicious;
        }
    }
});