#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::services::webauthn::{WebAuthnRegistrationRequest, WebAuthnAuthenticationRequest};
use serde_json;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test WebAuthn registration request parsing
    if let Ok(json_str) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<WebAuthnRegistrationRequest>(json_str);
        let _ = serde_json::from_str::<WebAuthnAuthenticationRequest>(json_str);
    }

    // Test request creation with fuzzed parameters
    if data.len() >= 30 {
        let username_data = &data[..15];
        let display_name_data = &data[15..30];

        if let (Ok(username), Ok(display_name)) = (
            std::str::from_utf8(username_data),
            std::str::from_utf8(display_name_data),
        ) {
            // Test registration request creation
            let reg_request = WebAuthnRegistrationRequest {
                username: username.to_string(),
                display_name: display_name.to_string(),
            };

            // Test serialization
            let _ = serde_json::to_string(&reg_request);

            // Test authentication request creation
            let auth_request = WebAuthnAuthenticationRequest {
                username: username.to_string(),
            };

            // Test serialization
            let _ = serde_json::to_string(&auth_request);
        }
    }

    // Test credential ID generation with fuzzed data
    if data.len() >= 32 {
        // Use first 32 bytes as mock credential ID
        let credential_id = &data[..32];

        // Test base64url encoding of credential ID
        let encoded = base64ct::Base64UrlUnpadded::encode_string(credential_id);
        let _ = encoded;

        // Test decoding back
        let _ = base64ct::Base64UrlUnpadded::decode_vec(&encoded);
    }

    // Test challenge generation simulation
    if data.len() > 40 {
        let challenge_data = &data[32..];
        // Simulate challenge generation (in real WebAuthn, this would be random)
        let challenge_b64 = base64ct::Base64UrlUnpadded::encode_string(challenge_data);
        let _ = challenge_b64;
    }
});