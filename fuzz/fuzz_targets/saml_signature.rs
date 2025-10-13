#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::services::saml_signature::SamlMessage;
use serde_json;
use uuid::Uuid;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test SAML message parsing with fuzzed JSON
    if let Ok(json_str) = std::str::from_utf8(data) {
        let _ = serde_json::from_str::<SamlMessage>(json_str);
    }

    // Test SAML message creation with fuzzed parameters
    if data.len() >= 50 {
        // Use parts of the data to create various string fields
        let saml_id_data = &data[..16];
        let message_type_data = &data[16..24];
        let issuer_data = &data[24..32];
        let destination_data = &data[32..40];
        let xml_content_data = &data[40..];

        if let (Ok(saml_id), Ok(message_type), Ok(issuer), Ok(destination), Ok(xml_content)) = (
            std::str::from_utf8(saml_id_data),
            std::str::from_utf8(message_type_data),
            std::str::from_utf8(issuer_data),
            std::str::from_utf8(destination_data),
            std::str::from_utf8(xml_content_data),
        ) {
            let message = SamlMessage {
                id: Uuid::new_v4(),
                saml_id: saml_id.to_string(),
                message_type: message_type.to_string(),
                issuer: issuer.to_string(),
                destination: destination.to_string(),
                xml_content: xml_content.to_string(),
                signature: Some("mock_signature".to_string()),
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                session_id: Some("mock_session".to_string()),
                relay_state: Some("mock_relay_state".to_string()),
            };

            // Test message serialization
            let _ = serde_json::to_string(&message);
        }
    }

    // Test XML content validation (basic XML structure check)
    if data.len() > 20 {
        let xml_data = &data[10..];
        if let Ok(xml_str) = std::str::from_utf8(xml_data) {
            // Basic XML validation - check for XML declaration or root element
            let is_xml_like = xml_str.contains("<?xml") ||
                             xml_str.contains("<") && xml_str.contains(">") ||
                             xml_str.contains("<saml") ||
                             xml_str.contains("<Assertion");
            let _ = is_xml_like;
        }
    }
});