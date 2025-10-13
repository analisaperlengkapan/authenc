#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::services::saml::SamlService;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Convert fuzzer input to string for XML parsing
    if let Ok(xml_str) = std::str::from_utf8(data) {
        // Create a dummy SAML service for testing parsing
        // Note: We can't easily create a full service without database, so we'll test XML parsing directly
        let _result = quick_xml::de::from_str::<authenc::services::saml::SamlResponse>(xml_str);
    }
});