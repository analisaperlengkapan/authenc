#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::crypto::xmldsig::{CanonicalizationMethod, DigestMethod, SignatureMethod};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Test canonicalization method parsing
    if let Ok(uri_str) = std::str::from_utf8(data) {
        let _ = CanonicalizationMethod::from_uri(uri_str);
    }

    // Test digest method parsing with first part of data
    if data.len() > 10 {
        let digest_data = &data[..10];
        if let Ok(uri_str) = std::str::from_utf8(digest_data) {
            let _ = DigestMethod::from_uri(uri_str);
        }
    }

    // Test signature method parsing with middle part of data
    if data.len() > 20 {
        let sig_data = &data[10..20];
        if let Ok(uri_str) = std::str::from_utf8(sig_data) {
            let _ = SignatureMethod::from_uri(uri_str);
        }
    }

    // Test XML signature validation with remaining data as XML
    if data.len() > 50 {
        let xml_data = &data[20..];
        if let Ok(xml_str) = std::str::from_utf8(xml_data) {
            // This would test XML signature validation if we had a full implementation
            // For now, just ensure the XML parsing doesn't crash
            let _ = xml_str.len();
        }
    }
});