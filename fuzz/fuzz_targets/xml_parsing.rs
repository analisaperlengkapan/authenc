#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Convert fuzzer input to string for XML parsing
    if let Ok(xml_str) = std::str::from_utf8(data) {
        // Test XML parsing with quick-xml
        use quick_xml::de::from_str;
        let _result: Result<serde_json::Value, _> = from_str(xml_str);
    }
});