#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test base64 encoding/decoding
    use base64ct::{Base64, Encoding};

    // Encode the data
    let encoded = Base64::encode_string(data);

    // Try to decode it back
    let _decoded = Base64::decode_vec(&encoded);
});