#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::crypto::aes_gcm::AesGcmService;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let service = AesGcmService::new();

    // Test encryption
    if let Ok(encrypted) = service.encrypt(data) {
        // Test decryption
        let _ = service.decrypt(&encrypted);
    }
});