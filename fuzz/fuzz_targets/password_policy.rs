#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::services::password_policy::PasswordPolicy;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Convert fuzzer input to string for password validation
    if let Ok(password) = std::str::from_utf8(data) {
        let policy = PasswordPolicy::default();
        let _ = policy.validate(password);
    }
});