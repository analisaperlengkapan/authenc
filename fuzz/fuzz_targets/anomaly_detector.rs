#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::services::anomaly_detector::{AnomalyDetector, AnomalyDetectorTrait};

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let detector = AnomalyDetector::new();

    // Split data into user_id and ip
    let split_point = data.len() / 2;
    let user_id_bytes = &data[0..split_point];
    let ip_bytes = &data[split_point..];

    if let (Ok(user_id), Ok(ip)) = (
        std::str::from_utf8(user_id_bytes),
        std::str::from_utf8(ip_bytes)
    ) {
        // Test anomaly detection
        let _ = detector.is_new_ip(user_id, ip);
        // Test again with same IP (should return false)
        let _ = detector.is_new_ip(user_id, ip);
    }
});