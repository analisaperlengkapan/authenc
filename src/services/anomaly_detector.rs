use std::collections::HashMap;
use std::sync::Mutex;

/// Trait for anomaly detection functionality
pub trait AnomalyDetectorTrait: Send + Sync {
    /// Check if an IP address is new for a given user
    fn is_new_ip(&self, user_id: &str, ip: &str) -> Result<bool, String>;
}

/// Anomaly detector for tracking user IP addresses and detecting suspicious activity
pub struct AnomalyDetector {
    /// Map of user IDs to their known IP addresses for anomaly detection
    known_ips: Mutex<HashMap<String, Vec<String>>>,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyDetector {
    /// Create a new anomaly detector instance
    pub fn new() -> Self {
        Self {
            known_ips: Mutex::new(HashMap::new()),
        }
    }
}

impl AnomalyDetectorTrait for AnomalyDetector {
    /// Check if an IP address is new for a given user (implementation)
    fn is_new_ip(&self, user_id: &str, ip: &str) -> Result<bool, String> {
        let mut map = self
            .known_ips
            .lock()
            .map_err(|e| format!("Lock poisoned: {e}"))?;
        let ips = map.entry(user_id.to_string()).or_default();
        if !ips.contains(&ip.to_string()) {
            ips.push(ip.to_string());
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_anomaly_detector_creation() {
        let detector = AnomalyDetector::new();
        assert!(detector.known_ips.lock().unwrap().is_empty());
    }

    #[test]
    fn test_anomaly_detector_default() {
        let detector = AnomalyDetector::default();
        assert!(detector.known_ips.lock().unwrap().is_empty());
    }

    #[test]
    fn test_is_new_ip_first_ip() {
        let detector = AnomalyDetector::new();
        let result = detector.is_new_ip("user1", "192.168.1.1").unwrap();
        assert!(result); // First IP should be new

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), 1);
        assert!(ips.contains_key("user1"));
        assert_eq!(ips["user1"], vec!["192.168.1.1"]);
    }

    #[test]
    fn test_is_new_ip_existing_ip() {
        let detector = AnomalyDetector::new();

        // First call should return true (new IP)
        let result1 = detector.is_new_ip("user1", "192.168.1.1").unwrap();
        assert!(result1);

        // Second call with same IP should return false (not new)
        let result2 = detector.is_new_ip("user1", "192.168.1.1").unwrap();
        assert!(!result2);

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips["user1"], vec!["192.168.1.1"]);
    }

    #[test]
    fn test_is_new_ip_multiple_ips_same_user() {
        let detector = AnomalyDetector::new();

        // Add first IP
        let result1 = detector.is_new_ip("user1", "192.168.1.1").unwrap();
        assert!(result1);

        // Add second IP
        let result2 = detector.is_new_ip("user1", "192.168.1.2").unwrap();
        assert!(result2);

        // Check first IP again
        let result3 = detector.is_new_ip("user1", "192.168.1.1").unwrap();
        assert!(!result3);

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips["user1"], vec!["192.168.1.1", "192.168.1.2"]);
    }

    #[test]
    fn test_is_new_ip_different_users() {
        let detector = AnomalyDetector::new();

        // User 1
        let result1 = detector.is_new_ip("user1", "192.168.1.1").unwrap();
        assert!(result1);

        // User 2 with same IP
        let result2 = detector.is_new_ip("user2", "192.168.1.1").unwrap();
        assert!(result2); // Should be new for user2

        // User 1 with different IP
        let result3 = detector.is_new_ip("user1", "192.168.1.2").unwrap();
        assert!(result3);

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips["user1"], vec!["192.168.1.1", "192.168.1.2"]);
        assert_eq!(ips["user2"], vec!["192.168.1.1"]);
    }

    #[test]
    fn test_is_new_ip_empty_user_id() {
        let detector = AnomalyDetector::new();
        let result = detector.is_new_ip("", "192.168.1.1").unwrap();
        assert!(result);

        let ips = detector.known_ips.lock().unwrap();
        assert!(ips.contains_key(""));
        assert_eq!(ips[""], vec!["192.168.1.1"]);
    }

    #[test]
    fn test_is_new_ip_empty_ip() {
        let detector = AnomalyDetector::new();
        let result = detector.is_new_ip("user1", "").unwrap();
        assert!(result);

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips["user1"], vec![""]);
    }

    #[test]
    fn test_is_new_ip_special_characters() {
        let detector = AnomalyDetector::new();
        let result = detector
            .is_new_ip("user@domain.com", "2001:db8::1")
            .unwrap();
        assert!(result);

        let ips = detector.known_ips.lock().unwrap();
        assert!(ips.contains_key("user@domain.com"));
        assert_eq!(ips["user@domain.com"], vec!["2001:db8::1"]);
    }

    #[test]
    fn test_anomaly_detector_thread_safety() {
        let detector = Arc::new(AnomalyDetector::new());
        let mut handles = vec![];

        // Spawn multiple threads to test concurrent access
        for i in 0..10 {
            let detector_clone = Arc::clone(&detector);
            let handle = thread::spawn(move || {
                let user_id = format!("user{}", i % 3); // 3 different users
                let ip = format!("192.168.1.{}", i % 5); // 5 different IPs
                detector_clone.is_new_ip(&user_id, &ip).unwrap()
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify final state
        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), 3); // 3 users

        for i in 0..3 {
            let user_id = format!("user{}", i);
            assert!(ips.contains_key(&user_id));
            // Each user should have up to 5 IPs (some may be duplicates)
            assert!(ips[&user_id].len() <= 5);
        }
    }

    #[test]
    fn test_anomaly_detector_large_number_of_ips() {
        let detector = AnomalyDetector::new();

        // Add many IPs for one user
        for i in 0..1000 {
            let ip = format!("192.168.{}.{}", i / 256, i % 256);
            let result = detector.is_new_ip("user1", &ip).unwrap();
            assert!(result); // All should be new
        }

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips["user1"].len(), 1000);
    }

    #[test]
    fn test_anomaly_detector_debug() {
        let detector = AnomalyDetector::new();
        let _ = detector.is_new_ip("user1", "192.168.1.1").unwrap();

        let debug_str = format!("{:?}", detector.known_ips);
        assert!(debug_str.contains("Mutex"));
    }

    #[test]
    fn test_is_new_ip_ipv6_addresses() {
        let detector = AnomalyDetector::new();

        // Test various IPv6 formats
        let ipv6_addresses = vec![
            "2001:db8::1",
            "::1",
            "fe80::1%eth0",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "::ffff:192.0.2.1",
        ];

        for (i, ip) in ipv6_addresses.iter().enumerate() {
            let user_id = format!("user{}", i);
            let result = detector.is_new_ip(&user_id, ip).unwrap();
            assert!(result, "IPv6 address {} should be new", ip);
        }

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), ipv6_addresses.len());
    }

    #[test]
    fn test_is_new_ip_unicode_user_ids() {
        let detector = AnomalyDetector::new();

        let unicode_user_ids = vec![
            "用户1",        // Chinese
            "пользователь", // Russian
            "usuário",      // Portuguese with accent
            "ユーザー",     // Japanese
            "👤user",       // Emoji
            "café",         // French with accent
        ];

        for (i, user_id) in unicode_user_ids.iter().enumerate() {
            let ip = format!("192.168.1.{}", i + 1);
            let result = detector.is_new_ip(user_id, &ip).unwrap();
            assert!(result, "Unicode user ID '{}' should work", user_id);
        }

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), unicode_user_ids.len());
    }

    #[test]
    fn test_is_new_ip_very_long_inputs() {
        let detector = AnomalyDetector::new();

        // Very long user ID
        let long_user_id = "a".repeat(10000);
        let result1 = detector.is_new_ip(&long_user_id, "192.168.1.1").unwrap();
        assert!(result1);

        // Very long IP (not a valid IP, but should be handled)
        let long_ip = "1".repeat(1000);
        let result2 = detector.is_new_ip("user2", &long_ip).unwrap();
        assert!(result2);

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), 2);
        assert!(ips.contains_key(&long_user_id));
        assert!(ips.contains_key("user2"));
    }

    #[test]
    fn test_is_new_ip_whitespace_handling() {
        let detector = AnomalyDetector::new();

        // Test with whitespace in user ID and IP
        let result1 = detector.is_new_ip(" user1 ", " 192.168.1.1 ").unwrap();
        assert!(result1);

        // Same user/IP with different whitespace should be treated as different
        let result2 = detector.is_new_ip("user1", "192.168.1.1").unwrap();
        assert!(result2); // Different because whitespace is part of the string

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), 2);
        assert!(ips.contains_key(" user1 "));
        assert!(ips.contains_key("user1"));
    }

    #[test]
    fn test_is_new_ip_case_sensitivity() {
        let detector = AnomalyDetector::new();

        // User IDs are case sensitive
        let result1 = detector.is_new_ip("User1", "192.168.1.1").unwrap();
        assert!(result1);

        let result2 = detector.is_new_ip("user1", "192.168.1.1").unwrap();
        assert!(result2); // Different user (case sensitive)

        let result3 = detector.is_new_ip("USER1", "192.168.1.1").unwrap();
        assert!(result3); // Different user (case sensitive)

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), 3);
        assert!(ips.contains_key("User1"));
        assert!(ips.contains_key("user1"));
        assert!(ips.contains_key("USER1"));
    }

    #[test]
    fn test_is_new_ip_concurrent_different_patterns() {
        let detector = Arc::new(AnomalyDetector::new());
        let mut handles = vec![];

        // Pattern 1: Sequential IPs for same user
        let detector1 = Arc::clone(&detector);
        let handle1 = thread::spawn(move || {
            for i in 0..50 {
                let ip = format!("10.0.0.{}", i);
                let result = detector1.is_new_ip("user_a", &ip).unwrap();
                assert!(result, "IP {} should be new for user_a", ip);
            }
        });
        handles.push(handle1);

        // Pattern 2: Same IP for different users
        let detector2 = Arc::clone(&detector);
        let handle2 = thread::spawn(move || {
            for i in 0..50 {
                let user_id = format!("user_b_{}", i);
                let result = detector2.is_new_ip(&user_id, "192.168.1.100").unwrap();
                assert!(result, "IP should be new for user {}", user_id);
            }
        });
        handles.push(handle2);

        // Pattern 3: Random pattern
        let detector3 = Arc::clone(&detector);
        let handle3 = thread::spawn(move || {
            for i in 0..50 {
                let user_id = format!("user_c_{}", i % 10); // 10 users
                let ip = format!("172.16.{}.{}", i / 256, i % 256);
                let _ = detector3.is_new_ip(&user_id, &ip).unwrap();
                // Don't assert here as some might not be new due to randomness
            }
        });
        handles.push(handle3);

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify final state
        let ips = detector.known_ips.lock().unwrap();
        assert!(ips.contains_key("user_a"));
        assert_eq!(ips["user_a"].len(), 50); // All IPs should be unique

        // Check that user_b_* users exist
        let user_b_count = ips.keys().filter(|k| k.starts_with("user_b_")).count();
        assert_eq!(user_b_count, 50);

        // Check that user_c_* users exist
        let user_c_count = ips.keys().filter(|k| k.starts_with("user_c_")).count();
        assert_eq!(user_c_count, 10);
    }

    #[test]
    fn test_is_new_ip_memory_efficiency() {
        let detector = AnomalyDetector::new();

        // Add many users with few IPs each
        for i in 0..1000 {
            let user_id = format!("user_{}", i);
            let ip = format!("192.168.{}.1", i % 256);
            let result = detector.is_new_ip(&user_id, &ip).unwrap();
            assert!(result);
        }

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), 1000);

        // Each user should have exactly 1 IP
        for user_ips in ips.values() {
            assert_eq!(user_ips.len(), 1);
        }
    }

    #[test]
    fn test_is_new_ip_duplicate_ip_tracking() {
        let detector = AnomalyDetector::new();

        // Add the same IP multiple times for different users
        let shared_ip = "10.0.0.1";
        for i in 0..100 {
            let user_id = format!("user_{}", i);
            let result = detector.is_new_ip(&user_id, shared_ip).unwrap();
            assert!(result, "IP should be new for user {}", user_id);
        }

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), 100);

        // Each user should have the shared IP
        for user_ips in ips.values() {
            assert_eq!(user_ips.len(), 1);
            assert_eq!(user_ips[0], shared_ip);
        }
    }

    #[test]
    fn test_is_new_ip_mixed_operations() {
        let detector = AnomalyDetector::new();

        // Mix of operations: some new, some existing
        let operations = vec![
            ("user1", "192.168.1.1", true),  // new
            ("user1", "192.168.1.1", false), // existing
            ("user1", "192.168.1.2", true),  // new
            ("user2", "192.168.1.1", true),  // new (different user)
            ("user1", "192.168.1.2", false), // existing
            ("user2", "192.168.1.2", true),  // new
            ("user3", "192.168.1.1", true),  // new
        ];

        for (user_id, ip, expected_new) in operations {
            let result = detector.is_new_ip(user_id, ip).unwrap();
            assert_eq!(
                result, expected_new,
                "IP {} for user {} should be new={}",
                ip, user_id, expected_new
            );
        }

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), 3);
        assert_eq!(ips["user1"].len(), 2);
        assert_eq!(ips["user2"].len(), 2);
        assert_eq!(ips["user3"].len(), 1);
    }

    #[test]
    fn test_is_new_ip_null_bytes() {
        let detector = AnomalyDetector::new();

        // Test with null bytes in strings (potential attack vector)
        let result1 = detector.is_new_ip("user\x00null", "192.168.1.1").unwrap();
        assert!(result1);

        let result2 = detector.is_new_ip("user1", "192.168.1.\x001").unwrap();
        assert!(result2);

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), 2);
        assert!(ips.contains_key("user\x00null"));
        assert!(ips.contains_key("user1"));
    }

    #[test]
    fn test_is_new_ip_extreme_concurrency() {
        let detector = Arc::new(AnomalyDetector::new());
        let num_threads = 50;
        let operations_per_thread = 100;

        let mut handles = vec![];

        for thread_id in 0..num_threads {
            let detector_clone = Arc::clone(&detector);
            let handle = thread::spawn(move || {
                let mut results = vec![];

                for op in 0..operations_per_thread {
                    let user_id = format!("thread_{}_user_{}", thread_id, op % 10);
                    let ip = format!("10.{}.{}.{}", thread_id % 256, op % 256, op % 256);

                    match detector_clone.is_new_ip(&user_id, &ip) {
                        Ok(is_new) => results.push(is_new),
                        Err(e) => panic!("Error in thread {}: {}", thread_id, e),
                    }
                }

                results
            });
            handles.push(handle);
        }

        // Collect all results
        let mut all_results = vec![];
        for handle in handles {
            let thread_results = handle.join().unwrap();
            all_results.extend(thread_results);
        }

        // Should have many true results (new IPs/users)
        let true_count = all_results.iter().filter(|&&x| x).count();
        assert!(true_count > 0, "Should have some new IPs detected");

        // Verify final state is consistent
        let ips = detector.known_ips.lock().unwrap();
        assert!(ips.len() > 0);

        // Each user should have at least one IP
        for user_ips in ips.values() {
            assert!(!user_ips.is_empty());
        }
    }

    #[test]
    fn test_anomaly_detector_trait_implementation() {
        // Test that the trait implementation works correctly
        let detector = AnomalyDetector::new();
        let trait_ref: &dyn AnomalyDetectorTrait = &detector;

        let result = trait_ref.is_new_ip("test_user", "127.0.0.1").unwrap();
        assert!(result);

        let result2 = trait_ref.is_new_ip("test_user", "127.0.0.1").unwrap();
        assert!(!result2);
    }

    #[test]
    fn test_is_new_ip_private_ips() {
        let detector = AnomalyDetector::new();

        let private_ips = vec![
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "127.0.0.1",
            "169.254.0.1", // Link-local
        ];

        for (i, ip) in private_ips.iter().enumerate() {
            let user_id = format!("user{}", i);
            let result = detector.is_new_ip(&user_id, ip).unwrap();
            assert!(result, "Private IP {} should be handled correctly", ip);
        }

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), private_ips.len());
    }

    #[test]
    fn test_is_new_ip_invalid_ips() {
        let detector = AnomalyDetector::new();

        // These are not valid IPs but should still be handled
        let invalid_ips = vec![
            "999.999.999.999",
            "192.168.1.256",
            "not.an.ip.address",
            "",
            "192.168.1",
            "::gggg", // Invalid IPv6
        ];

        for (i, ip) in invalid_ips.iter().enumerate() {
            let user_id = format!("user{}", i);
            let result = detector.is_new_ip(&user_id, ip).unwrap();
            assert!(result, "Invalid IP '{}' should still be processed", ip);
        }

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), invalid_ips.len());
    }

    #[test]
    fn test_is_new_ip_memory_cleanup_simulation() {
        let detector = AnomalyDetector::new();

        // Simulate adding and "removing" users (by checking existing behavior)
        // In a real system, you might want to clean up old entries

        // Add some users
        for i in 0..10 {
            let user_id = format!("temp_user_{}", i);
            let result = detector.is_new_ip(&user_id, "192.168.1.1").unwrap();
            assert!(result);
        }

        let ips_before = detector.known_ips.lock().unwrap().len();
        assert_eq!(ips_before, 10);

        // In this simple implementation, users persist
        // A more advanced version might have cleanup logic
        let ips_after = detector.known_ips.lock().unwrap().len();
        assert_eq!(ips_after, 10);
    }

    #[test]
    fn test_anomaly_detector_clone_behavior() {
        // Test that the detector can be used in contexts requiring Send + Sync
        let detector = Arc::new(AnomalyDetector::new());

        let detector_clone = Arc::clone(&detector);
        let handle = thread::spawn(move || {
            let result = detector_clone
                .is_new_ip("thread_user", "192.168.1.1")
                .unwrap();
            assert!(result);
        });

        handle.join().unwrap();

        // Original detector should see the change
        let result = detector.is_new_ip("thread_user", "192.168.1.1").unwrap();
        assert!(!result); // Should not be new
    }

    #[test]
    fn test_is_new_ip_performance_characteristics() {
        let detector = AnomalyDetector::new();

        // Test that operations complete in reasonable time
        let start = std::time::Instant::now();

        for i in 0..10000 {
            let user_id = format!("perf_user_{}", i % 100); // 100 users
            let ip = format!("192.168.{}.{}", (i / 256) % 256, i % 256);
            let _ = detector.is_new_ip(&user_id, &ip).unwrap();
        }

        let elapsed = start.elapsed();
        // Should complete in reasonable time (less than 1 second for 10k operations)
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "Performance test took too long: {:?}",
            elapsed
        );

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), 100); // 100 users
    }

    #[test]
    fn test_is_new_ip_edge_case_empty_strings() {
        let detector = AnomalyDetector::new();

        // Test various combinations of empty/blank strings
        let test_cases = vec![
            ("", ""),
            ("", "192.168.1.1"),
            ("user1", ""),
            ("", " "),
            (" ", ""),
            (" ", " "),
        ];

        for (user_id, ip) in &test_cases {
            let result = detector.is_new_ip(user_id, ip).unwrap();
            assert!(
                result,
                "Empty/blank combination should work: user='{}', ip='{}'",
                user_id, ip
            );
        }

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), 3); // 3 unique user_ids: "", "user1", " "
    }

    #[test]
    fn test_anomaly_detector_multiple_instances() {
        // Test that multiple detector instances work independently
        let detector1 = AnomalyDetector::new();
        let detector2 = AnomalyDetector::new();

        // Same user/IP in different detectors should be independent
        let result1 = detector1.is_new_ip("user1", "192.168.1.1").unwrap();
        let result2 = detector2.is_new_ip("user1", "192.168.1.1").unwrap();

        assert!(result1);
        assert!(result2); // Should be new for detector2 too

        // Verify they don't share state
        let ips1 = detector1.known_ips.lock().unwrap();
        let ips2 = detector2.known_ips.lock().unwrap();

        assert_eq!(ips1.len(), 1);
        assert_eq!(ips2.len(), 1);
        assert_eq!(ips1["user1"], vec!["192.168.1.1"]);
        assert_eq!(ips2["user1"], vec!["192.168.1.1"]);
    }

    #[test]
    fn test_is_new_ip_rapid_succession() {
        let detector = AnomalyDetector::new();
        let user_id = "rapid_user";

        // First call should establish the IP
        let first_result = detector.is_new_ip(user_id, "192.168.1.1").unwrap();
        assert!(first_result); // First call should be new

        // Rapid succession of checks for the same user/IP - all should return false
        for _ in 0..1000 {
            let result = detector.is_new_ip(user_id, "192.168.1.1").unwrap();
            assert!(!result); // Should not be new after first call
        }

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips[user_id], vec!["192.168.1.1"]);
    }

    #[test]
    fn test_is_new_ip_user_id_reuse() {
        let detector = AnomalyDetector::new();

        // User ID that was used before but with different IPs
        let _ = detector.is_new_ip("user1", "192.168.1.1").unwrap();
        let _ = detector.is_new_ip("user1", "192.168.1.2").unwrap();

        // Later, same user with first IP again
        let result = detector.is_new_ip("user1", "192.168.1.1").unwrap();
        assert!(!result); // Should not be new

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips["user1"], vec!["192.168.1.1", "192.168.1.2"]);
    }

    #[test]
    fn test_anomaly_detector_drop_behavior() {
        // Test that the detector can be properly dropped
        {
            let detector = AnomalyDetector::new();
            let _ = detector.is_new_ip("user1", "192.168.1.1").unwrap();
            // Detector goes out of scope here
        }
        // Should not panic or cause issues
    }

    #[test]
    fn test_is_new_ip_max_reasonable_load() {
        let detector = AnomalyDetector::new();

        // Test with a large but reasonable number of unique combinations
        for user in 0..100 {
            for ip in 0..10 {
                let user_id = format!("user_{}", user);
                let ip_addr = format!("192.168.{}.{}", user % 256, ip);
                let result = detector.is_new_ip(&user_id, &ip_addr).unwrap();
                assert!(result, "IP {} should be new for user {}", ip_addr, user_id);
            }
        }

        let ips = detector.known_ips.lock().unwrap();
        assert_eq!(ips.len(), 100);

        for user_ips in ips.values() {
            assert_eq!(user_ips.len(), 10); // Each user should have 10 unique IPs
        }
    }
}
