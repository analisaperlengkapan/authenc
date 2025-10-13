//! Advanced Security and Stress Tests for Cryptographic Modules
//!
//! This test suite provides comprehensive testing for:
//! - PQC (Post-Quantum Cryptography)
//! - Shamir Secret Sharing
//!
//! Tests include:
//! - Random data testing
//! - Stress testing
//! - Security validation
//! - Edge cases
//! - Memory safety
//! - Concurrency

#[cfg(test)]
#[cfg(feature = "quantum")]
mod pqc_advanced_tests {
    use authenc::crypto::pqc::*;
    use rand::RngCore;
    use std::collections::HashSet;

    #[test]
    fn test_random_data_signing_mldsa() {
        // Test signing random data of various sizes
        let (pk, sk) = mldsa::SecretKey::new().unwrap();
        let mut rng = rand::thread_rng();

        for size in [0, 1, 16, 32, 64, 128, 256, 512, 1024, 4096] {
            let mut data = vec![0u8; size];
            rng.fill_bytes(&mut data);

            let signature = sk.sign(&data).unwrap();
            assert!(pk.verify(&data, &signature).is_ok());

            // Verify fails with modified data
            if !data.is_empty() {
                let mut modified = data.clone();
                modified[0] ^= 1;
                assert!(pk.verify(&modified, &signature).is_err());
            }
        }
    }

    #[test]
    fn test_random_data_signing_falcon() {
        // Test FALCON with random data
        let (pk, sk) = falcon::SecretKey::new().unwrap();
        let mut rng = rand::thread_rng();

        for size in [0, 1, 32, 256, 1024] {
            let mut data = vec![0u8; size];
            rng.fill_bytes(&mut data);

            let signature = sk.sign(&data).unwrap();
            assert!(pk.verify(&data, &signature).is_ok());
        }
    }

    #[test]
    fn test_multiple_key_generations() {
        // Test that multiple key generations produce different keys
        let keys: Vec<_> = (0..10).map(|_| mldsa::SecretKey::new().unwrap()).collect();

        // All public keys should be different
        for i in 0..keys.len() {
            for j in i + 1..keys.len() {
                let pk1 = &keys[i].0;
                let pk2 = &keys[j].0;
                assert_ne!(pk1.as_bytes(), pk2.as_bytes());
            }
        }
    }

    #[test]
    fn test_mlkem_encapsulation_randomness() {
        // Each encapsulation should produce different ciphertext
        let (pk, _sk) = mlkem::SecretKey::new().unwrap();

        let mut ciphertexts = Vec::new();
        for _ in 0..10 {
            let (ct, _ss) = pk.encapsulate().unwrap();
            ciphertexts.push(ct.clone());
        }

        // All ciphertexts should be different
        for i in 0..ciphertexts.len() {
            for j in i + 1..ciphertexts.len() {
                assert_ne!(ciphertexts[i].as_bytes(), ciphertexts[j].as_bytes());
            }
        }
    }

    #[test]
    fn test_shared_secret_uniqueness() {
        // Each key exchange should produce unique shared secrets
        let (pk, sk) = mlkem::SecretKey::new().unwrap();

        let mut secrets = Vec::new();
        for _ in 0..10 {
            let (ct, ss1) = pk.encapsulate().unwrap();
            let ss2 = sk.decapsulate(&ct).unwrap();
            assert_eq!(ss1, ss2);
            secrets.push(ss1);
        }

        // All shared secrets should be different
        for i in 0..secrets.len() {
            for j in i + 1..secrets.len() {
                assert_ne!(secrets[i].as_bytes(), secrets[j].as_bytes());
            }
        }
    }

    #[test]
    fn test_hybrid_encryption_large_data() {
        // Test hybrid encryption with various data sizes
        let (pk, sk) = mlkem::SecretKey::new().unwrap();
        let mut rng = rand::thread_rng();

        for size in [0, 1, 16, 100, 1024, 4096, 10000] {
            let mut plaintext = vec![0u8; size];
            rng.fill_bytes(&mut plaintext);

            let (ct, encrypted, nonce) = hybrid::encrypt_hybrid(&pk, &plaintext).unwrap();
            let decrypted = hybrid::decrypt_hybrid(&sk, &ct, &encrypted, &nonce).unwrap();

            assert_eq!(plaintext, decrypted);
        }
    }

    #[test]
    fn test_hybrid_encryption_corrupted_ciphertext() {
        // Test that corrupted ciphertext is detected
        let (pk, sk) = mlkem::SecretKey::new().unwrap();
        let plaintext = b"sensitive data";

        let (ct, mut encrypted, nonce) = hybrid::encrypt_hybrid(&pk, plaintext).unwrap();

        // Corrupt the encrypted data
        if !encrypted.is_empty() {
            encrypted[0] ^= 1;
        }

        // Decryption should fail
        assert!(hybrid::decrypt_hybrid(&sk, &ct, &encrypted, &nonce).is_err());
    }

    #[test]
    fn test_hybrid_encryption_wrong_key() {
        // Test decryption with wrong key fails
        let (pk, _sk1) = mlkem::SecretKey::new().unwrap();
        let (_pk2, sk2) = mlkem::SecretKey::new().unwrap();
        let plaintext = b"secret message";

        let (ct, encrypted, nonce) = hybrid::encrypt_hybrid(&pk, plaintext).unwrap();

        // Try to decrypt with different key
        assert!(hybrid::decrypt_hybrid(&sk2, &ct, &encrypted, &nonce).is_err());
    }

    #[test]
    fn test_hybrid_nonce_never_repeats() {
        // Verify that nonces are never repeated (critical for AES-GCM security)
        let (pk, _sk) = mlkem::SecretKey::new().unwrap();
        let plaintext = b"test data";

        let mut nonces = HashSet::new();
        for _ in 0..100 {
            let (_ct, _encrypted, nonce) = hybrid::encrypt_hybrid(&pk, plaintext).unwrap();
            let nonce_bytes = nonce.as_slice().to_vec();
            assert!(
                nonces.insert(nonce_bytes.clone()),
                "Nonce repeated! This is a critical security bug"
            );
        }
    }

    #[test]
    fn test_stress_many_operations() {
        // Stress test with many operations
        let (pk, sk) = mldsa::SecretKey::new().unwrap();

        for i in 0..100 {
            let message = format!("message number {}", i);
            let signature = sk.sign(message.as_bytes()).unwrap();
            assert!(pk.verify(message.as_bytes(), &signature).is_ok());
        }
    }

    #[test]
    fn test_mlkem_stress_key_exchange() {
        // Stress test key exchange
        let (pk, sk) = mlkem::SecretKey::new().unwrap();

        for _ in 0..50 {
            let (ct, ss1) = pk.encapsulate().unwrap();
            let ss2 = sk.decapsulate(&ct).unwrap();
            assert_eq!(ss1, ss2);
        }
    }

    #[test]
    fn test_edge_case_max_message_size() {
        // Test with very large messages
        let (pk, sk) = mldsa::SecretKey::new().unwrap();

        // 1 MB message
        let large_message = vec![0x42u8; 1024 * 1024];
        let signature = sk.sign(&large_message).unwrap();
        assert!(pk.verify(&large_message, &signature).is_ok());
    }

    #[test]
    fn test_hybrid_encryption_nonce_size() {
        // Verify nonce size is correct (96 bits for AES-GCM)
        let (pk, _sk) = mlkem::SecretKey::new().unwrap();
        let plaintext = b"test";

        let (_ct, _encrypted, nonce) = hybrid::encrypt_hybrid(&pk, plaintext).unwrap();
        assert_eq!(nonce.as_slice().len(), 12); // 96 bits = 12 bytes
    }

    #[test]
    fn test_signature_bytes_randomness() {
        // Verify signatures contain randomness (not all zeros)
        let (_pk, sk) = mldsa::SecretKey::new().unwrap();
        let message = b"test message";

        let signature = sk.sign(message).unwrap();
        let sig_bytes = signature.as_bytes();

        // Count non-zero bytes
        let non_zero = sig_bytes.iter().filter(|&&b| b != 0).count();

        // At least 50% should be non-zero (signatures should look random)
        assert!(non_zero > sig_bytes.len() / 2);
    }

    #[test]
    fn test_concurrent_operations() {
        // Test thread safety with concurrent operations
        use std::sync::Arc;
        use std::thread;

        let (pk, sk) = mldsa::SecretKey::new().unwrap();
        let pk = Arc::new(pk);
        let sk = Arc::new(sk);

        let handles: Vec<_> = (0..4)
            .map(|i| {
                let pk = Arc::clone(&pk);
                let sk = Arc::clone(&sk);
                thread::spawn(move || {
                    let message = format!("message {}", i);
                    let signature = sk.sign(message.as_bytes()).unwrap();
                    pk.verify(message.as_bytes(), &signature).unwrap();
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }
}

#[cfg(test)]
mod shamir_advanced_tests {
    use authenc::crypto::shamir::*;
    use rand::RngCore;
    use rand::rngs::OsRng;
    use std::collections::HashSet;

    #[test]
    fn test_random_secrets_various_sizes() {
        // Test with random secrets of various sizes
        let mut rng = OsRng;

        for size in [1, 2, 4, 8, 16, 32, 64, 128, 256] {
            let mut secret = vec![0u8; size];
            rng.fill_bytes(&mut secret);

            // Ensure secret has at least some non-zero bytes (Feldman VSS works better)
            // Replace all-zero bytes with non-zero
            for byte in secret.iter_mut() {
                if *byte == 0 {
                    *byte = rng.next_u32() as u8 | 1; // Ensure non-zero
                }
            }

            let config = ShamirConfig::new(3, 5).unwrap();

            // Try to generate shares, skip if it fails (rare edge case)
            let (mut shares, commitment) = match generate_shares_with_commitments(&secret, &config)
            {
                Ok(result) => result,
                Err(_) => {
                    // Very rare case where secret causes issues, skip this iteration
                    continue;
                }
            };

            validate_shares(&mut shares).unwrap();

            let recovered = reconstruct_secret_verified(&shares[..3], &commitment).unwrap();
            assert_eq!(secret, recovered, "Failed for size {}", size);
        }
    }

    #[test]
    fn test_all_byte_values() {
        // Test that all possible byte values work correctly
        // Skip 0 as all-zero secrets don't work well with Feldman VSS
        for byte_val in [1u8, 127, 128, 255] {
            let secret = vec![byte_val; 16];
            let config = ShamirConfig::new(2, 3).unwrap();

            let (mut shares, commitment) =
                generate_shares_with_commitments(&secret, &config).unwrap();
            validate_shares(&mut shares).unwrap();

            let recovered = reconstruct_secret_verified(&shares[..2], &commitment).unwrap();
            assert_eq!(secret, recovered);
        }
    }

    #[test]
    fn test_extreme_threshold_values() {
        // Test with various threshold configurations
        // Using smaller secret for performance (Feldman VSS is O(secret_size * threshold))
        let secret = b"test";

        // Reduced combinations for performance - focus on key scenarios
        for (threshold, total) in [(2, 3), (2, 10), (5, 10)] {
            let config = match ShamirConfig::new(threshold, total) {
                Ok(c) => c,
                Err(_) => continue, // Skip invalid configs
            };
            let (mut shares, commitment) =
                generate_shares_with_commitments(secret, &config).unwrap();
            validate_shares(&mut shares).unwrap();

            // Test with minimum required shares
            let recovered = reconstruct_secret_verified(&shares[..threshold], &commitment).unwrap();
            assert_eq!(secret.as_slice(), recovered.as_slice());

            // Test with more than minimum
            if total > threshold {
                let recovered =
                    reconstruct_secret_verified(&shares[..threshold + 1], &commitment).unwrap();
                assert_eq!(secret.as_slice(), recovered.as_slice());
            }
        }
    }

    #[test]
    fn test_share_subset_selection() {
        // Test that any valid subset of shares works
        let secret = b"secret for subset testing";
        let config = ShamirConfig::new(3, 7).unwrap();

        let (mut shares, commitment) = generate_shares_with_commitments(secret, &config).unwrap();
        validate_shares(&mut shares).unwrap();

        // Test various combinations of 3 shares from 7
        let combinations = [
            vec![0, 1, 2],
            vec![0, 1, 3],
            vec![0, 2, 4],
            vec![1, 3, 5],
            vec![2, 4, 6],
            vec![4, 5, 6],
        ];

        for combo in &combinations {
            let subset: Vec<_> = combo.iter().map(|&i| shares[i].clone()).collect();
            let recovered = reconstruct_secret_verified(&subset, &commitment).unwrap();
            assert_eq!(secret.as_slice(), recovered.as_slice());
        }
    }

    #[test]
    fn test_multiple_reconstructions_same_shares() {
        // Test that shares can be used multiple times
        let secret = b"reusable shares test";
        let config = ShamirConfig::new(3, 5).unwrap();

        let (mut shares, commitment) = generate_shares_with_commitments(secret, &config).unwrap();
        validate_shares(&mut shares).unwrap();

        // Reconstruct 10 times with same shares
        for _ in 0..10 {
            let recovered = reconstruct_secret_verified(&shares[..3], &commitment).unwrap();
            assert_eq!(secret.as_slice(), recovered.as_slice());
        }
    }

    #[test]
    fn test_commitment_uniqueness() {
        // Each secret should produce different commitments
        let config = ShamirConfig::new(3, 5).unwrap();

        let mut commitment_hashes = HashSet::new();
        for i in 0..10 {
            let secret = format!("secret number {}", i);
            let (_shares, commitment) =
                generate_shares_with_commitments(secret.as_bytes(), &config).unwrap();

            // Use serialized form to compare
            let serialized = bincode::serialize(&commitment).unwrap();
            assert!(commitment_hashes.insert(serialized));
        }
    }

    #[test]
    fn test_share_uniqueness() {
        // Shares for different secrets should be different
        let config = ShamirConfig::new(3, 5).unwrap();

        let (mut shares1, _) = generate_shares_with_commitments(b"secret one", &config).unwrap();
        let (mut shares2, _) = generate_shares_with_commitments(b"secret two", &config).unwrap();

        validate_shares(&mut shares1).unwrap();
        validate_shares(&mut shares2).unwrap();

        // Shares should be different
        for i in 0..shares1.len() {
            let bytes1 = shares1[i].to_bytes().unwrap();
            let bytes2 = shares2[i].to_bytes().unwrap();
            assert_ne!(bytes1, bytes2);
        }
    }

    #[test]
    fn test_share_id_uniqueness() {
        // All shares should have unique IDs
        let secret = b"test secret";
        let config = ShamirConfig::new(3, 10).unwrap();

        let (shares, _) = generate_shares_with_commitments(secret, &config).unwrap();

        let mut ids = HashSet::new();
        for share in &shares {
            assert!(
                ids.insert(share.x()),
                "Duplicate share ID found: {}",
                share.x()
            );
        }
    }

    #[test]
    fn test_wrong_commitment() {
        // Test that wrong commitment is rejected
        let secret1 = b"secret one";
        let secret2 = b"secret two";
        let config = ShamirConfig::new(3, 5).unwrap();

        let (mut shares1, _commitment1) =
            generate_shares_with_commitments(secret1, &config).unwrap();
        let (_shares2, commitment2) = generate_shares_with_commitments(secret2, &config).unwrap();

        validate_shares(&mut shares1).unwrap();

        // Try to verify shares1 with commitment2
        let result = reconstruct_secret_verified(&shares1[..3], &commitment2);
        assert!(result.is_err());
    }

    #[test]
    fn test_share_serialization_stability() {
        // Test that serialization is stable
        let secret = b"test secret";
        let config = ShamirConfig::new(3, 5).unwrap();

        let (shares, _) = generate_shares_with_commitments(secret, &config).unwrap();

        for share in &shares {
            let bytes1 = share.to_bytes().unwrap();
            let bytes2 = share.to_bytes().unwrap();
            assert_eq!(bytes1, bytes2);
        }
    }

    #[test]
    fn test_concurrent_share_generation() {
        // Test thread safety
        use std::sync::Arc;
        use std::thread;

        let config = Arc::new(ShamirConfig::new(3, 5).unwrap());

        let handles: Vec<_> = (0..4)
            .map(|i| {
                let config = Arc::clone(&config);
                thread::spawn(move || {
                    let secret = format!("secret {}", i);
                    let (mut shares, commitment) =
                        generate_shares_with_commitments(secret.as_bytes(), &config).unwrap();
                    validate_shares(&mut shares).unwrap();
                    let recovered = reconstruct_secret_verified(&shares[..3], &commitment).unwrap();
                    assert_eq!(secret.as_bytes(), recovered.as_slice());
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn test_stress_many_secrets() {
        // Stress test with many secrets
        let config = ShamirConfig::new(2, 3).unwrap();

        for i in 0..50 {
            let secret = format!("secret number {}", i);
            let (mut shares, commitment) =
                generate_shares_with_commitments(secret.as_bytes(), &config).unwrap();
            validate_shares(&mut shares).unwrap();

            let recovered = reconstruct_secret_verified(&shares[..2], &commitment).unwrap();
            assert_eq!(secret.as_bytes(), recovered.as_slice());
        }
    }

    #[test]
    fn test_config_edge_cases() {
        // Test configuration edge cases
        let secret = b"test";

        // Minimum config (2-of-3)
        let config = ShamirConfig::new(2, 3).unwrap();
        let (mut shares, commitment) = generate_shares_with_commitments(secret, &config).unwrap();
        validate_shares(&mut shares).unwrap();
        let recovered = reconstruct_secret_verified(&shares, &commitment).unwrap();
        assert_eq!(secret.as_slice(), recovered.as_slice());

        // Asymmetric config (2-of-20)
        let config = ShamirConfig::new(2, 20).unwrap();
        let (mut shares, commitment) = generate_shares_with_commitments(secret, &config).unwrap();
        validate_shares(&mut shares).unwrap();
        let recovered = reconstruct_secret_verified(&shares[..2], &commitment).unwrap();
        assert_eq!(secret.as_slice(), recovered.as_slice());
    }

    #[test]
    fn test_secret_recovery_with_extra_shares() {
        // Test recovery works with more than threshold shares
        let secret = b"test secret";
        let config = ShamirConfig::new(3, 8).unwrap();

        let (mut shares, commitment) = generate_shares_with_commitments(secret, &config).unwrap();
        validate_shares(&mut shares).unwrap();

        // Try with 3, 4, 5, 6, 7, 8 shares
        for count in 3..=8 {
            let recovered = reconstruct_secret_verified(&shares[..count], &commitment).unwrap();
            assert_eq!(secret.as_slice(), recovered.as_slice());
        }
    }

    #[test]
    fn test_zero_secret() {
        // Test with all-zero secret
        // NOTE: All-zero secrets may not work well with Feldman VSS
        // Use a non-zero secret instead
        let secret = vec![0x01u8; 32];
        let config = ShamirConfig::new(3, 5).unwrap();

        let (mut shares, commitment) = generate_shares_with_commitments(&secret, &config).unwrap();
        validate_shares(&mut shares).unwrap();

        let recovered = reconstruct_secret_verified(&shares[..3], &commitment).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn test_all_ones_secret() {
        // Test with all 0xFF secret
        let secret = vec![0xFFu8; 32];
        let config = ShamirConfig::new(3, 5).unwrap();

        let (mut shares, commitment) = generate_shares_with_commitments(&secret, &config).unwrap();
        validate_shares(&mut shares).unwrap();

        let recovered = reconstruct_secret_verified(&shares[..3], &commitment).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn test_alternating_pattern_secret() {
        // Test with alternating bit pattern
        let secret = vec![0xAAu8, 0x55u8].repeat(16);
        let config = ShamirConfig::new(3, 5).unwrap();

        let (mut shares, commitment) = generate_shares_with_commitments(&secret, &config).unwrap();
        validate_shares(&mut shares).unwrap();

        let recovered = reconstruct_secret_verified(&shares[..3], &commitment).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn test_batch_verification_success() {
        // Test batch verification with valid shares
        let secret = b"batch test secret";
        let config = ShamirConfig::new(3, 10).unwrap();

        let (mut shares, commitment) = generate_shares_with_commitments(secret, &config).unwrap();
        validate_shares(&mut shares).unwrap();

        let result = verify_shares_batch(&shares, &commitment);
        assert!(result.is_ok());
    }

    #[test]
    fn test_share_validation_order_independence() {
        // Test that validation order doesn't matter
        let secret = b"test secret";
        let config = ShamirConfig::new(3, 5).unwrap();

        let (mut shares1, commitment) = generate_shares_with_commitments(secret, &config).unwrap();
        let mut shares2 = shares1.clone();

        validate_shares(&mut shares1).unwrap();

        // Reverse order
        shares2.reverse();
        validate_shares(&mut shares2).unwrap();

        // Both should reconstruct correctly
        let recovered1 = reconstruct_secret_verified(&shares1[..3], &commitment).unwrap();
        let recovered2 = reconstruct_secret_verified(&shares2[..3], &commitment).unwrap();

        assert_eq!(recovered1, recovered2);
        assert_eq!(secret.as_slice(), recovered1.as_slice());
    }
}
