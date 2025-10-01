# Shamir Secret Sharing - Quick Start Guide

## 🚀 Usage Examples

### Basic Usage (3-of-5 threshold)

```rust
use authenc::crypto::shamir::{
    generate_shares_with_commitments,
    reconstruct_secret_verified,
    validate_shares,
    ShamirConfig,
};

// 1. Generate shares
let secret = b"my-secret-key-32-bytes-long!!!";
let config = ShamirConfig::recommended(); // 3-of-5

let (mut shares, commitment) = generate_shares_with_commitments(secret, &config)?;

// 2. Validate shares
validate_shares(&mut shares)?;

// 3. Distribute shares to different locations
// Share 1 -> Location A
// Share 2 -> Location B
// Share 3 -> Location C
// Share 4 -> Location D
// Share 5 -> Location E

// 4. Reconstruct (need any 3 shares)
let recovered = reconstruct_secret_verified(&shares[..3], &commitment)?;
assert_eq!(recovered, secret);
```

### High Security (5-of-7 threshold)

```rust
let config = ShamirConfig::high_security(); // 5-of-7
let (mut shares, commitment) = generate_shares_with_commitments(secret, &config)?;
validate_shares(&mut shares)?;

// Distribute 7 shares, need any 5 to reconstruct
```

### Custom Configuration

```rust
let config = ShamirConfig::new(4, 6)?; // 4-of-6
let (mut shares, commitment) = generate_shares_with_commitments(secret, &config)?;
```

### Serialization for Storage

```rust
// Serialize shares
let share_bytes = shares[0].to_bytes()?;
std::fs::write("share1.bin", share_bytes)?;

// Serialize commitment
let commit_bytes = commitment.to_bytes()?;
std::fs::write("commitment.bin", commit_bytes)?;

// Later: Deserialize
use authenc::crypto::shamir::{Share, Commitment};

let share_bytes = std::fs::read("share1.bin")?;
let mut share = Share::from_bytes(&share_bytes)?;

let commit_bytes = std::fs::read("commitment.bin")?;
let commitment = Commitment::from_bytes(&commit_bytes)?;
```

### Verification Without Reconstruction

```rust
use authenc::crypto::shamir::verify_share_with_commitment;

// Verify individual shares
for share in &shares {
    verify_share_with_commitment(share, &commitment)?;
}
```

### Large Data Encryption Pattern

```rust
use rand::RngCore;

// 1. Generate symmetric key
let mut symmetric_key = [0u8; 32];
rand::rngs::OsRng.fill_bytes(&mut symmetric_key);

// 2. Encrypt large data with AES-GCM
let encrypted_data = aes_gcm_encrypt(large_data, &symmetric_key)?;

// 3. Split only the key with Shamir
let config = ShamirConfig::recommended();
let (mut shares, commitment) = generate_shares_with_commitments(&symmetric_key, &config)?;
validate_shares(&mut shares)?;

// 4. Store encrypted data in database
store_encrypted_data(encrypted_data)?;

// 5. Distribute key shares to different locations
distribute_shares(shares)?;

// Later: Reconstruct key and decrypt
let recovered_key = reconstruct_secret_verified(&shares[..3], &commitment)?;
let decrypted_data = aes_gcm_decrypt(&encrypted_data, &recovered_key)?;
```

## ⚡ Performance Guidelines

### Secret Size Recommendations

| Secret Size | Time (3-of-5) | Recommendation |
|------------|---------------|----------------|
| 32 bytes   | ~0.5s         | ✅ Ideal |
| 64 bytes   | ~1s           | ✅ Good |
| 128 bytes  | ~2s           | ✅ Acceptable |
| 256 bytes  | ~5s           | ⚠️ Use for keys only |
| > 1KB      | > 20s         | ❌ Encrypt first! |

### Threshold Configuration

| Use Case | Configuration | Shares | Threshold |
|----------|--------------|--------|-----------|
| Development | `new(2, 3)` | 3 | 2 |
| Production | `recommended()` | 5 | 3 |
| High Security | `high_security()` | 7 | 5 |
| Custom | `new(t, n)` | n | t |

## 🔒 Security Best Practices

### 1. Share Distribution

```rust
// ❌ BAD: Don't store all shares together
let all_shares = vec![share1, share2, share3, share4, share5];
database.store("shares", all_shares); // INSECURE!

// ✅ GOOD: Distribute to different locations
hsm_1.store(share1);           // Hardware Security Module
cloud_vault.store(share2);     // Cloud KMS
offline_storage.store(share3); // Cold storage
admin_device.store(share4);    // Authorized device
backup_location.store(share5); // Secure backup
```

### 2. Access Control

```rust
// Implement access controls
fn reconstruct_secret_with_auth(
    shares: &[Share],
    commitment: &Commitment,
    auth_token: &AuthToken,
) -> Result<Vec<u8>> {
    // 1. Verify authentication
    verify_auth_token(auth_token)?;
    
    // 2. Log access attempt
    audit_log::record_reconstruction_attempt(auth_token.user_id)?;
    
    // 3. Rate limit
    rate_limiter.check_limit(auth_token.user_id)?;
    
    // 4. Reconstruct
    let secret = reconstruct_secret_verified(shares, commitment)?;
    
    // 5. Log success
    audit_log::record_reconstruction_success(auth_token.user_id)?;
    
    Ok(secret)
}
```

### 3. Error Handling

```rust
use authenc::crypto::shamir::ShamirError;

match generate_shares_with_commitments(secret, &config) {
    Ok((shares, commitment)) => {
        // Success
    }
    Err(ShamirError::SecretTooLarge) => {
        // Use encryption pattern for large data
    }
    Err(ShamirError::InvalidThreshold) => {
        // Invalid configuration
    }
    Err(e) => {
        // Other errors
        log::error!("Shamir error: {}", e);
    }
}
```

## 🧪 Testing Examples

### Unit Test Template

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_custom_scenario() {
        let secret = b"test-secret";
        let config = ShamirConfig::new(2, 3).unwrap();
        
        let (mut shares, commitment) = 
            generate_shares_with_commitments(secret, &config).unwrap();
        validate_shares(&mut shares).unwrap();
        
        // Verify all shares
        for share in &shares {
            assert!(verify_share_with_commitment(share, &commitment).is_ok());
        }
        
        // Reconstruct
        let recovered = reconstruct_secret_verified(&shares[..2], &commitment).unwrap();
        assert_eq!(recovered, secret);
    }
}
```

### Integration Test

```rust
#[tokio::test]
async fn test_distributed_reconstruction() {
    let secret = b"production-key";
    let config = ShamirConfig::recommended();
    
    // Generate
    let (mut shares, commitment) = 
        generate_shares_with_commitments(secret, &config).unwrap();
    validate_shares(&mut shares).unwrap();
    
    // Simulate distributed storage
    let location_a = store_share_remotely(&shares[0], "location-a").await.unwrap();
    let location_b = store_share_remotely(&shares[1], "location-b").await.unwrap();
    let location_c = store_share_remotely(&shares[2], "location-c").await.unwrap();
    
    // Simulate distributed retrieval
    let retrieved_shares = vec![
        retrieve_share_from(location_a).await.unwrap(),
        retrieve_share_from(location_b).await.unwrap(),
        retrieve_share_from(location_c).await.unwrap(),
    ];
    
    // Reconstruct
    let recovered = reconstruct_secret_verified(&retrieved_shares, &commitment).unwrap();
    assert_eq!(recovered, secret);
}
```

## 🛡️ Error Types Reference

```rust
pub enum ShamirError {
    InsufficientShares,      // Not enough shares to reconstruct
    InvalidShare,            // Share format corrupted
    InvalidShareIndex,       // Share index out of range
    SecretTooLarge,         // Secret exceeds 16MB limit
    EmptySecret,            // Secret is empty
    InvalidThreshold,       // Threshold < 2 or > 255
    InvalidShareCount,      // Share count ≤ threshold or > 255
    ShareVerificationFailed,// Feldman verification failed (tampered)
    IntegrityCheckFailed,   // Commitment integrity failed
    UnsupportedVersion,     // Protocol version mismatch
    SerializationError,     // Serialization failed
    ShareNotValidated,      // Must call validate() first
    InvalidCommitment,      // Commitment data invalid
    CommitmentTooLarge,     // Commitment exceeds 100MB (DoS)
}
```

## 📊 Monitoring & Alerts

### Metrics to Track

```rust
// Reconstruction attempts
metrics::counter!("shamir.reconstruction.attempts").increment(1);

// Reconstruction failures
metrics::counter!("shamir.reconstruction.failures").increment(1);

// Verification time
let start = Instant::now();
verify_share_with_commitment(share, commitment)?;
metrics::histogram!("shamir.verification.duration_ms")
    .record(start.elapsed().as_millis());
```

### Alert Conditions

- More than 5 failed reconstructions in 1 hour
- Reconstruction attempts from unusual locations
- Verification failures > 10% rate
- Reconstruction duration > 30 seconds

## 🔗 Related Documentation

- [Security Audit Report](./SHAMIR_SECURITY_AUDIT.md)
- [Cryptographic Specifications](./CRYPTO_SPECS.md)
- [Deployment Guide](./DEPLOYMENT.md)

## 📞 Support

For security issues, contact: security@example.com  
For general support: support@example.com
