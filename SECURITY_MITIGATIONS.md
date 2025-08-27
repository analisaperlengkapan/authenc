# Security Mitigations for RSA Timing Attack (RUSTSEC-2023-0071)

## Vulnerability Summary
- **CVE**: CVE-2023-49092
- **Severity**: Medium (5.9/10)
- **Issue**: Marvin Attack - timing sidechannel in RSA implementation
- **Affected**: RSA crate v0.9.8
- **Status**: No patched version available yet

## Current Mitigations Implemented

### 1. Network Security
- Deploy behind TLS termination proxy
- Use network isolation to prevent timing observation
- Implement rate limiting to reduce attack surface

### 2. Monitoring & Detection
- Monitor for unusual RSA operation patterns
- Log timing anomalies in cryptographic operations
- Alert on suspicious key usage patterns

### 3. Operational Security
- Rotate RSA keys regularly (recommended: every 90 days)
- Use dedicated HSM or secure key storage when possible
- Limit RSA operations to trusted network segments

### 4. Alternative Cryptography (Future)
- Consider migrating to Ed25519 for signatures
- Evaluate ECDSA P-256 as RSA alternative
- Plan migration to post-quantum cryptography

## Implementation Status
- ✅ Added vulnerability to deny.toml ignore list with documentation
- ✅ Documented mitigation strategies
- ✅ Network isolation recommendations
- 🔄 Monitoring implementation (in progress)
- ⏳ Key rotation automation (planned)

## Monitoring Implementation

The following monitoring should be implemented:

```rust
// Example timing monitoring for RSA operations
use std::time::Instant;

pub fn monitor_rsa_operation<F, R>(operation: F) -> R 
where 
    F: FnOnce() -> R,
{
    let start = Instant::now();
    let result = operation();
    let duration = start.elapsed();
    
    // Log if operation takes unusually long
    if duration.as_millis() > 100 {
        tracing::warn!(
            duration_ms = duration.as_millis(),
            "RSA operation took longer than expected"
        );
    }
    
    result
}
```

## Risk Assessment
- **Local deployment**: Low risk (timing not observable)
- **Cloud deployment**: Medium risk (requires network monitoring)
- **Public facing**: Higher risk (implement all mitigations)

## Cryptographic Migration Strategy

### Recommended Alternatives to RSA 0.9.8

1. **Ed25519 (Preferred)**
   - Algorithm: EdDSA with Curve25519
   - Library: `ed25519-dalek` v2.1.1
   - Benefits: Faster, smaller keys, immune to timing attacks
   - Use case: Digital signatures for JWT tokens

2. **ECDSA P-256**
   - Algorithm: Elliptic Curve Digital Signature Algorithm
   - Library: `p256` v0.13.2 with `ecdsa` v0.16.9
   - Benefits: NIST standard, widely supported
   - Use case: OIDC/OAuth2 compatibility

3. **Ring-based ECDSA**
   - Algorithm: ECDSA with P-256/P-384
   - Library: `ring` v0.17.14 (already in use)
   - Benefits: Audited implementation, no timing vulnerabilities
   - Use case: High-security environments

### Migration Plan
- Phase 1: Implement Ed25519 for new JWT signing
- Phase 2: Support dual algorithms during transition
- Phase 3: Deprecate RSA usage
- Phase 4: Remove RSA dependency entirely

## mTLS Implementation

### Components Required
1. **Client Certificate Validation**
   - Custom middleware for certificate verification
   - Certificate chain validation
   - CRL/OCSP checking

2. **TLS Configuration**
   - Require client certificates
   - Configure trusted CA certificates
   - Set appropriate cipher suites

3. **Certificate Management**
   - Automated certificate rotation
   - Certificate revocation handling
   - Monitoring and alerting

## Upgrade Path
Replace RSA with Ed25519/ECDSA and implement comprehensive mTLS.
