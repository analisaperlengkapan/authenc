#![no_main]

use libfuzzer_sys::fuzz_target;
use authenc::crypto::shamir::{generate_shares_with_commitments, reconstruct_secret, ShamirConfig};

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    let secret = &data[0..16];
    let threshold = (data.len() / 16).max(2).min(10) as usize;
    let num_shares = threshold + 1;

    // Create ShamirConfig
    if let Ok(config) = ShamirConfig::new(threshold, num_shares) {
        // Generate shares
        if let Ok((shares, _commitment)) = generate_shares_with_commitments(secret, &config) {
            // Try to reconstruct with enough shares
            let reconstruction_shares = &shares[0..threshold];
            let _ = reconstruct_secret(reconstruction_shares, threshold);
        }
    }
});