use authenc::crypto::ecdsa_p521_keys::{ECDSA_P521_KEYPAIR, sign_jwt_p521, verify_jwt_p521};
use p521::ecdsa::VerifyingKey;

#[test]
fn test_p521_end_to_end_flow() {
    // 1. Define test data (Raw JSON, as sign_jwt_p521 encodes it)
    let header = r#"{"alg":"ES512"}"#;
    let payload = r#"{"sub":"test"}"#;

    // 2. Sign the JWT
    let token = sign_jwt_p521(header, payload).expect("Failed to sign JWT");

    // 3. Get the verifying key from the static keypair
    let verifying_key = VerifyingKey::from(&*ECDSA_P521_KEYPAIR);

    // 4. Verify the JWT
    let (decoded_header, decoded_payload) = verify_jwt_p521(&token, &verifying_key)
        .expect("Failed to verify JWT");

    // 5. Assertions
    assert_eq!(decoded_header, header);
    assert_eq!(decoded_payload, payload);
}
