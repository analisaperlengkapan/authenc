use authenc::services::security::brute_force_protector::BruteForceProtector;

#[test]
fn brute_force_detects_and_clears() {
    let protector = BruteForceProtector::new(3, 60);
    // 4 attempts => blocked (returns true for "exceeded")
    for _ in 0..3 {
        assert_eq!(protector.register_attempt("u1").unwrap(), false);
    }
    assert_eq!(protector.register_attempt("u1").unwrap(), true);
    protector.clear("u1").unwrap();
    assert_eq!(protector.register_attempt("u1").unwrap(), false);
}
