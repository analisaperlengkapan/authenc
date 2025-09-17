use authenc::models::user::User;
use authenc::services::stores::user_store::UserStore;
use uuid::Uuid;

#[test]
fn user_store_basic_flow() {
    let store = UserStore::new();
    let u = User::new(
        "alice".into(),
        "alice@example.com".into(),
        Some("hash".into()),
        Some(Uuid::new_v4()),
    );
    let id = u.id;
    store.add_user(u.clone());
    assert_eq!(store.get_all().len(), 1);
    assert!(store.get_by_id(&id).is_some());
    assert!(store.get_by_username("alice").is_some());
    // TODO: Implement proper password hashing and verification
    assert_eq!(store.verify_password("alice", "password").unwrap(), true);
}
