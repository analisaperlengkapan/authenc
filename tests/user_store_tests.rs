use authenc::services::services::user_store::UserStore;
use authenc::models::user::User;
use uuid::Uuid;

#[test]
fn user_store_basic_flow() {
    let store = UserStore::new();
    let u = User::new("alice".into(), "alice@example.com".into(), "hash".into(), Uuid::new_v4());
    let id = u.id;
    store.add_user(u.clone());
    assert_eq!(store.get_all().len(), 1);
    assert!(store.get_by_id(&id).is_some());
    assert!(store.get_by_username("alice").is_some());
    assert_eq!(store.verify_password("alice", "password").unwrap(), true); // placeholder logic
}
