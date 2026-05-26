pub fn get_realm_id() -> String {
    if let Ok(Some(storage)) = gloo_utils::window().local_storage() {
        if let Ok(Some(id)) = storage.get_item("authenc_realm_id") {
            return id;
        }
    }
    "00000000-0000-0000-0000-000000000000".to_string()
}

pub fn get_username() -> String {
    if let Ok(Some(storage)) = gloo_utils::window().local_storage() {
        if let Ok(Some(username)) = storage.get_item("authenc_user") {
            return username;
        }
    }
    String::new()
}
