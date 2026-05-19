use leptos::prelude::*;

#[component]
pub fn Header() -> impl IntoView {
    let realm = if let Ok(Some(storage)) = gloo_utils::window().local_storage() {
        storage.get_item("authenc_realm").ok().flatten().unwrap_or_else(|| "master".to_string())
    } else {
        "master".to_string()
    };

    let user = if let Ok(Some(storage)) = gloo_utils::window().local_storage() {
        storage.get_item("authenc_user").ok().flatten().unwrap_or_else(|| "Admin".to_string())
    } else {
        "Admin".to_string()
    };

    view! {
        <header class="header" style="height: 60px; background: white; border-bottom: 1px solid #dee2e6; display: flex; align-items: center; justify-content: space-between; padding: 0 20px;">
            <div class="realm-selector" style="font-weight: bold; color: #555;">
                <i class="fas fa-shield-alt" style="margin-right: 8px;"></i>
                "Current Realm: " <span style="color: #2563eb; text-transform: uppercase;">{realm}</span>
            </div>
            <div class="user-menu" style="display: flex; align-items: center;">
                <div class="user-avatar" style="width: 32px; height: 32px; background: #e9ecef; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 10px;">
                    <i class="fas fa-user" style="color: #6c757d;"></i>
                </div>
                <span style="font-weight: 500;">{user}</span>
            </div>
        </header>
    }
}
