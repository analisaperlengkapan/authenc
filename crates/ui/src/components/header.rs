use leptos::*;

#[component]
pub fn Header() -> impl IntoView {
    view! {
        <header class="header" style="height: 60px; background: white; border-bottom: 1px solid #dee2e6; display: flex; align-items: center; justify-content: space-between; padding: 0 20px;">
            <div class="realm-selector" style="font-weight: bold; color: #555;">
                <i class="fas fa-shield-alt" style="margin-right: 8px;"></i>
                "Current Realm: " <span style="color: #007bff;">"Master"</span>
            </div>
            <div class="user-menu" style="display: flex; align-items: center;">
                <div class="user-avatar" style="width: 32px; height: 32px; background: #e9ecef; border-radius: 50%; display: flex; align-items: center; justify-content: center; margin-right: 10px;">
                    <i class="fas fa-user" style="color: #6c757d;"></i>
                </div>
                <span style="font-weight: 500;">"Admin"</span>
            </div>
        </header>
    }
}
