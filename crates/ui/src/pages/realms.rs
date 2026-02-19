use leptos::*;

#[component]
pub fn Realms() -> impl IntoView {
    view! {
        <div class="realms-page">
            <div class="header-actions" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="margin: 0;">"Realms"</h2>
                <button style="background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                    <i class="fas fa-plus" style="margin-right: 5px;"></i> "Create Realm"
                </button>
            </div>

            <div class="realm-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                <div class="realm-card" style="background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 20px; border-top: 4px solid #007bff;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px;">
                        <h3 style="margin: 0; font-size: 1.2rem;">"Master"</h3>
                        <span style="background: #e9ecef; color: #495057; padding: 2px 8px; border-radius: 4px; font-size: 0.8em;">"System"</span>
                    </div>
                    <p style="color: #6c757d; margin-bottom: 20px;">"The master realm is the root realm for system administration."</p>
                    <div class="actions" style="border-top: 1px solid #eee; padding-top: 15px; display: flex; justify-content: flex-end;">
                        <button style="padding: 6px 12px; border: 1px solid #007bff; background: white; color: #007bff; border-radius: 4px; cursor: pointer;">"Manage"</button>
                    </div>
                </div>

                <div class="realm-card" style="background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 20px; border-top: 4px solid #6c757d;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px;">
                        <h3 style="margin: 0; font-size: 1.2rem;">"Customer A"</h3>
                        <span style="background: #d4edda; color: #155724; padding: 2px 8px; border-radius: 4px; font-size: 0.8em;">"Enabled"</span>
                    </div>
                    <p style="color: #6c757d; margin-bottom: 20px;">"Production realm for Customer A (Acme Corp)."</p>
                    <div class="actions" style="border-top: 1px solid #eee; padding-top: 15px; display: flex; justify-content: flex-end;">
                        <button style="padding: 6px 12px; border: 1px solid #007bff; background: white; color: #007bff; border-radius: 4px; cursor: pointer;">"Manage"</button>
                    </div>
                </div>
            </div>
        </div>
    }
}
