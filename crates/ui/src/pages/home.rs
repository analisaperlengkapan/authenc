use leptos::*;

#[component]
pub fn Home() -> impl IntoView {
    view! {
        <div class="dashboard">
            <h2 style="margin-bottom: 20px;">"Dashboard"</h2>
            <div class="stats-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px;">
                <div class="stat-card" style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h3 style="margin-top: 0; color: #6c757d; font-size: 1rem;">"Total Users"</h3>
                    <div class="value" style="font-size: 2em; font-weight: bold; color: #007bff; margin-top: 10px;">"150"</div>
                </div>
                <div class="stat-card" style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h3 style="margin-top: 0; color: #6c757d; font-size: 1rem;">"Active Sessions"</h3>
                    <div class="value" style="font-size: 2em; font-weight: bold; color: #28a745; margin-top: 10px;">"42"</div>
                </div>
                <div class="stat-card" style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h3 style="margin-top: 0; color: #6c757d; font-size: 1rem;">"Realms"</h3>
                    <div class="value" style="font-size: 2em; font-weight: bold; color: #6c757d; margin-top: 10px;">"3"</div>
                </div>
                <div class="stat-card" style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                    <h3 style="margin-top: 0; color: #6c757d; font-size: 1rem;">"Events (24h)"</h3>
                    <div class="value" style="font-size: 2em; font-weight: bold; color: #dc3545; margin-top: 10px;">"1,204"</div>
                </div>
            </div>
        </div>
    }
}
