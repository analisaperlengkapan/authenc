use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use crate::api_client::authenticated_request;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemStats {
    pub total_users: u64,
    pub active_users: u64,
    pub total_sessions: u64,
    pub active_sessions: u64,
    pub total_realms: u64,
    pub total_policies: u64,
    pub security_events_today: u64,
    pub failed_login_attempts: u64,
    pub uptime_seconds: u64,
    pub memory_usage_mb: u64,
    pub cpu_usage_percent: f64,
}

async fn fetch_stats() -> Result<SystemStats, String> {
    let resp = authenticated_request("GET", "/api/v1/admin/stats", None::<&()>).await?;

    if !resp.ok() {
        return Err(format!("API error: {}", resp.status()));
    }

    resp.json::<SystemStats>()
        .await
        .map_err(|e| e.to_string())
}

#[component]
pub fn Home() -> impl IntoView {
    let stats = LocalResource::new(|_| fetch_stats());

    view! {
        <div class="dashboard">
            <h2 style="margin-bottom: 20px;">"Dashboard"</h2>

            <Suspense fallback=move || view! { <p>"Loading stats..."</p> }>
                {move || {
                    stats.get().map(|res| {
                        match res {
                            Ok(data) => view! {
                                <div class="stats-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px;">
                                    <div class="stat-card" style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                                        <h3 style="margin-top: 0; color: #6c757d; font-size: 1rem;">"Total Users"</h3>
                                        <div class="value" style="font-size: 2em; font-weight: bold; color: #007bff; margin-top: 10px;">{data.total_users}</div>
                                        <div class="sub-value" style="font-size: 0.8em; color: #6c757d; margin-top: 5px;">
                                            {data.active_users} " active"
                                        </div>
                                    </div>
                                    <div class="stat-card" style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                                        <h3 style="margin-top: 0; color: #6c757d; font-size: 1rem;">"Sessions"</h3>
                                        <div class="value" style="font-size: 2em; font-weight: bold; color: #28a745; margin-top: 10px;">{data.total_sessions}</div>
                                        <div class="sub-value" style="font-size: 0.8em; color: #6c757d; margin-top: 5px;">
                                            {data.active_sessions} " active"
                                        </div>
                                    </div>
                                    <div class="stat-card" style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                                        <h3 style="margin-top: 0; color: #6c757d; font-size: 1rem;">"Realms"</h3>
                                        <div class="value" style="font-size: 2em; font-weight: bold; color: #6c757d; margin-top: 10px;">{data.total_realms}</div>
                                    </div>
                                    <div class="stat-card" style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                                        <h3 style="margin-top: 0; color: #6c757d; font-size: 1rem;">"Events (Today)"</h3>
                                        <div class="value" style="font-size: 2em; font-weight: bold; color: #dc3545; margin-top: 10px;">{data.security_events_today}</div>
                                        <div class="sub-value" style="font-size: 0.8em; color: #6c757d; margin-top: 5px;">
                                            {data.failed_login_attempts} " failed logins"
                                        </div>
                                    </div>
                                </div>
                            }.into_any(),
                            Err(e) => view! {
                                <div class="error" style="color: red; padding: 20px; background: #fee; border-radius: 4px;">
                                    "Error loading stats: " {e}
                                </div>
                            }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}
