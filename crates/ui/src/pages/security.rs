use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use crate::api_client::authenticated_request;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityStats {
    pub active_sessions: u64,
    pub trusted_devices: u64,
    pub risky_sessions: u64,
    pub compliance_rate: f64,
}

use crate::utils::get_realm_id;

#[component]
pub fn SecurityDashboard() -> impl IntoView {
    let stats = LocalResource::new(|_| async move {
            let realm_id = get_realm_id();
            let url = format!("/api/v1/auth/zero-trust/dashboard/security?realm_id={}", realm_id);
            match authenticated_request("GET", &url, None::<&()>).await {
                Ok(res) if res.ok() => res.json::<SecurityStats>().await.map_err(|e| e.to_string()),
                _ => Err("Failed to fetch security stats".to_string()),
            }
        }
    );

    view! {
        <div class="security-dashboard">
            <h2 style="margin-bottom: 20px;">"Security Dashboard (Zero Trust)"</h2>

            <Suspense fallback=|| view! { <p>"Loading security metrics..."</p> }>
                {move || stats.get().map(|res| match res {
                    Ok(data) => view! {
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px;">
                            <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center;">
                                <div style="font-size: 0.85rem; color: #6c757d;">"Active Sessions"</div>
                                <div style="font-size: 2rem; font-weight: bold;">{data.active_sessions}</div>
                            </div>
                            <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center;">
                                <div style="font-size: 0.85rem; color: #6c757d;">"Trusted Devices"</div>
                                <div style="font-size: 2rem; font-weight: bold;">{data.trusted_devices}</div>
                            </div>
                            <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center;">
                                <div style="font-size: 0.85rem; color: #6c757d;">"Risky Sessions"</div>
                                <div style="font-size: 2rem; font-weight: bold; color: #dc3545;">{data.risky_sessions}</div>
                            </div>
                            <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center;">
                                <div style="font-size: 0.85rem; color: #6c757d;">"Compliance Rate"</div>
                                <div style="font-size: 2rem; font-weight: bold; color: #28a745;">{format!("{:.0}%", data.compliance_rate * 100.0)}</div>
                            </div>
                        </div>
                    }.into_any(),
                    _ => view! { <p style="color: red;">"Error loading dashboard data"</p> }.into_any()
                })}
            </Suspense>
        </div>
    }
}
