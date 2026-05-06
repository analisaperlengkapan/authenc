use leptos::*;
use serde::{Deserialize, Serialize};
use crate::api_client::authenticated_request;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyResponse {
    pub id: Uuid,
    pub name: String,
    pub policy_type: String,
    pub logic: String,
    pub enabled: bool,
}

use crate::utils::get_realm_id;

#[component]
pub fn Authorization() -> impl IntoView {
    let policies = create_resource(
        || (),
        |_| async move {
            let realm_id = get_realm_id();
            let url = format!("/api/v1/admin/policies?realm_id={}", realm_id);
            match authenticated_request("GET", &url, None::<&()>).await {
                Ok(res) if res.ok() => res.json::<Vec<PolicyResponse>>().await.map_err(|e| e.to_string()),
                _ => Ok(vec![]),
            }
        }
    );

    view! {
        <div class="authorization-page">
            <h2 style="margin-bottom: 20px;">"Authorization Policies"</h2>
            <div class="table-container" style="background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;">
                <Suspense fallback=|| view! { <div style="padding: 20px; text-align: center;">"Loading policies..."</div> }>
                    {move || policies.get().map(|res| match res {
                        Ok(pols) if pols.is_empty() => view! { <div style="padding: 20px; text-align: center;">"No policies defined."</div> }.into_view(),
                        Ok(pols) => view! {
                            <table style="width: 100%; border-collapse: collapse;">
                                <thead>
                                    <tr style="background: #f8f9fa; border-bottom: 1px solid #dee2e6;">
                                        <th style="padding: 15px; text-align: left;">"Name"</th>
                                        <th style="padding: 15px; text-align: left;">"Type"</th>
                                        <th style="padding: 15px; text-align: left;">"Logic"</th>
                                        <th style="padding: 15px; text-align: left;">"Status"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {pols.into_iter().map(|p| view! {
                                        <tr style="border-bottom: 1px solid #dee2e6;">
                                            <td style="padding: 15px;">{p.name}</td>
                                            <td style="padding: 15px;">{p.policy_type}</td>
                                            <td style="padding: 15px;">{p.logic}</td>
                                            <td style="padding: 15px;">
                                                <span style={if p.enabled { "color: green" } else { "color: red" }}>
                                                    {if p.enabled { "Enabled" } else { "Disabled" }}
                                                </span>
                                            </td>
                                        </tr>
                                    }).collect_view()}
                                </tbody>
                            </table>
                        }.into_view(),
                        _ => view! { <div style="padding: 20px; text-align: center; color: red;">"Error loading policies"</div> }.into_view()
                    })}
                </Suspense>
            </div>
        </div>
    }
}
