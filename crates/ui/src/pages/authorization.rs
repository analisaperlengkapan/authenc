use leptos::prelude::*;
use crate::api_client::authenticated_request;
use crate::components::modal::Modal;
use crate::utils::get_realm_id;
use crate::models::{PolicyResponse, CreatePolicyRequest, PermissionResponse, CreatePermissionRequest};

#[component]
pub fn Authorization() -> impl IntoView {
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);
    let (show_policy_modal, set_show_policy_modal) = signal(false);
    let (show_permission_modal, set_show_permission_modal) = signal(false);

    // Policy Form signals
    let (policy_name, set_policy_name) = signal(String::new());
    let (policy_type, set_type) = signal("RoleBased".to_string());
    let (policy_logic, set_logic) = signal("Positive".to_string());
    let (policy_config, set_config) = signal("{}".to_string());

    // Permission Form signals
    let (perm_name, set_perm_name) = signal(String::new());
    let (perm_resource, set_perm_resource) = signal(String::new());
    let (perm_action, set_perm_action) = signal(String::new());

    let policies_resource = LocalResource::new(|_| async move {
            let realm_id = get_realm_id();
            let url = format!("/api/v1/admin/policies?realm_id={}", realm_id);
            match authenticated_request("GET", &url, None::<&()>).await {
                Ok(res) if res.ok() => res.json::<Vec<PolicyResponse>>().await.map_err(|e| e.to_string()),
                _ => Ok(vec![]),
            }
        }
    );

    let permissions_resource = LocalResource::new(|_| async move {
            let realm_id = get_realm_id();
            let url = format!("/api/v1/auth/realms/{}/permissions", realm_id);
            match authenticated_request("GET", &url, None::<&()>).await {
                Ok(res) if res.ok() => res.json::<Vec<PermissionResponse>>().await.map_err(|e| e.to_string()),
                _ => Ok(vec![]),
            }
        }
    );

    let create_policy_action = create_action(move |_: &()| async move {
        let config: serde_json::Value = serde_json::from_str(&policy_config.get()).unwrap_or_default();
        let req = CreatePolicyRequest {
            name: policy_name.get(),
            description: None,
            policy_type: policy_type.get(),
            logic: policy_logic.get(),
            config,
            enabled: true,
            realm_id: get_realm_id(),
        };

        match authenticated_request("POST", "/api/v1/admin/policies", Some(&req)).await {
            Ok(res) if res.ok() => {
                set_show_policy_modal.set(false);
                policies_resource.refetch();
            }
            _ => set_error_message.set(Some("Failed to create policy".to_string())),
        }
    });

    let create_permission_action = create_action(move |_: &()| async move {
        let req = CreatePermissionRequest {
            name: perm_name.get(),
            description: None,
            resource: perm_resource.get(),
            action: perm_action.get(),
        };

        let realm_id = get_realm_id();
        let url = format!("/api/v1/auth/realms/{}/permissions", realm_id);
        match authenticated_request("POST", &url, Some(&req)).await {
            Ok(res) if res.ok() => {
                set_show_permission_modal.set(false);
                permissions_resource.refetch();
            }
            _ => set_error_message.set(Some("Failed to create permission".to_string())),
        }
    });

    view! {
        <div class="authorization-page">
            <div class="header-actions" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="margin: 0;">"Authorization"</h2>
                <div style="display: gap; gap: 10px;">
                    <button
                        on:click=move |_| set_show_policy_modal.set(true)
                        style="background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold; margin-right: 10px;">
                        "Add Policy"
                    </button>
                    <button
                        on:click=move |_| set_show_permission_modal.set(true)
                        style="background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                        "Add Permission"
                    </button>
                </div>
            </div>

            {move || error_message.get().map(|msg| view! {
                <div style="color: #ef4444; background: #fee2e2; padding: 10px; border-radius: 4px; margin-bottom: 20px;">{msg}</div>
            })}

            <div style="margin-bottom: 30px;">
                <h3>"Policies"</h3>
                <div class="table-container" style="background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;">
                    <Suspense fallback=|| view! { <div style="padding: 20px; text-align: center;">"Loading policies..."</div> }>
                        {move || policies_resource.get().map(|res| match res {
                            Ok(pols) if pols.is_empty() => view! { <div style="padding: 20px; text-align: center;">"No policies defined."</div> }.into_any(),
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
                            }.into_any(),
                            _ => view! { <div style="padding: 20px; text-align: center; color: red;">"Error loading policies"</div> }.into_any()
                        })}
                    </Suspense>
                </div>
            </div>

            <div>
                <h3>"Permissions"</h3>
                <div class="table-container" style="background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;">
                    <Suspense fallback=|| view! { <div style="padding: 20px; text-align: center;">"Loading permissions..."</div> }>
                        {move || permissions_resource.get().map(|res| match res {
                            Ok(perms) if perms.is_empty() => view! { <div style="padding: 20px; text-align: center;">"No permissions defined."</div> }.into_any(),
                            Ok(perms) => view! {
                                <table style="width: 100%; border-collapse: collapse;">
                                    <thead>
                                        <tr style="background: #f8f9fa; border-bottom: 1px solid #dee2e6;">
                                            <th style="padding: 15px; text-align: left;">"Name"</th>
                                            <th style="padding: 15px; text-align: left;">"Resource"</th>
                                            <th style="padding: 15px; text-align: left;">"Policies"</th>
                                            <th style="padding: 15px; text-align: right;">"Actions"</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {perms.into_iter().map(|p| {
                                            let name = p.name.clone();
                                            view! {
                                            <tr style="border-bottom: 1px solid #dee2e6;">
                                                <td style="padding: 15px;">{p.name}</td>
                                                <td style="padding: 15px;">{p.resource_id}</td>
                                                <td style="padding: 15px;">{p.policies.join(", ")}</td>
                                                <td style="padding: 15px; text-align: right;">
                                                    <button
                                                        on:click=move |_| {
                                                            if gloo_utils::window().confirm_with_message("Delete permission?").unwrap_or(false) {
                                                                let rid = get_realm_id();
                                                                let url = format!("/api/v1/auth/realms/{}/permissions/{}", rid, urlencoding::encode(&name));
                                                                spawn_local(async move {
                                                                    let _ = authenticated_request("DELETE", &url, None::<&()>).await;
                                                                    permissions_resource.refetch();
                                                                });
                                                            }
                                                        }
                                                        style="color: red; background: none; border: none; cursor: pointer;"><i class="fas fa-trash"></i></button>
                                                </td>
                                            </tr>
                                        }}).collect_view()}
                                    </tbody>
                                </table>
                            }.into_any(),
                            _ => view! { <div style="padding: 20px; text-align: center; color: red;">"Error loading permissions"</div> }.into_any()
                        })}
                    </Suspense>
                </div>
            </div>

            <Modal is_open=show_policy_modal on_close=move |_| set_show_policy_modal.set(false) title="Create Policy">
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    <input type="text" placeholder="Policy Name" on:input=move |ev| set_policy_name.set(event_target_value(&ev)) prop:value=policy_name style="padding: 8px;" />
                    <select on:change=move |ev| set_type.set(event_target_value(&ev)) style="padding: 8px;">
                        <option value="RoleBased">"Role-Based"</option>
                        <option value="AttributeBased">"Attribute-Based"</option>
                        <option value="RiskBased">"Risk-Based"</option>
                    </select>
                    <select on:change=move |ev| set_logic.set(event_target_value(&ev)) style="padding: 8px;">
                        <option value="Positive">"Positive"</option>
                        <option value="Negative">"Negative"</option>
                    </select>
                    <textarea placeholder="Config (JSON)" on:input=move |ev| set_config.set(event_target_value(&ev)) prop:value=policy_config style="padding: 8px; min-height: 100px; font-family: monospace;"></textarea>
                    <button on:click=move |_| create_policy_action.dispatch(()) style="padding: 10px; background: #28a745; color: white; border: none; cursor: pointer;">"Create Policy"</button>
                </div>
            </Modal>

            <Modal is_open=show_permission_modal on_close=move |_| set_show_permission_modal.set(false) title="Create Permission">
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    <input type="text" placeholder="Permission Name" on:input=move |ev| set_perm_name.set(event_target_value(&ev)) prop:value=perm_name style="padding: 8px;" />
                    <input type="text" placeholder="Resource ID" on:input=move |ev| set_perm_resource.set(event_target_value(&ev)) prop:value=perm_resource style="padding: 8px;" />
                    <input type="text" placeholder="Action/Scope" on:input=move |ev| set_perm_action.set(event_target_value(&ev)) prop:value=perm_action style="padding: 8px;" />
                    <button on:click=move |_| create_permission_action.dispatch(()) style="padding: 10px; background: #28a745; color: white; border: none; cursor: pointer;">"Create Permission"</button>
                </div>
            </Modal>
        </div>
    }
}
