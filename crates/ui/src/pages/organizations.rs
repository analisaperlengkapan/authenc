use leptos::*;
use crate::models::{ListOrganizationsResponse, CreateOrganizationRequest, UpdateOrganizationRequest, OrganizationMembersResponse, Organization, OrganizationSettings, OrganizationSettingsResponse};
use crate::api_client::authenticated_request;
use crate::components::modal::Modal;

#[component]
pub fn Organizations() -> impl IntoView {
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);
    let (show_create_modal, set_show_create_modal) = create_signal(false);
    let (show_edit_modal, set_show_edit_modal) = create_signal(false);
    let (show_settings_modal, set_show_settings_modal) = create_signal(false);
    let (selected_org, set_selected_org) = create_signal::<Option<Organization>>(None);
    let (show_members_modal, set_show_members_modal) = create_signal(false);
    let (show_add_member_modal, set_show_add_member_modal) = create_signal(false);

    // Form signals
    let (org_name, set_org_name) = create_signal(String::new());
    let (org_display_name, set_org_display_name) = create_signal(String::new());
    let (org_description, set_org_description) = create_signal(String::new());
    let (org_domain, set_org_domain) = create_signal(String::new());

    // Settings signals
    let (member_user_id, set_member_user_id) = create_signal(String::new());
    let (member_role, set_member_role) = create_signal("member".to_string());
    let (allow_signup, set_allow_signup) = create_signal(false);
    let (require_verify, set_require_verify) = create_signal(false);
    let (enforce_mfa, set_enforce_mfa) = create_signal(false);
    let (pwd_policy, set_pwd_policy) = create_signal(String::new());
    let (timeout, set_timeout) = create_signal(3600u64);
    let (max_users, set_max_users) = create_signal(String::new());

    let members_resource = create_resource(
        move || selected_org.get(),
        move |org| async move {
            if let Some(o) = org {
                let url = format!("/api/v1/organizations/{}/members", o.id);
                match authenticated_request("GET", &url, None::<&()>).await {
                    Ok(response) => {
                        if response.ok() {
                            match response.json::<OrganizationMembersResponse>().await {
                                Ok(res) => Ok(res.members),
                                Err(e) => Err(e.to_string()),
                            }
                        } else {
                            Err(format!("Failed to fetch members: {}", response.status()))
                        }
                    }
                    Err(e) => Err(e),
                }
            } else {
                Ok(Vec::new())
            }
        }
    );

    let organizations_resource = create_resource(
        || (),
        move |_| async move {
            set_error_message.set(None);
            let url = "/api/v1/organizations";

            match authenticated_request("GET", url, None::<&()>).await {
                Ok(response) => {
                    if response.ok() {
                        match response.json::<ListOrganizationsResponse>().await {
                            Ok(res) => Ok(res.organizations),
                            Err(e) => Err(e.to_string()),
                        }
                    } else {
                        let msg = format!("Failed to fetch organizations: {}", response.status());
                        set_error_message.set(Some(msg.clone()));
                        Err(msg)
                    }
                }
                Err(e) => {
                    set_error_message.set(Some(e.clone()));
                    Err(e)
                }
            }
        }
    );

    let create_org_action = create_action(move |_: &()| async move {
        let req = CreateOrganizationRequest {
            name: org_name.get(),
            display_name: org_display_name.get(),
            description: Some(org_description.get()).filter(|s| !s.is_empty()),
            domain: Some(org_domain.get()).filter(|s| !s.is_empty()),
        };

        match authenticated_request("POST", "/api/v1/organizations", Some(&req)).await {
            Ok(response) => {
                if response.ok() {
                    set_show_create_modal.set(false);
                    organizations_resource.refetch();
                } else {
                    set_error_message.set(Some(format!("Failed to create organization: {}", response.status())));
                }
            }
            Err(e) => set_error_message.set(Some(e)),
        }
    });

    let update_org_action = create_action(move |_: &()| async move {
        let Some(org) = selected_org.get() else { return };
        let req = UpdateOrganizationRequest {
            name: org_name.get(),
            display_name: org_display_name.get(),
            description: Some(org_description.get()).filter(|s| !s.is_empty()),
            domain: Some(org_domain.get()).filter(|s| !s.is_empty()),
        };

        let url = format!("/api/v1/organizations/{}", org.id);
        match authenticated_request("PUT", &url, Some(&req)).await {
            Ok(res) if res.ok() => {
                set_show_edit_modal.set(false);
                organizations_resource.refetch();
            }
            _ => set_error_message.set(Some("Failed to update organization".to_string())),
        }
    });

    let add_member_action = create_action(move |_: &()| async move {
        let Some(org) = selected_org.get() else { return };
        let payload = serde_json::json!({
            "user_id": member_user_id.get(),
            "role": member_role.get()
        });

        let url = format!("/api/v1/organizations/{}/members", org.id);
        match authenticated_request("POST", &url, Some(&payload)).await {
            Ok(res) if res.ok() => {
                set_show_add_member_modal.set(false);
                members_resource.refetch();
            }
            _ => set_error_message.set(Some("Failed to add member".to_string())),
        }
    });

    let save_settings_action = create_action(move |_: &()| async move {
        let Some(org) = selected_org.get() else { return };
        let req = OrganizationSettings {
            organization_id: org.id.clone(),
            allow_public_signup: allow_signup.get(),
            require_email_verification: require_verify.get(),
            enable_two_factor: enforce_mfa.get(),
            password_policy: pwd_policy.get(),
            session_timeout: timeout.get(),
            max_users: max_users.get().parse().ok(),
            features: vec![],
        };

        let url = format!("/api/v1/organizations/{}/settings", org.id);
        match authenticated_request("PUT", &url, Some(&req)).await {
            Ok(res) if res.ok() => set_show_settings_modal.set(false),
            _ => set_error_message.set(Some("Failed to save settings".to_string())),
        }
    });

    let delete_org_action = create_action(move |id: &String| {
        let id = id.clone();
        async move {
            let url = format!("/api/v1/organizations/{}", id);
            match authenticated_request("DELETE", &url, None::<&()>).await {
                Ok(response) => {
                    if response.ok() {
                        organizations_resource.refetch();
                    } else {
                        set_error_message.set(Some(format!("Failed to delete organization: {}", response.status())));
                    }
                }
                Err(e) => set_error_message.set(Some(e)),
            }
        }
    });

    view! {
        <div class="organizations-page">
            <div class="header-actions" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="margin: 0;">"Organizations"</h2>
                <button
                    on:click=move |_| {
                        set_org_name.set(String::new());
                        set_org_display_name.set(String::new());
                        set_org_description.set(String::new());
                        set_org_domain.set(String::new());
                        set_show_create_modal.set(true);
                    }
                    style="background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                    <i class="fas fa-plus" style="margin-right: 5px;"></i> "Create Organization"
                </button>
            </div>

            {move || error_message.get().map(|msg| view! {
                <div style="color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; padding: .75rem 1.25rem; margin-bottom: 1rem; border: 1px solid transparent; border-radius: .25rem;">
                    {msg}
                </div>
            })}

            <div class="table-container" style="background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;">
                <Suspense fallback=move || view! { <div style="padding: 20px; text-align: center;">"Loading organizations..."</div> }>
                {move || {
                    organizations_resource.get().map(|res| {
                        match res {
                            Ok(orgs) => {
                                if orgs.is_empty() {
                                    view! {
                                        <div style="padding: 40px; text-align: center; color: #6c757d;">
                                            "No organizations found."
                                        </div>
                                    }.into_view()
                                } else {
                                    view! {
                                        <table style="width: 100%; border-collapse: collapse;">
                                            <thead>
                                                <tr style="background: #f8f9fa; border-bottom: 1px solid #dee2e6;">
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Name"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Domain"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Actions"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {orgs.into_iter().map(|org| {
                                                    let o1 = org.clone();
                                                    let o2 = org.clone();
                                                    let o3 = org.clone();
                                                    let id = org.id.clone();
                                                    view! {
                                                        <tr style="border-bottom: 1px solid #dee2e6;">
                                                            <td style="padding: 15px;">
                                                                <div style="font-weight: 600;">{org.display_name.unwrap_or(org.name.clone())}</div>
                                                                <div style="font-size: 0.8em; color: #6c757d;">{org.name}</div>
                                                            </td>
                                                            <td style="padding: 15px;">{org.domain.unwrap_or_else(|| "-".to_string())}</td>
                                                            <td style="padding: 15px;">
                                                                <button
                                                                    on:click=move |_| {
                                                                        set_selected_org.set(Some(o1.clone()));
                                                                        set_show_members_modal.set(true);
                                                                    }
                                                                    style="margin-right: 8px; padding: 6px 12px; border: 1px solid #dee2e6; background: white; border-radius: 4px; cursor: pointer; color: #495057;">
                                                                    "Members"
                                                                </button>
                                                                <button
                                                                    on:click=move |_| {
                                                                        set_selected_org.set(Some(o2.clone()));
                                                                        let oid = o2.id.clone();
                                                                        spawn_local(async move {
                                                                            let url = format!("/api/v1/organizations/{}/settings", oid);
                                                                            if let Ok(res) = authenticated_request("GET", &url, None::<&()>).await {
                                                                                if let Ok(data) = res.json::<OrganizationSettingsResponse>().await {
                                                                                    let s = data.settings;
                                                                                    set_allow_signup.set(s.allow_public_signup);
                                                                                    set_require_verify.set(s.require_email_verification);
                                                                                    set_enforce_mfa.set(s.enable_two_factor);
                                                                                    set_pwd_policy.set(s.password_policy);
                                                                                    set_timeout.set(s.session_timeout);
                                                    set_max_users.set(s.max_users.map(|m| m.to_string()).unwrap_or_default());
                                                                                    set_show_settings_modal.set(true);
                                                                                }
                                                                            }
                                                                        });
                                                                    }
                                                                    style="margin-right: 8px; padding: 6px 12px; border: 1px solid #dee2e6; background: white; border-radius: 4px; cursor: pointer; color: #495057;">
                                                                    "Settings"
                                                                </button>
                                                                <button
                                                                    on:click=move |_| {
                                                                        set_org_name.set(o3.name.clone());
                                                                        set_org_display_name.set(o3.display_name.clone().unwrap_or_default());
                                                                        set_org_description.set(o3.description.clone().unwrap_or_default());
                                                                        set_org_domain.set(o3.domain.clone().unwrap_or_default());
                                                                        set_selected_org.set(Some(o3.clone()));
                                                                        set_show_edit_modal.set(true);
                                                                    }
                                                                    style="margin-right: 8px; padding: 6px 12px; border: 1px solid #dee2e6; background: white; border-radius: 4px; cursor: pointer; color: #495057;">
                                                                    "Edit"
                                                                </button>
                                                                <button
                                                                    on:click=move |_| {
                                                                        if gloo_utils::window().confirm_with_message("Delete organization?").unwrap_or(false) {
                                                                            delete_org_action.dispatch(id.clone());
                                                                        }
                                                                    }
                                                                    style="padding: 6px 12px; border: 1px solid #dc3545; background: white; border-radius: 4px; cursor: pointer; color: #dc3545;">
                                                                    <i class="fas fa-trash"></i>
                                                                </button>
                                                            </td>
                                                        </tr>
                                                    }
                                                }).collect_view()}
                                            </tbody>
                                        </table>
                                    }.into_view()
                                }
                            },
                            Err(_) => view! {
                                <div style="padding: 20px; text-align: center; color: #dc3545;">
                                    "Error loading organizations."
                                </div>
                            }.into_view()
                        }
                    })
                }}
                </Suspense>
            </div>

            <Modal is_open=show_create_modal on_close=move |_| set_show_create_modal.set(false) title="Create Organization">
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    <input type="text" placeholder="Name" on:input=move |ev| set_org_name.set(event_target_value(&ev)) prop:value=org_name style="padding: 8px;" />
                    <input type="text" placeholder="Display Name" on:input=move |ev| set_org_display_name.set(event_target_value(&ev)) prop:value=org_display_name style="padding: 8px;" />
                    <input type="text" placeholder="Domain" on:input=move |ev| set_org_domain.set(event_target_value(&ev)) prop:value=org_domain style="padding: 8px;" />
                    <textarea placeholder="Description" on:input=move |ev| set_org_description.set(event_target_value(&ev)) prop:value=org_description style="padding: 8px;"></textarea>
                    <button on:click=move |_| create_org_action.dispatch(()) style="padding: 10px; background: #28a745; color: white; border: none; cursor: pointer;">"Create"</button>
                </div>
            </Modal>

            <Modal is_open=show_edit_modal on_close=move |_| set_show_edit_modal.set(false) title="Edit Organization">
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    <input type="text" placeholder="Name" on:input=move |ev| set_org_name.set(event_target_value(&ev)) prop:value=org_name style="padding: 8px;" />
                    <input type="text" placeholder="Display Name" on:input=move |ev| set_org_display_name.set(event_target_value(&ev)) prop:value=org_display_name style="padding: 8px;" />
                    <input type="text" placeholder="Domain" on:input=move |ev| set_org_domain.set(event_target_value(&ev)) prop:value=org_domain style="padding: 8px;" />
                    <textarea placeholder="Description" on:input=move |ev| set_org_description.set(event_target_value(&ev)) prop:value=org_description style="padding: 8px;"></textarea>
                    <button on:click=move |_| update_org_action.dispatch(()) style="padding: 10px; background: #007bff; color: white; border: none; cursor: pointer;">"Save Changes"</button>
                </div>
            </Modal>

            <Modal is_open=show_settings_modal on_close=move |_| set_show_settings_modal.set(false) title="Organization Settings">
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    <label style="display: flex; align-items: center; gap: 10px;">
                        <input type="checkbox" on:change=move |ev| set_allow_signup.set(event_target_checked(&ev)) prop:checked=allow_signup />
                        "Allow Public Signup"
                    </label>
                    <label style="display: flex; align-items: center; gap: 10px;">
                        <input type="checkbox" on:change=move |ev| set_require_verify.set(event_target_checked(&ev)) prop:checked=require_verify />
                        "Require Email Verification"
                    </label>
                    <label style="display: flex; align-items: center; gap: 10px;">
                        <input type="checkbox" on:change=move |ev| set_enforce_mfa.set(event_target_checked(&ev)) prop:checked=enforce_mfa />
                        "Enforce Two-Factor Auth"
                    </label>
                    <div>
                        <label style="display: block; margin-bottom: 5px;">"Password Policy"</label>
                        <input type="text" on:input=move |ev| set_pwd_policy.set(event_target_value(&ev)) prop:value=pwd_policy style="width: 100%; padding: 8px;" />
                    </div>
                    <div>
                        <label style="display: block; margin-bottom: 5px;">"Session Timeout (sec)"</label>
                        <input type="number" on:input=move |ev| set_timeout.set(event_target_value(&ev).parse().unwrap_or(3600)) prop:value=timeout style="width: 100%; padding: 8px;" />
                    </div>
                    <div>
                        <label style="display: block; margin-bottom: 5px;">"Max Users"</label>
                        <input type="number" on:input=move |ev| set_max_users.set(event_target_value(&ev)) prop:value=max_users style="width: 100%; padding: 8px;" />
                    </div>
                    <button on:click=move |_| save_settings_action.dispatch(()) style="padding: 10px; background: #007bff; color: white; border: none; cursor: pointer;">"Save Settings"</button>
                </div>
            </Modal>

            <Modal is_open=show_members_modal on_close=move |_| set_show_members_modal.set(false) title="Organization Members">
                <div style="margin-bottom: 15px;">
                    <button on:click=move |_| set_show_add_member_modal.set(true) style="background: #28a745; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer;">"+ Add Member"</button>
                </div>
                <Suspense fallback=|| view! { <p>"Loading..."</p> }>
                    {move || {
                        let current_org = selected_org.get();
                        members_resource.get().map(move |res| match res {
                        Ok(members) => {
                            let org_id = current_org.clone().map(|o| o.id).unwrap_or_default();
                            view! {
                            <table style="width: 100%;">
                                <thead><tr><th style="text-align: left;">"User ID"</th><th style="text-align: left;">"Role"</th><th style="text-align: right;">"Actions"</th></tr></thead>
                                <tbody>
                                    {members.into_iter().map(|m| {
                                        let uid = m.user_id.clone();
                                        let oid = org_id.clone();
                                        view! {
                                        <tr style="border-top: 1px solid #eee;">
                                            <td style="padding: 8px;">{m.user_id}</td>
                                            <td style="padding: 8px;">{m.role}</td>
                                            <td style="padding: 8px; text-align: right;">
                                                <button
                                                    on:click=move |_| {
                                                        if gloo_utils::window().confirm_with_message("Remove member?").unwrap_or(false) {
                                                            let url = format!("/api/v1/organizations/{}/members/{}", oid, uid);
                                                            spawn_local(async move {
                                                                let _ = authenticated_request("DELETE", &url, None::<&()>).await;
                                                                members_resource.refetch();
                                                            });
                                                        }
                                                    }
                                                    style="color: red; background: none; border: none; cursor: pointer;"><i class="fas fa-user-minus"></i></button>
                                            </td>
                                        </tr>
                                    }}).collect_view()}
                                </tbody>
                            </table>
                        }.into_view()
                        },
                        _ => view! { <p>"Error loading members"</p> }.into_view()
                    })}}
                </Suspense>
            </Modal>

            <Modal is_open=show_add_member_modal on_close=move |_| set_show_add_member_modal.set(false) title="Add Member">
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    <input type="text" placeholder="User ID (UUID)" on:input=move |ev| set_member_user_id.set(event_target_value(&ev)) prop:value=member_user_id style="padding: 8px;" />
                    <select on:change=move |ev| set_member_role.set(event_target_value(&ev)) style="padding: 8px;">
                        <option value="member">"Member"</option>
                        <option value="admin">"Admin"</option>
                        <option value="owner">"Owner"</option>
                    </select>
                    <button on:click=move |_| add_member_action.dispatch(()) style="padding: 10px; background: #28a745; color: white; border: none; cursor: pointer;">"Add Member"</button>
                </div>
            </Modal>
        </div>
    }
}
