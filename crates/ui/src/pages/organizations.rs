use leptos::*;
use crate::models::{ListOrganizationsResponse, CreateOrganizationRequest, OrganizationMembersResponse};
use crate::api_client::authenticated_request;
use crate::components::modal::Modal;

#[component]
pub fn Organizations() -> impl IntoView {
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);
    let (show_create_modal, set_show_create_modal) = create_signal(false);
    let (selected_org_id, set_selected_org_id) = create_signal::<Option<String>>(None);
    let (show_members_modal, set_show_members_modal) = create_signal(false);

    // Form signals
    let (new_org_name, set_new_org_name) = create_signal(String::new());
    let (new_org_display_name, set_new_org_display_name) = create_signal(String::new());
    let (new_org_description, set_new_org_description) = create_signal(String::new());
    let (new_org_domain, set_new_org_domain) = create_signal(String::new());

    let members_resource = create_resource(
        move || selected_org_id.get(),
        move |org_id| async move {
            if let Some(id) = org_id {
                let url = format!("/api/v1/organizations/{}/members", id);
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
            name: new_org_name.get(),
            display_name: new_org_display_name.get(),
            description: Some(new_org_description.get()).filter(|s| !s.is_empty()),
            domain: Some(new_org_domain.get()).filter(|s| !s.is_empty()),
        };

        match authenticated_request("POST", "/api/v1/organizations", Some(&req)).await {
            Ok(response) => {
                if response.ok() {
                    set_show_create_modal.set(false);
                    // Reset form
                    set_new_org_name.set(String::new());
                    set_new_org_display_name.set(String::new());
                    set_new_org_description.set(String::new());
                    set_new_org_domain.set(String::new());
                    organizations_resource.refetch();
                } else {
                    set_error_message.set(Some(format!("Failed to create organization: {}", response.status())));
                }
            }
            Err(e) => set_error_message.set(Some(e)),
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
                    on:click=move |_| set_show_create_modal.set(true)
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
                                            "You are not a member of any organizations."
                                        </div>
                                    }.into_view()
                                } else {
                                    view! {
                                        <table style="width: 100%; border-collapse: collapse;">
                                            <thead>
                                                <tr style="background: #f8f9fa; border-bottom: 1px solid #dee2e6;">
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Name"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Domain"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Status"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Actions"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {orgs.into_iter().map(|org| {
                                                    let id = org.id.clone();
                                                    let id_for_members = id.clone();
                                                    let id_for_delete = id.clone();
                                                    view! {
                                                        <tr style="border-bottom: 1px solid #dee2e6;">
                                                            <td style="padding: 15px;">
                                                                <div style="font-weight: 600;">{org.display_name.unwrap_or(org.name.clone())}</div>
                                                                <div style="font-size: 0.8em; color: #6c757d;">{org.name}</div>
                                                            </td>
                                                            <td style="padding: 15px;">{org.domain.unwrap_or_else(|| "-".to_string())}</td>
                                                            <td style="padding: 15px;">
                                                                <span style={if org.enabled {
                                                                    "background: #d4edda; color: #155724; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;"
                                                                } else {
                                                                    "background: #f8d7da; color: #721c24; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;"
                                                                }}>
                                                                    {if org.enabled { "Active" } else { "Disabled" }}
                                                                </span>
                                                            </td>
                                                            <td style="padding: 15px;">
                                                                <button
                                                                    on:click=move |_| {
                                                                        set_selected_org_id.set(Some(id_for_members.clone()));
                                                                        set_show_members_modal.set(true);
                                                                    }
                                                                    style="margin-right: 8px; padding: 6px 12px; border: 1px solid #dee2e6; background: white; border-radius: 4px; cursor: pointer; color: #495057;">
                                                                    <i class="fas fa-users"></i> " Members"
                                                                </button>
                                                                <button
                                                                    on:click=move |_| {
                                                                        if gloo_utils::window().confirm_with_message("Are you sure you want to delete this organization?").unwrap_or(false) {
                                                                            delete_org_action.dispatch(id_for_delete.clone());
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

            <Modal
                is_open=show_members_modal
                on_close=move |_| set_show_members_modal.set(false)
                title="Organization Members"
            >
                <div class="members-modal">
                    <Suspense fallback=move || view! { <p>"Loading members..."</p> }>
                        {move || {
                            members_resource.get().map(|res| {
                                match res {
                                    Ok(members) => {
                                        if members.is_empty() {
                                            view! { <p>"No members found."</p> }.into_view()
                                        } else {
                                            view! {
                                                <table style="width: 100%; border-collapse: collapse;">
                                                    <thead>
                                                        <tr style="background: #f8f9fa; border-bottom: 1px solid #dee2e6;">
                                                            <th style="padding: 10px; text-align: left;">"User ID"</th>
                                                            <th style="padding: 10px; text-align: left;">"Role"</th>
                                                            <th style="padding: 10px; text-align: left;">"Joined At"</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {members.into_iter().map(|member| {
                                                            view! {
                                                                <tr style="border-bottom: 1px solid #eee;">
                                                                    <td style="padding: 10px; font-size: 0.9em;">{member.user_id}</td>
                                                                    <td style="padding: 10px;">{member.role}</td>
                                                                    <td style="padding: 10px; font-size: 0.9em;">{member.joined_at.unwrap_or_else(|| "-".to_string())}</td>
                                                                </tr>
                                                            }
                                                        }).collect_view()}
                                                    </tbody>
                                                </table>
                                            }.into_view()
                                        }
                                    }
                                    Err(e) => view! { <p style="color: red;">{e}</p> }.into_view()
                                }
                            })
                        }}
                    </Suspense>
                    <div style="margin-top: 20px; display: flex; justify-content: flex-end;">
                        <button
                            on:click=move |_| set_show_members_modal.set(false)
                            style="padding: 8px 16px; border: 1px solid #ccc; background: white; border-radius: 4px; cursor: pointer;">
                            "Close"
                        </button>
                    </div>
                </div>
            </Modal>

            <Modal
                is_open=show_create_modal
                on_close=move |_| set_show_create_modal.set(false)
                title="Create Organization"
            >
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Name (Unique Identifier)"</label>
                        <input
                            type="text"
                            style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;"
                            on:input=move |ev| set_new_org_name.set(event_target_value(&ev))
                            prop:value=new_org_name
                        />
                    </div>
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Display Name"</label>
                        <input
                            type="text"
                            style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;"
                            on:input=move |ev| set_new_org_display_name.set(event_target_value(&ev))
                            prop:value=new_org_display_name
                        />
                    </div>
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Domain (optional)"</label>
                        <input
                            type="text"
                            placeholder="example.com"
                            style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;"
                            on:input=move |ev| set_new_org_domain.set(event_target_value(&ev))
                            prop:value=new_org_domain
                        />
                    </div>
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Description (optional)"</label>
                        <textarea
                            style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; min-height: 80px;"
                            on:input=move |ev| set_new_org_description.set(event_target_value(&ev))
                            prop:value=new_org_description
                        ></textarea>
                    </div>
                    <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 10px;">
                        <button
                            on:click=move |_| set_show_create_modal.set(false)
                            style="padding: 10px 20px; border: 1px solid #ccc; background: white; border-radius: 4px; cursor: pointer;">
                            "Cancel"
                        </button>
                        <button
                            on:click=move |_| create_org_action.dispatch(())
                            style="padding: 10px 20px; border: none; background: #28a745; color: white; border-radius: 4px; cursor: pointer; font-weight: bold;">
                            "Create"
                        </button>
                    </div>
                </div>
            </Modal>
        </div>
    }
}
