use leptos::prelude::*;
use crate::models::{Group, CreateGroupRequest, UpdateGroupRequest};
use crate::api_client::authenticated_request;
use crate::components::modal::Modal;

fn get_realm_id() -> String {
    if let Ok(Some(storage)) = gloo_utils::window().local_storage() {
        if let Ok(Some(id)) = storage.get_item("authenc_selected_realm_id") {
            return id;
        }
    }
    // Fallback
    "550e8400-e29b-41d4-a716-446655440000".to_string()
}

#[component]
pub fn Groups() -> impl IntoView {
    // State for modals
    let (show_create_modal, set_show_create_modal) = signal(false);
    let (show_edit_modal, set_show_edit_modal) = signal(false);
    let (show_delete_modal, set_show_delete_modal) = signal(false);

    // State for form data
    let (selected_group, set_selected_group) = create_signal::<Option<Group>>(None);
    let (group_name, set_group_name) = signal(String::new());
    let (group_description, set_group_description) = signal(String::new());
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);

    // Resource to fetch groups
    let groups_resource = LocalResource::new(|_| async move {
            let realm_id = get_realm_id();
            let url = format!("/api/v1/auth/realms/{}/groups", realm_id);

            match authenticated_request("GET", &url, None::<&()>).await {
                Ok(resp) => {
                    if resp.ok() {
                        resp.json::<Vec<Group>>().await.map_err(|e| e.to_string())
                    } else {
                        Err(format!("Error fetching groups: {} (Realm: {})", resp.status(), realm_id))
                    }
                }
                Err(e) => Err(e),
            }
        },
    );

    // Actions
    let create_group = move |_| {
        set_error_message.set(None);
        let name = group_name.get();
        let description = group_description.get();
        let realm_id = get_realm_id();

        if name.trim().is_empty() {
            set_error_message.set(Some("Group name is required".to_string()));
            return;
        }

        spawn_local(async move {
            let req = CreateGroupRequest {
                name,
                description: if description.is_empty() { None } else { Some(description) },
                realm_id: realm_id.clone(),
            };

            let url = format!("/api/v1/auth/realms/{}/groups", realm_id);

            match authenticated_request("POST", &url, Some(&req)).await {
                Ok(resp) => {
                    if resp.ok() {
                        set_show_create_modal.set(false);
                        set_group_name.set(String::new());
                        set_group_description.set(String::new());
                        groups_resource.refetch();
                    } else {
                        set_error_message.set(Some(format!("Failed to create group: {}", resp.status())));
                    }
                }
                Err(e) => set_error_message.set(Some(format!("Error: {}", e))),
            }
        });
    };

    let update_group = move |_| {
        set_error_message.set(None);
        let Some(group) = selected_group.get() else { return };
        let name = group_name.get();
        let description = group_description.get();
        let realm_id = get_realm_id();

        if name.trim().is_empty() {
            set_error_message.set(Some("Group name is required".to_string()));
            return;
        }

        spawn_local(async move {
            let req = UpdateGroupRequest {
                name: Some(name),
                description: Some(description),
            };

            let url = format!("/api/v1/auth/realms/{}/groups/{}", realm_id, group.id);

            match authenticated_request("PUT", &url, Some(&req)).await {
                Ok(resp) => {
                    if resp.ok() {
                        set_show_edit_modal.set(false);
                        set_selected_group.set(None);
                        groups_resource.refetch();
                    } else {
                        set_error_message.set(Some(format!("Failed to update group: {}", resp.status())));
                    }
                }
                Err(e) => set_error_message.set(Some(format!("Error: {}", e))),
            }
        });
    };

    let delete_group = move |_| {
        set_error_message.set(None);
        let Some(group) = selected_group.get() else { return };
        let realm_id = get_realm_id();

        spawn_local(async move {
            let url = format!("/api/v1/auth/realms/{}/groups/{}", realm_id, group.id);

            match authenticated_request("DELETE", &url, None::<&()>).await {
                Ok(resp) => {
                    if resp.ok() {
                        set_show_delete_modal.set(false);
                        set_selected_group.set(None);
                        groups_resource.refetch();
                    } else {
                        set_error_message.set(Some(format!("Failed to delete group: {}", resp.status())));
                    }
                }
                Err(e) => set_error_message.set(Some(format!("Error: {}", e))),
            }
        });
    };

    let open_create_modal = move |_| {
        set_group_name.set(String::new());
        set_group_description.set(String::new());
        set_error_message.set(None);
        set_show_create_modal.set(true);
    };

    let open_edit_modal = move |group: Group| {
        set_group_name.set(group.name.clone());
        set_group_description.set(group.description.clone().unwrap_or_default());
        set_selected_group.set(Some(group));
        set_error_message.set(None);
        set_show_edit_modal.set(true);
    };

    let open_delete_modal = move |group: Group| {
        set_selected_group.set(Some(group));
        set_error_message.set(None);
        set_show_delete_modal.set(true);
    };

    view! {
        <div class="groups-page">
            <div class="header-actions" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="margin: 0;">"Groups"</h2>
                <button
                    style="background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;"
                    on:click=open_create_modal
                >
                    <i class="fas fa-plus" style="margin-right: 5px;"></i> "Create Group"
                </button>
            </div>

            <div class="table-container" style="background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;">
                <table style="width: 100%; border-collapse: collapse;">
                    <thead>
                        <tr style="background: #f8f9fa; border-bottom: 1px solid #dee2e6;">
                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Name"</th>
                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Path"</th>
                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Description"</th>
                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Members"</th>
                            <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Actions"</th>
                        </tr>
                    </thead>
                    <tbody>
                        <Suspense fallback=move || view! { <tr><td colspan="5" style="padding: 15px; text-align: center;">"Loading groups..."</td></tr> }>
                            {move || {
                                groups_resource.get().map(|result| match result {
                                    Ok(groups) => {
                                        if groups.is_empty() {
                                            view! { <tr><td colspan="5" style="padding: 15px; text-align: center; color: #6c757d;">"No groups found"</td></tr> }.into_any()
                                        } else {
                                            groups.into_iter().map(|group| {
                                                let group_clone_edit = group.clone();
                                                let group_clone_delete = group.clone();
                                                view! {
                                                    <tr style="border-bottom: 1px solid #dee2e6;">
                                                        <td style="padding: 15px;">{group.name}</td>
                                                        <td style="padding: 15px;">{group.path}</td>
                                                        <td style="padding: 15px;">{group.description.unwrap_or_default()}</td>
                                                        <td style="padding: 15px;">
                                                            <span style="background: #e9ecef; color: #495057; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;">
                                                                {group.member_count} " members"
                                                            </span>
                                                        </td>
                                                        <td style="padding: 15px;">
                                                            <button
                                                                style="margin-right: 8px; padding: 6px 12px; border: 1px solid #dee2e6; background: white; border-radius: 4px; cursor: pointer; color: #495057;"
                                                                on:click=move |_| open_edit_modal(group_clone_edit.clone())
                                                            >
                                                                <i class="fas fa-edit"></i> " Edit"
                                                            </button>
                                                            <button
                                                                style="padding: 6px 12px; border: 1px solid #dc3545; background: white; border-radius: 4px; cursor: pointer; color: #dc3545;"
                                                                on:click=move |_| open_delete_modal(group_clone_delete.clone())
                                                            >
                                                                <i class="fas fa-trash"></i>
                                                            </button>
                                                        </td>
                                                    </tr>
                                                }
                                            }).collect_view()
                                        }
                                    }
                                    Err(e) => view! { <tr><td colspan="5" style="padding: 15px; text-align: center; color: #dc3545;">"Error loading groups: " {e}</td></tr> }.into_any()
                                })
                            }}
                        </Suspense>
                    </tbody>
                </table>
            </div>

            // Create Modal
            <Modal
                title="Create Group"
                is_open=show_create_modal
                on_close=move |_| set_show_create_modal.set(false)
            >
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    {move || error_message.get().map(|msg| view! { <div style="color: red; padding: 10px; background: #ffe6e6; border-radius: 4px;">{msg}</div> })}
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 500;">"Name"</label>
                        <input
                            type="text"
                            style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;"
                            prop:value=group_name
                            on:input=move |ev| set_group_name.set(event_target_value(&ev))
                        />
                    </div>
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 500;">"Description"</label>
                        <textarea
                            style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; min-height: 80px;"
                            prop:value=group_description
                            on:input=move |ev| set_group_description.set(event_target_value(&ev))
                        />
                    </div>
                    <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 10px;">
                        <button
                            style="padding: 8px 16px; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer;"
                            on:click=move |_| set_show_create_modal.set(false)
                        >
                            "Cancel"
                        </button>
                        <button
                            style="padding: 8px 16px; border: none; background: #28a745; color: white; border-radius: 4px; cursor: pointer;"
                            on:click=create_group
                        >
                            "Create"
                        </button>
                    </div>
                </div>
            </Modal>

            // Edit Modal
            <Modal
                title="Edit Group"
                is_open=show_edit_modal
                on_close=move |_| set_show_edit_modal.set(false)
            >
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    {move || error_message.get().map(|msg| view! { <div style="color: red; padding: 10px; background: #ffe6e6; border-radius: 4px;">{msg}</div> })}
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 500;">"Name"</label>
                        <input
                            type="text"
                            style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;"
                            prop:value=group_name
                            on:input=move |ev| set_group_name.set(event_target_value(&ev))
                        />
                    </div>
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 500;">"Description"</label>
                        <textarea
                            style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; min-height: 80px;"
                            prop:value=group_description
                            on:input=move |ev| set_group_description.set(event_target_value(&ev))
                        />
                    </div>
                    <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 10px;">
                        <button
                            style="padding: 8px 16px; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer;"
                            on:click=move |_| set_show_edit_modal.set(false)
                        >
                            "Cancel"
                        </button>
                        <button
                            style="padding: 8px 16px; border: none; background: #007bff; color: white; border-radius: 4px; cursor: pointer;"
                            on:click=update_group
                        >
                            "Save Changes"
                        </button>
                    </div>
                </div>
            </Modal>

            // Delete Modal
            <Modal
                title="Delete Group"
                is_open=show_delete_modal
                on_close=move |_| set_show_delete_modal.set(false)
            >
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    {move || error_message.get().map(|msg| view! { <div style="color: red; padding: 10px; background: #ffe6e6; border-radius: 4px;">{msg}</div> })}
                    <p>
                        "Are you sure you want to delete group "
                        <strong>{move || selected_group.get().map(|g| g.name).unwrap_or_default()}</strong>
                        "?"
                    </p>
                    <p style="color: #666; font-size: 0.9em;">
                        "This action cannot be undone."
                    </p>
                    <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 10px;">
                        <button
                            style="padding: 8px 16px; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer;"
                            on:click=move |_| set_show_delete_modal.set(false)
                        >
                            "Cancel"
                        </button>
                        <button
                            style="padding: 8px 16px; border: none; background: #dc3545; color: white; border-radius: 4px; cursor: pointer;"
                            on:click=delete_group
                        >
                            "Delete"
                        </button>
                    </div>
                </div>
            </Modal>
        </div>
    }
}
