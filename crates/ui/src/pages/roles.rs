use leptos::prelude::*;
use crate::models::{Role, CreateRoleRequest};
use crate::api_client::authenticated_request;
use crate::components::modal::Modal;
use crate::utils::get_realm_id;

#[component]
pub fn Roles() -> impl IntoView {
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);
    let (show_create_modal, set_show_create_modal) = signal(false);
    let (show_edit_modal, set_show_edit_modal) = signal(false);
    let (selected_role, set_selected_role) = create_signal::<Option<Role>>(None);

    // Form signals
    let (role_name, set_role_name) = signal(String::new());
    let (role_description, set_role_description) = signal(String::new());

    let roles_resource = LocalResource::new(move |_| async move {
            set_error_message.set(None);
            let realm_id = get_realm_id();
            let url = format!("/api/v1/auth/realms/{}/roles", realm_id);

            match authenticated_request("GET", &url, None::<&()>).await {
                Ok(response) => {
                    if response.ok() {
                        response.json::<Vec<Role>>().await.map_err(|e| e.to_string())
                    } else {
                        let msg = format!("Failed to fetch roles: {}", response.status());
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

    let create_role_action = create_action(move |_: &()| async move {
        let realm_id = get_realm_id();
        let req = CreateRoleRequest {
            name: role_name.get(),
            description: Some(role_description.get()).filter(|s| !s.is_empty()),
        };

        let url = format!("/api/v1/auth/realms/{}/roles", realm_id);
        match authenticated_request("POST", &url, Some(&req)).await {
            Ok(response) => {
                if response.ok() {
                    set_show_create_modal.set(false);
                    roles_resource.refetch();
                } else {
                    set_error_message.set(Some(format!("Failed to create role: {}", response.status())));
                }
            }
            Err(e) => set_error_message.set(Some(e)),
        }
    });

    let update_role_action = create_action(move |_: &()| async move {
        let Some(role) = selected_role.get() else { return };
        let realm_id = get_realm_id();
        let req = CreateRoleRequest {
            name: role_name.get(),
            description: Some(role_description.get()).filter(|s| !s.is_empty()),
        };

        let url = format!("/api/v1/auth/realms/{}/roles/{}", realm_id, urlencoding::encode(&role.name));
        match authenticated_request("PUT", &url, Some(&req)).await {
            Ok(res) if res.ok() => {
                set_show_edit_modal.set(false);
                roles_resource.refetch();
            }
            _ => set_error_message.set(Some("Failed to update role".to_string())),
        }
    });

    let delete_role_action = create_action(move |name: &String| {
        let name = name.clone();
        async move {
            let realm_id = get_realm_id();
            let url = format!("/api/v1/auth/realms/{}/roles/{}", realm_id, urlencoding::encode(&name));
            match authenticated_request("DELETE", &url, None::<&()>).await {
                Ok(response) => {
                    if response.ok() {
                        roles_resource.refetch();
                    } else {
                        set_error_message.set(Some(format!("Failed to delete role: {}", response.status())));
                    }
                }
                Err(e) => set_error_message.set(Some(e)),
            }
        }
    });

    view! {
        <div class="roles-page">
            <div class="header-actions" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="margin: 0;">"Roles"</h2>
                <button
                    on:click=move |_| {
                        set_role_name.set(String::new());
                        set_role_description.set(String::new());
                        set_show_create_modal.set(true);
                    }
                    style="background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                    <i class="fas fa-plus" style="margin-right: 5px;"></i> "Create Role"
                </button>
            </div>

            {move || error_message.get().map(|msg| view! {
                <div style="color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; padding: .75rem 1.25rem; margin-bottom: 1rem; border: 1px solid transparent; border-radius: .25rem;">
                    {msg}
                </div>
            })}

            <div class="table-container" style="background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;">
                <Suspense fallback=move || view! { <div style="padding: 20px; text-align: center;">"Loading roles..."</div> }>
                {move || {
                    roles_resource.get().map(|res| {
                        match res {
                            Ok(roles) => {
                                if roles.is_empty() {
                                    view! {
                                        <div style="padding: 20px; text-align: center; color: #6c757d;">
                                            "No roles found."
                                        </div>
                                    }.into_any()
                                } else {
                                    view! {
                                        <table style="width: 100%; border-collapse: collapse;">
                                            <thead>
                                                <tr style="background: #f8f9fa; border-bottom: 1px solid #dee2e6;">
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Role Name"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Description"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Composite"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Actions"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {roles.into_iter().map(|role| {
                                                    let r1 = role.clone();
                                                    let name = role.name.clone();
                                                    let name_for_delete = name.clone();
                                                    view! {
                                                        <tr style="border-bottom: 1px solid #dee2e6;">
                                                            <td style="padding: 15px;">{role.name}</td>
                                                            <td style="padding: 15px;">{role.description.unwrap_or_default()}</td>
                                                            <td style="padding: 15px;">{if role.composite { "True" } else { "False" }}</td>
                                                            <td style="padding: 15px;">
                                                                <button
                                                                    on:click=move |_| {
                                                                        set_role_name.set(r1.name.clone());
                                                                        set_role_description.set(r1.description.clone().unwrap_or_default());
                                                                        set_selected_role.set(Some(r1.clone()));
                                                                        set_show_edit_modal.set(true);
                                                                    }
                                                                    style="margin-right: 8px; padding: 6px 12px; border: 1px solid #dee2e6; background: white; border-radius: 4px; cursor: pointer; color: #495057;">
                                                                    "Edit"
                                                                </button>
                                                                <button
                                                                    on:click=move |_| {
                                                                        if gloo_utils::window().confirm_with_message(&format!("Are you sure you want to delete role '{}'?", name_for_delete)).unwrap_or(false) {
                                                                            delete_role_action.dispatch(name_for_delete.clone());
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
                                    }.into_any()
                                }
                            },
                            Err(_) => view! {
                                <div style="padding: 20px; text-align: center; color: #dc3545;">
                                    "Error loading roles."
                                </div>
                            }.into_any()
                        }
                    })
                }}
                </Suspense>
            </div>

            <Modal is_open=show_create_modal on_close=move |_| set_show_create_modal.set(false) title="Create Role">
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    <input type="text" placeholder="Name" on:input=move |ev| set_role_name.set(event_target_value(&ev)) prop:value=role_name style="padding: 8px;" />
                    <input type="text" placeholder="Description" on:input=move |ev| set_role_description.set(event_target_value(&ev)) prop:value=role_description style="padding: 8px;" />
                    <button on:click=move |_| create_role_action.dispatch(()) style="padding: 10px; background: #28a745; color: white; border: none; cursor: pointer;">"Create"</button>
                </div>
            </Modal>

            <Modal is_open=show_edit_modal on_close=move |_| set_show_edit_modal.set(false) title="Edit Role">
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    <input type="text" placeholder="Name" on:input=move |ev| set_role_name.set(event_target_value(&ev)) prop:value=role_name style="padding: 8px;" />
                    <input type="text" placeholder="Description" on:input=move |ev| set_role_description.set(event_target_value(&ev)) prop:value=role_description style="padding: 8px;" />
                    <button on:click=move |_| update_role_action.dispatch(()) style="padding: 10px; background: #007bff; color: white; border: none; cursor: pointer;">"Save Changes"</button>
                </div>
            </Modal>
        </div>
    }
}
