use leptos::*;
use crate::models::{Role, CreateRoleRequest};
use crate::api_client::authenticated_request;
use crate::components::modal::Modal;
use crate::utils::get_realm_id;

#[component]
pub fn Roles() -> impl IntoView {
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);
    let (show_create_modal, set_show_create_modal) = create_signal(false);

    // Form signals
    let (new_role_name, set_new_role_name) = create_signal(String::new());
    let (new_role_description, set_new_role_description) = create_signal(String::new());

    let roles_resource = create_resource(
        || (),
        move |_| async move {
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
            name: new_role_name.get(),
            description: Some(new_role_description.get()).filter(|s| !s.is_empty()),
        };

        let url = format!("/api/v1/auth/realms/{}/roles", realm_id);
        match authenticated_request("POST", &url, Some(&req)).await {
            Ok(response) => {
                if response.ok() {
                    set_show_create_modal.set(false);
                    set_new_role_name.set(String::new());
                    set_new_role_description.set(String::new());
                    roles_resource.refetch();
                } else {
                    set_error_message.set(Some(format!("Failed to create role: {}", response.status())));
                }
            }
            Err(e) => set_error_message.set(Some(e)),
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
                    on:click=move |_| set_show_create_modal.set(true)
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
                                    }.into_view()
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
                                    }.into_view()
                                }
                            },
                            Err(_) => view! {
                                <div style="padding: 20px; text-align: center; color: #dc3545;">
                                    "Error loading roles."
                                </div>
                            }.into_view()
                        }
                    })
                }}
                </Suspense>
            </div>

            <Modal
                is_open=show_create_modal
                on_close=move |_| set_show_create_modal.set(false)
                title="Create Role"
            >
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Name"</label>
                        <input
                            type="text"
                            style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;"
                            on:input=move |ev| set_new_role_name.set(event_target_value(&ev))
                            prop:value=new_role_name
                        />
                    </div>
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Description"</label>
                        <input
                            type="text"
                            style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;"
                            on:input=move |ev| set_new_role_description.set(event_target_value(&ev))
                            prop:value=new_role_description
                        />
                    </div>
                    <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 10px;">
                        <button
                            on:click=move |_| set_show_create_modal.set(false)
                            style="padding: 10px 20px; border: 1px solid #ccc; background: white; border-radius: 4px; cursor: pointer;">
                            "Cancel"
                        </button>
                        <button
                            on:click=move |_| create_role_action.dispatch(())
                            style="padding: 10px 20px; border: none; background: #28a745; color: white; border-radius: 4px; cursor: pointer; font-weight: bold;">
                            "Create"
                        </button>
                    </div>
                </div>
            </Modal>
        </div>
    }
}
