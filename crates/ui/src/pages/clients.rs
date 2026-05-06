use leptos::*;
use crate::models::{ClientResponse, CreateClientRequest, UpdateClientRequest};
use crate::api_client::authenticated_request;
use crate::components::modal::Modal;
use crate::utils::get_realm_id;

#[component]
pub fn Clients() -> impl IntoView {
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);
    let (show_create_modal, set_show_create_modal) = create_signal(false);
    let (show_edit_modal, set_show_edit_modal) = create_signal(false);
    let (selected_client, set_selected_client) = create_signal::<Option<ClientResponse>>(None);

    // Form signals
    let (client_id, set_client_id) = create_signal(String::new());
    let (client_name, set_client_name) = create_signal(String::new());
    let (client_secret, set_client_secret) = create_signal(String::new());
    let (redirect_uris, set_redirect_uris) = create_signal(String::new());
    let (enabled, set_enabled) = create_signal(true);

    let clients_resource = create_resource(
        || (),
        move |_| async move {
            set_error_message.set(None);
            let realm_id = get_realm_id();
            let url = format!("/api/v1/auth/realms/{}/clients", realm_id);

            match authenticated_request("GET", &url, None::<&()>).await {
                Ok(response) => {
                    if response.ok() {
                        response.json::<Vec<ClientResponse>>().await.map_err(|e| e.to_string())
                    } else {
                        let msg = format!("Failed to fetch clients: {}", response.status());
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

    let create_client_action = create_action(move |_: &()| async move {
        let realm_id = get_realm_id();
        let uris = redirect_uris.get()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let req = CreateClientRequest {
            client_id: client_id.get(),
            name: client_name.get(),
            client_secret: client_secret.get(),
            redirect_uris: uris,
            enabled: enabled.get(),
        };

        let url = format!("/api/v1/auth/realms/{}/clients", realm_id);
        match authenticated_request("POST", &url, Some(&req)).await {
            Ok(response) => {
                if response.ok() {
                    set_show_create_modal.set(false);
                    clients_resource.refetch();
                } else {
                    set_error_message.set(Some(format!("Failed to create client: {}", response.status())));
                }
            }
            Err(e) => set_error_message.set(Some(e)),
        }
    });

    let update_client_action = create_action(move |_: &()| async move {
        let Some(client) = selected_client.get() else { return };
        let realm_id = get_realm_id();
        let uris = redirect_uris.get()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let req = UpdateClientRequest {
            name: Some(client_name.get()),
            enabled: Some(enabled.get()),
            redirect_uris: Some(uris),
            client_secret: Some(client_secret.get()).filter(|s| !s.is_empty()),
        };

        let url = format!("/api/v1/auth/realms/{}/clients/{}", realm_id, client.client_id);
        match authenticated_request("PUT", &url, Some(&req)).await {
            Ok(res) if res.ok() => {
                set_show_edit_modal.set(false);
                clients_resource.refetch();
            }
            _ => set_error_message.set(Some("Failed to update client".to_string())),
        }
    });

    let delete_client_action = create_action(move |id: &String| {
        let id = id.clone();
        async move {
            let realm_id = get_realm_id();
            let url = format!("/api/v1/auth/realms/{}/clients/{}", realm_id, id);
            match authenticated_request("DELETE", &url, None::<&()>).await {
                Ok(response) => {
                    if response.ok() {
                        clients_resource.refetch();
                    } else {
                        set_error_message.set(Some(format!("Failed to delete client: {}", response.status())));
                    }
                }
                Err(e) => set_error_message.set(Some(e)),
            }
        }
    });

    view! {
        <div class="clients-page">
            <div class="header-actions" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="margin: 0;">"Clients"</h2>
                <button
                    on:click=move |_| {
                        set_client_id.set(String::new());
                        set_client_name.set(String::new());
                        set_client_secret.set(String::new());
                        set_redirect_uris.set(String::new());
                        set_enabled.set(true);
                        set_show_create_modal.set(true);
                    }
                    style="background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                    <i class="fas fa-plus" style="margin-right: 5px;"></i> "Create Client"
                </button>
            </div>

            {move || error_message.get().map(|msg| view! {
                <div style="color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; padding: .75rem 1.25rem; margin-bottom: 1rem; border: 1px solid transparent; border-radius: .25rem;">
                    {msg}
                </div>
            })}

            <div class="table-container" style="background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;">
                <Suspense fallback=move || view! { <div style="padding: 20px; text-align: center;">"Loading clients..."</div> }>
                {move || {
                    clients_resource.get().map(|res| {
                        match res {
                            Ok(clients) => {
                                if clients.is_empty() {
                                    view! {
                                        <div style="padding: 20px; text-align: center; color: #6c757d;">
                                            "No clients found."
                                        </div>
                                    }.into_view()
                                } else {
                                    view! {
                                        <table style="width: 100%; border-collapse: collapse;">
                                            <thead>
                                                <tr style="background: #f8f9fa; border-bottom: 1px solid #dee2e6;">
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Client ID"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Name"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Status"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Actions"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {clients.into_iter().map(|client| {
                                                    let c1 = client.clone();
                                                    let id = client.client_id.clone();
                                                    let id_for_delete = id.clone();
                                                    view! {
                                                        <tr style="border-bottom: 1px solid #dee2e6;">
                                                            <td style="padding: 15px;">{client.client_id}</td>
                                                            <td style="padding: 15px;">{client.name}</td>
                                                            <td style="padding: 15px;">
                                                                <span style={if client.enabled {
                                                                    "background: #d4edda; color: #155724; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;"
                                                                } else {
                                                                    "background: #f8d7da; color: #721c24; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;"
                                                                }}>
                                                                    {if client.enabled { "Enabled" } else { "Disabled" }}
                                                                </span>
                                                            </td>
                                                            <td style="padding: 15px;">
                                                                <button
                                                                    on:click=move |_| {
                                                                        set_client_name.set(c1.name.clone());
                                                                        set_redirect_uris.set(c1.redirect_uris.join(", "));
                                                                        set_enabled.set(c1.enabled);
                                                                        set_client_secret.set(String::new());
                                                                        set_selected_client.set(Some(c1.clone()));
                                                                        set_show_edit_modal.set(true);
                                                                    }
                                                                    style="margin-right: 8px; padding: 6px 12px; border: 1px solid #dee2e6; background: white; border-radius: 4px; cursor: pointer; color: #495057;">
                                                                    "Edit"
                                                                </button>
                                                                <button
                                                                    on:click=move |_| {
                                                                        if gloo_utils::window().confirm_with_message(&format!("Are you sure you want to delete client '{}'?", id_for_delete)).unwrap_or(false) {
                                                                            delete_client_action.dispatch(id_for_delete.clone());
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
                                    "Error loading clients."
                                </div>
                            }.into_view()
                        }
                    })
                }}
                </Suspense>
            </div>

            <Modal is_open=show_create_modal on_close=move |_| set_show_create_modal.set(false) title="Create Client">
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    <input type="text" placeholder="Client ID" on:input=move |ev| set_client_id.set(event_target_value(&ev)) prop:value=client_id style="padding: 8px;" />
                    <input type="text" placeholder="Name" on:input=move |ev| set_client_name.set(event_target_value(&ev)) prop:value=client_name style="padding: 8px;" />
                    <input type="password" placeholder="Client Secret" on:input=move |ev| set_client_secret.set(event_target_value(&ev)) prop:value=client_secret style="padding: 8px;" />
                    <input type="text" placeholder="Redirect URIs (comma separated)" on:input=move |ev| set_redirect_uris.set(event_target_value(&ev)) prop:value=redirect_uris style="padding: 8px;" />
                    <label style="display: flex; align-items: center; gap: 10px;">
                        <input type="checkbox" on:change=move |ev| set_enabled.set(event_target_checked(&ev)) prop:checked=enabled />
                        "Enabled"
                    </label>
                    <button on:click=move |_| create_client_action.dispatch(()) style="padding: 10px; background: #28a745; color: white; border: none; cursor: pointer;">"Create"</button>
                </div>
            </Modal>

            <Modal is_open=show_edit_modal on_close=move |_| set_show_edit_modal.set(false) title="Edit Client">
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    <input type="text" placeholder="Name" on:input=move |ev| set_client_name.set(event_target_value(&ev)) prop:value=client_name style="padding: 8px;" />
                    <input type="password" placeholder="Client Secret (optional)" on:input=move |ev| set_client_secret.set(event_target_value(&ev)) prop:value=client_secret style="padding: 8px;" />
                    <input type="text" placeholder="Redirect URIs (comma separated)" on:input=move |ev| set_redirect_uris.set(event_target_value(&ev)) prop:value=redirect_uris style="padding: 8px;" />
                    <label style="display: flex; align-items: center; gap: 10px;">
                        <input type="checkbox" on:change=move |ev| set_enabled.set(event_target_checked(&ev)) prop:checked=enabled />
                        "Enabled"
                    </label>
                    <button on:click=move |_| update_client_action.dispatch(()) style="padding: 10px; background: #007bff; color: white; border: none; cursor: pointer;">"Save Changes"</button>
                </div>
            </Modal>
        </div>
    }
}
