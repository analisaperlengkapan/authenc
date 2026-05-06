use leptos::*;
use crate::models::{ClientResponse, CreateClientRequest};
use crate::api_client::authenticated_request;
use crate::components::modal::Modal;
use crate::utils::get_realm_id;

#[component]
pub fn Clients() -> impl IntoView {
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);
    let (show_create_modal, set_show_create_modal) = create_signal(false);

    // Form signals
    let (client_id, set_client_id) = create_signal(String::new());
    let (client_name, set_client_name) = create_signal(String::new());
    let (client_secret, set_client_secret) = create_signal(String::new());
    let (redirect_uris, set_redirect_uris) = create_signal(String::new());

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
            enabled: true,
        };

        let url = format!("/api/v1/auth/realms/{}/clients", realm_id);
        match authenticated_request("POST", &url, Some(&req)).await {
            Ok(response) => {
                if response.ok() {
                    set_show_create_modal.set(false);
                    set_client_id.set(String::new());
                    set_client_name.set(String::new());
                    set_client_secret.set(String::new());
                    set_redirect_uris.set(String::new());
                    clients_resource.refetch();
                } else {
                    set_error_message.set(Some(format!("Failed to create client: {}", response.status())));
                }
            }
            Err(e) => set_error_message.set(Some(e)),
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
                    on:click=move |_| set_show_create_modal.set(true)
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

            <Modal
                is_open=show_create_modal
                on_close=move |_| set_show_create_modal.set(false)
                title="Create Client"
            >
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Client ID"</label>
                        <input
                            type="text"
                            style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;"
                            on:input=move |ev| set_client_id.set(event_target_value(&ev))
                            prop:value=client_id
                        />
                    </div>
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Name"</label>
                        <input
                            type="text"
                            style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;"
                            on:input=move |ev| set_client_name.set(event_target_value(&ev))
                            prop:value=client_name
                        />
                    </div>
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Client Secret"</label>
                        <input
                            type="password"
                            style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;"
                            on:input=move |ev| set_client_secret.set(event_target_value(&ev))
                            prop:value=client_secret
                        />
                    </div>
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Redirect URIs (comma separated)"</label>
                        <input
                            type="text"
                            placeholder="https://app.com/callback, http://localhost:8080"
                            style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;"
                            on:input=move |ev| set_redirect_uris.set(event_target_value(&ev))
                            prop:value=redirect_uris
                        />
                    </div>
                    <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 10px;">
                        <button
                            on:click=move |_| set_show_create_modal.set(false)
                            style="padding: 10px 20px; border: 1px solid #ccc; background: white; border-radius: 4px; cursor: pointer;">
                            "Cancel"
                        </button>
                        <button
                            on:click=move |_| create_client_action.dispatch(())
                            style="padding: 10px 20px; border: none; background: #28a745; color: white; border-radius: 4px; cursor: pointer; font-weight: bold;">
                            "Create"
                        </button>
                    </div>
                </div>
            </Modal>
        </div>
    }
}
