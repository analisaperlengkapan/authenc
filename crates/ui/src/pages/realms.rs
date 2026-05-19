use leptos::*;
use crate::api_client::authenticated_request;
use uuid::Uuid;
use crate::models::{RealmResponse, CreateRealmRequest, UpdateRealmRequest};
use crate::components::modal::Modal;

fn switch_realm(realm_id: Uuid) {
    if let Ok(Some(storage)) = gloo_utils::window().local_storage() {
        let _ = storage.set_item("authenc_realm_id", &realm_id.to_string());
        // Reload page to refresh all components with the new realm context
        let _ = gloo_utils::window().location().reload();
    }
}

#[component]
pub fn Realms() -> impl IntoView {
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);
    let (show_create_modal, set_show_create_modal) = create_signal(false);
    let (show_edit_modal, set_show_edit_modal) = create_signal(false);
    let (selected_realm, set_selected_realm) = create_signal::<Option<RealmResponse>>(None);

    // Form signals
    let (realm_name, set_realm_name) = create_signal(String::new());
    let (display_name, set_display_name) = create_signal(String::new());
    let (description, set_description) = create_signal(String::new());
    let (enabled, set_enabled) = create_signal(true);
    let (registration_allowed, set_registration_allowed) = create_signal(false);
    let (verify_email, set_verify_email) = create_signal(false);
    let (reset_password_allowed, set_reset_password_allowed) = create_signal(false);

    let realms_resource = create_resource(
        || (),
        move |_| async move {
            set_error_message.set(None);
            match authenticated_request("GET", "/api/v1/auth/realms", None::<&()>).await {
                Ok(response) => {
                    if response.ok() {
                        response.json::<Vec<RealmResponse>>().await.map_err(|e| e.to_string())
                    } else {
                        let msg = format!("Failed to fetch realms: {}", response.status());
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

    let create_realm_action = create_action(move |_: &()| async move {
        let req = CreateRealmRequest {
            name: realm_name.get(),
            display_name: Some(display_name.get()).filter(|s| !s.is_empty()),
            description: Some(description.get()).filter(|s| !s.is_empty()),
            enabled: Some(enabled.get()),
        };

        match authenticated_request("POST", "/api/v1/auth/realms", Some(&req)).await {
            Ok(res) if res.ok() => {
                set_show_create_modal.set(false);
                realms_resource.refetch();
            }
            _ => set_error_message.set(Some("Failed to create realm".to_string())),
        }
    });

    let update_realm_action = create_action(move |_: &()| async move {
        let Some(realm) = selected_realm.get() else { return };
        let req = UpdateRealmRequest {
            display_name: Some(display_name.get()),
            description: Some(description.get()),
            enabled: Some(enabled.get()),
            registration_allowed: Some(registration_allowed.get()),
            verify_email: Some(verify_email.get()),
            reset_password_allowed: Some(reset_password_allowed.get()),
        };

        let url = format!("/api/v1/auth/realms/{}", realm.id);
        match authenticated_request("PUT", &url, Some(&req)).await {
            Ok(res) if res.ok() => {
                set_show_edit_modal.set(false);
                realms_resource.refetch();
            }
            _ => set_error_message.set(Some("Failed to update realm".to_string())),
        }
    });

    let delete_realm_action = create_action(move |id: &Uuid| {
        let id = *id;
        async move {
            let url = format!("/api/v1/auth/realms/{}", id);
            match authenticated_request("DELETE", &url, None::<&()>).await {
                Ok(res) if res.ok() => realms_resource.refetch(),
                _ => set_error_message.set(Some("Failed to delete realm".to_string())),
            }
        }
    });

    view! {
        <div class="realms-page">
            <div class="header-actions" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="margin: 0;">"Realms"</h2>
                <button
                    on:click=move |_| {
                        set_realm_name.set(String::new());
                        set_display_name.set(String::new());
                        set_description.set(String::new());
                        set_enabled.set(true);
                        set_show_create_modal.set(true);
                    }
                    style="background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                    <i class="fas fa-plus" style="margin-right: 5px;"></i> "Create Realm"
                </button>
            </div>

            {move || error_message.get().map(|msg| view! {
                <div style="color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; padding: .75rem 1.25rem; margin-bottom: 1rem; border: 1px solid transparent; border-radius: .25rem;">
                    {msg}
                </div>
            })}

            <div class="realm-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px;">
                <Suspense fallback=move || view! { <div style="padding: 20px; text-align: center;">"Loading realms..."</div> }>
                {move || {
                    realms_resource.get().map(|res| {
                        match res {
                            Ok(realms) => {
                                if realms.is_empty() {
                                    view! {
                                        <div style="grid-column: 1/-1; padding: 40px; text-align: center; background: white; border-radius: 8px;">
                                            "No realms found. Create one to get started."
                                        </div>
                                    }.into_view()
                                } else {
                                    realms.into_iter().map(|realm| {
                                        let r1 = realm.clone();
                                        let id = realm.id;
                                        let is_master = realm.name == "master";
                                        view! {
                                            <div class="realm-card" style=format!(
                                                "background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 20px; border-top: 4px solid {};",
                                                if is_master { "#007bff" } else { "#6c757d" }
                                            )>
                                                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px;">
                                                    <h3 style="margin: 0; font-size: 1.2rem;">{realm.display_name.unwrap_or(realm.name)}</h3>
                                                    <span style={if realm.enabled {
                                                        "background: #d4edda; color: #155724; padding: 2px 8px; border-radius: 4px; font-size: 0.8em;"
                                                    } else {
                                                        "background: #f8d7da; color: #721c24; padding: 2px 8px; border-radius: 4px; font-size: 0.8em;"
                                                    }}>
                                                        {if realm.enabled { "Enabled" } else { "Disabled" }}
                                                    </span>
                                                </div>
                                                <p style="color: #6c757d; margin-bottom: 20px; min-height: 3em;">
                                                    {realm.description.unwrap_or_else(|| "No description provided.".to_string())}
                                                </p>
                                                <div class="actions" style="border-top: 1px solid #eee; padding-top: 15px; display: flex; justify-content: flex-end; gap: 10px;">
                                                    <button
                                                        on:click=move |_| switch_realm(id)
                                                        style="padding: 6px 12px; border: 1px solid #007bff; background: white; color: #007bff; border-radius: 4px; cursor: pointer;"
                                                    >
                                                        "Manage"
                                                    </button>
                                                    <button
                                                        on:click=move |_| {
                                                            set_display_name.set(r1.display_name.clone().unwrap_or_default());
                                                            set_description.set(r1.description.clone().unwrap_or_default());
                                                            set_enabled.set(r1.enabled);
                                                            set_registration_allowed.set(r1.registration_allowed);
                                                            set_verify_email.set(r1.verify_email);
                                                            set_reset_password_allowed.set(r1.reset_password_allowed);
                                                            set_selected_realm.set(Some(r1.clone()));
                                                            set_show_edit_modal.set(true);
                                                        }
                                                        style="padding: 6px 12px; border: 1px solid #6c757d; background: white; color: #6c757d; border-radius: 4px; cursor: pointer;"
                                                    >
                                                        "Edit"
                                                    </button>
                                                    {(!is_master).then(|| view! {
                                                        <button
                                                            on:click=move |_| {
                                                                if gloo_utils::window().confirm_with_message("Delete realm?").unwrap_or(false) {
                                                                    delete_realm_action.dispatch(id);
                                                                }
                                                            }
                                                            style="padding: 6px 12px; border: 1px solid #dc3545; background: white; color: #dc3545; border-radius: 4px; cursor: pointer;"
                                                        >
                                                            <i class="fas fa-trash"></i>
                                                        </button>
                                                    })}
                                                </div>
                                            </div>
                                        }
                                    }).collect_view()
                                }
                            },
                            Err(_) => view! {
                                <div style="grid-column: 1/-1; padding: 20px; text-align: center; color: #dc3545; background: white; border-radius: 8px;">
                                    "Error loading realms."
                                </div>
                            }.into_view()
                        }
                    })
                }}
                </Suspense>
            </div>

            <Modal is_open=show_create_modal on_close=move |_| set_show_create_modal.set(false) title="Create Realm">
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    <input type="text" placeholder="Name" on:input=move |ev| set_realm_name.set(event_target_value(&ev)) prop:value=realm_name style="padding: 8px;" />
                    <input type="text" placeholder="Display Name" on:input=move |ev| set_display_name.set(event_target_value(&ev)) prop:value=display_name style="padding: 8px;" />
                    <textarea placeholder="Description" on:input=move |ev| set_description.set(event_target_value(&ev)) prop:value=description style="padding: 8px;"></textarea>
                    <label style="display: flex; align-items: center; gap: 10px;">
                        <input type="checkbox" on:change=move |ev| set_enabled.set(event_target_checked(&ev)) prop:checked=enabled />
                        "Enabled"
                    </label>
                    <button on:click=move |_| create_realm_action.dispatch(()) style="padding: 10px; background: #28a745; color: white; border: none; cursor: pointer;">"Create"</button>
                </div>
            </Modal>

            <Modal is_open=show_edit_modal on_close=move |_| set_show_edit_modal.set(false) title="Edit Realm">
                <div style="display: flex; flex-direction: column; gap: 15px; max-height: 80vh; overflow-y: auto;">
                    <div>
                        <label style="display: block; margin-bottom: 5px;">"Display Name"</label>
                        <input type="text" on:input=move |ev| set_display_name.set(event_target_value(&ev)) prop:value=display_name style="width: 100%; padding: 8px;" />
                    </div>
                    <div>
                        <label style="display: block; margin-bottom: 5px;">"Description"</label>
                        <textarea on:input=move |ev| set_description.set(event_target_value(&ev)) prop:value=description style="width: 100%; padding: 8px;"></textarea>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                        <label style="display: flex; align-items: center; gap: 10px;">
                            <input type="checkbox" on:change=move |ev| set_enabled.set(event_target_checked(&ev)) prop:checked=enabled />
                            "Enabled"
                        </label>
                        <label style="display: flex; align-items: center; gap: 10px;">
                            <input type="checkbox" on:change=move |ev| set_registration_allowed.set(event_target_checked(&ev)) prop:checked=registration_allowed />
                            "Registration Allowed"
                        </label>
                        <label style="display: flex; align-items: center; gap: 10px;">
                            <input type="checkbox" on:change=move |ev| set_verify_email.set(event_target_checked(&ev)) prop:checked=verify_email />
                            "Verify Email"
                        </label>
                        <label style="display: flex; align-items: center; gap: 10px;">
                            <input type="checkbox" on:change=move |ev| set_reset_password_allowed.set(event_target_checked(&ev)) prop:checked=reset_password_allowed />
                            "Reset Password Allowed"
                        </label>
                    </div>
                    <button on:click=move |_| update_realm_action.dispatch(()) style="padding: 10px; background: #007bff; color: white; border: none; cursor: pointer;">"Save Changes"</button>
                </div>
            </Modal>
        </div>
    }
}
