use leptos::*;
use serde::{Deserialize, Serialize};
use crate::api_client::authenticated_request;
use uuid::Uuid;
use crate::components::modal::Modal;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdentityProviderResponse {
    pub id: Uuid,
    pub name: String,
    pub display_name: String,
    pub provider_type: String,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub realm_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIdentityProviderRequest {
    pub name: String,
    pub display_name: String,
    pub provider_type: String,
    pub enabled: bool,
    pub config: serde_json::Value,
    pub realm_id: Uuid,
}

fn get_realm_id() -> String {
    if let Ok(Some(storage)) = gloo_utils::window().local_storage() {
        if let Ok(Some(id)) = storage.get_item("authenc_selected_realm_id") {
            return id;
        }
    }
    "550e8400-e29b-41d4-a716-446655440000".to_string()
}

#[component]
pub fn IdentityProviders() -> impl IntoView {
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);
    let (show_add_modal, set_show_add_modal) = create_signal(false);

    // Form signals
    let (new_name, set_new_name) = create_signal(String::new());
    let (new_display_name, set_new_display_name) = create_signal(String::new());
    let (new_type, set_new_type) = create_signal("LDAP".to_string());

    // LDAP Config signals
    let (ldap_url, set_ldap_url) = create_signal(String::new());
    let (ldap_base_dn, set_ldap_base_dn) = create_signal(String::new());
    let (ldap_bind_dn, set_ldap_bind_dn) = create_signal(String::new());
    let (ldap_bind_pw, set_ldap_bind_pw) = create_signal(String::new());

    let providers_resource = create_resource(
        || (),
        move |_| async move {
            set_error_message.set(None);
            let realm_id = get_realm_id();
            let url = format!("/api/v1/admin/identity-providers?realm_id={}", realm_id);

            match authenticated_request("GET", &url, None::<&()>).await {
                Ok(response) => {
                    if response.ok() {
                        response.json::<Vec<IdentityProviderResponse>>().await.map_err(|e| e.to_string())
                    } else {
                        let msg = format!("Failed to fetch providers: {}", response.status());
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

    let add_provider_action = create_action(move |_: &()| async move {
        let realm_id = Uuid::parse_str(&get_realm_id()).unwrap();

        let mut config = HashMap::new();
        if new_type.get() == "LDAP" {
            config.insert("server_url".to_string(), ldap_url.get());
            config.insert("base_dn".to_string(), ldap_base_dn.get());
            if !ldap_bind_dn.get().is_empty() {
                config.insert("bind_dn".to_string(), ldap_bind_dn.get());
                config.insert("bind_password".to_string(), ldap_bind_pw.get());
            }
        }

        let req = CreateIdentityProviderRequest {
            name: new_name.get(),
            display_name: new_display_name.get(),
            provider_type: new_type.get(),
            enabled: true,
            config: serde_json::to_value(config).unwrap(),
            realm_id,
        };

        match authenticated_request("POST", "/api/v1/admin/identity-providers", Some(&req)).await {
            Ok(res) if res.ok() => {
                set_show_add_modal.set(false);
                providers_resource.refetch();
            }
            _ => set_error_message.set(Some("Failed to create provider".to_string())),
        }
    });

    let delete_provider_action = create_action(move |id: &Uuid| {
        let id = *id;
        async move {
            let url = format!("/api/v1/admin/identity-providers/{}", id);
            match authenticated_request("DELETE", &url, None::<&()>).await {
                Ok(res) if res.ok() => providers_resource.refetch(),
                _ => set_error_message.set(Some("Failed to delete provider".to_string())),
            }
        }
    });

    view! {
        <div class="providers-page">
            <div class="header-actions" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="margin: 0;">"Identity Providers"</h2>
                <button
                    on:click=move |_| set_show_add_modal.set(true)
                    style="background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                    <i class="fas fa-plus" style="margin-right: 5px;"></i> "Add Provider"
                </button>
            </div>

            {move || error_message.get().map(|msg| view! {
                <div style="color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; padding: .75rem 1.25rem; margin-bottom: 1rem; border: 1px solid transparent; border-radius: .25rem;">
                    {msg}
                </div>
            })}

            <div class="table-container" style="background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;">
                <Suspense fallback=move || view! { <div style="padding: 20px; text-align: center;">"Loading identity providers..."</div> }>
                {move || {
                    providers_resource.get().map(|res| {
                        match res {
                            Ok(providers) => {
                                if providers.is_empty() {
                                    view! {
                                        <div style="padding: 40px; text-align: center; color: #6c757d;">
                                            "No identity providers configured for this realm."
                                        </div>
                                    }.into_view()
                                } else {
                                    view! {
                                        <table style="width: 100%; border-collapse: collapse;">
                                            <thead>
                                                <tr style="background: #f8f9fa; border-bottom: 1px solid #dee2e6;">
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Name"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Type"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Status"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Actions"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {providers.into_iter().map(|provider| {
                                                    let id = provider.id;
                                                    view! {
                                                        <tr style="border-bottom: 1px solid #dee2e6;">
                                                            <td style="padding: 15px;">
                                                                <div style="font-weight: 600;">{provider.display_name}</div>
                                                                <div style="font-size: 0.8em; color: #6c757d;">{provider.name}</div>
                                                            </td>
                                                            <td style="padding: 15px;">{provider.provider_type}</td>
                                                            <td style="padding: 15px;">
                                                                <span style={if provider.enabled {
                                                                    "background: #d4edda; color: #155724; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;"
                                                                } else {
                                                                    "background: #f8d7da; color: #721c24; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;"
                                                                }}>
                                                                    {if provider.enabled { "Enabled" } else { "Disabled" }}
                                                                </span>
                                                            </td>
                                                            <td style="padding: 15px;">
                                                                <button style="margin-right: 8px; padding: 6px 12px; border: 1px solid #dee2e6; background: white; border-radius: 4px; cursor: pointer; color: #495057;">
                                                                    <i class="fas fa-edit"></i> " Edit"
                                                                </button>
                                                                <button
                                                                    on:click=move |_| {
                                                                        if gloo_utils::window().confirm_with_message("Delete this provider?").unwrap_or(false) {
                                                                            delete_provider_action.dispatch(id);
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
                                    "Error loading identity providers."
                                </div>
                            }.into_view()
                        }
                    })
                }}
                </Suspense>
            </div>

            <Modal
                is_open=show_add_modal
                on_close=move |_| set_show_add_modal.set(false)
                title="Add Identity Provider"
            >
                <div style="display: flex; flex-direction: column; gap: 15px; min-width: 400px;">
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Type"</label>
                        <select
                            on:change=move |ev| set_new_type.set(event_target_value(&ev))
                            style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc;"
                        >
                            <option value="LDAP">"LDAP"</option>
                            <option value="OIDC">"OIDC"</option>
                            <option value="SAML">"SAML"</option>
                        </select>
                    </div>

                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Alias / ID"</label>
                        <input
                            type="text"
                            on:input=move |ev| set_new_name.set(event_target_value(&ev))
                            prop:value=new_name
                            placeholder="e.g. corp-ldap"
                            style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc;"
                        />
                    </div>

                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Display Name"</label>
                        <input
                            type="text"
                            on:input=move |ev| set_new_display_name.set(event_target_value(&ev))
                            prop:value=new_display_name
                            placeholder="e.g. Corporate LDAP"
                            style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc;"
                        />
                    </div>

                    {move || (new_type.get() == "LDAP").then(|| view! {
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 4px; border: 1px solid #e9ecef;">
                            <h4 style="margin-top: 0; margin-bottom: 10px;">"LDAP Configuration"</h4>
                            <div style="display: flex; flex-direction: column; gap: 10px;">
                                <div>
                                    <label style="display: block; font-size: 0.85em; margin-bottom: 3px;">"Server URL"</label>
                                    <input type="text" on:input=move |ev| set_ldap_url.set(event_target_value(&ev)) prop:value=ldap_url placeholder="ldap://localhost:389" style="width: 100%; padding: 6px;" />
                                </div>
                                <div>
                                    <label style="display: block; font-size: 0.85em; margin-bottom: 3px;">"Base DN"</label>
                                    <input type="text" on:input=move |ev| set_ldap_base_dn.set(event_target_value(&ev)) prop:value=ldap_base_dn placeholder="dc=example,dc=org" style="width: 100%; padding: 6px;" />
                                </div>
                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                                    <div>
                                        <label style="display: block; font-size: 0.85em; margin-bottom: 3px;">"Bind DN"</label>
                                        <input type="text" on:input=move |ev| set_ldap_bind_dn.set(event_target_value(&ev)) prop:value=ldap_bind_dn placeholder="cn=admin,..." style="width: 100%; padding: 6px;" />
                                    </div>
                                    <div>
                                        <label style="display: block; font-size: 0.85em; margin-bottom: 3px;">"Bind Password"</label>
                                        <input type="password" on:input=move |ev| set_ldap_bind_pw.set(event_target_value(&ev)) prop:value=ldap_bind_pw style="width: 100%; padding: 6px;" />
                                    </div>
                                </div>
                            </div>
                        </div>
                    })}

                    <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 10px;">
                        <button
                            on:click=move |_| set_show_add_modal.set(false)
                            style="padding: 10px 20px; border: 1px solid #ccc; background: white; border-radius: 4px; cursor: pointer;">
                            "Cancel"
                        </button>
                        <button
                            on:click=move |_| add_provider_action.dispatch(())
                            style="padding: 10px 20px; border: none; background: #007bff; color: white; border-radius: 4px; cursor: pointer; font-weight: bold;">
                            "Save Provider"
                        </button>
                    </div>
                </div>
            </Modal>
        </div>
    }
}
