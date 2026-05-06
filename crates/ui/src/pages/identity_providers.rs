use leptos::*;
use crate::api_client::authenticated_request;
use uuid::Uuid;
use crate::components::modal::Modal;
use std::collections::HashMap;
use crate::models::{IdentityProviderResponse, CreateIdentityProviderRequest};
use crate::utils::get_realm_id;

#[component]
pub fn IdentityProviders() -> impl IntoView {
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);
    let (show_modal, set_show_modal) = create_signal(false);
    let (selected_provider, set_selected_provider) = create_signal::<Option<IdentityProviderResponse>>(None);

    // Form signals
    let (new_name, set_new_name) = create_signal(String::new());
    let (new_display_name, set_new_display_name) = create_signal(String::new());
    let (new_type, set_new_type) = create_signal("LDAP".to_string());
    let (enabled, set_enabled) = create_signal(true);

    // LDAP Config signals
    let (ldap_url, set_ldap_url) = create_signal(String::new());
    let (ldap_base_dn, set_ldap_base_dn) = create_signal(String::new());
    let (ldap_bind_dn, set_ldap_bind_dn) = create_signal(String::new());
    let (ldap_bind_pw, set_ldap_bind_pw) = create_signal(String::new());
    let (ldap_username_attr, set_ldap_username_attr) = create_signal("uid".to_string());
    let (ldap_email_attr, set_ldap_email_attr) = create_signal("mail".to_string());
    let (ldap_role_mappings, set_ldap_role_mappings) = create_signal::<Vec<(String, String)>>(vec![]);

    // OIDC/SAML Config signals
    let (oidc_client_id, set_oidc_client_id) = create_signal(String::new());
    let (oidc_client_secret, set_oidc_client_secret) = create_signal(String::new());
    let (oidc_issuer, set_oidc_issuer) = create_signal(String::new());

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

    let save_provider_action = create_action(move |_: &()| async move {
        let realm_id = Uuid::parse_str(&get_realm_id()).unwrap();

        let mut config = HashMap::new();
        let provider_type = new_type.get();

        if provider_type == "LDAP" {
            config.insert("server_url".to_string(), ldap_url.get());
            config.insert("base_dn".to_string(), ldap_base_dn.get());
            config.insert("username_attribute".to_string(), ldap_username_attr.get());
            config.insert("email_attribute".to_string(), ldap_email_attr.get());
            if !ldap_bind_dn.get().is_empty() {
                config.insert("bind_dn".to_string(), ldap_bind_dn.get());
                config.insert("bind_password".to_string(), ldap_bind_pw.get());
            }

            let mut mappings = HashMap::new();
            for (group, role) in ldap_role_mappings.get() {
                if !group.is_empty() && !role.is_empty() {
                    mappings.insert(group, role);
                }
            }
            config.insert("role_mappings".to_string(), serde_json::to_string(&mappings).unwrap_or_default());
        } else if provider_type == "OIDC" {
            config.insert("client_id".to_string(), oidc_client_id.get());
            config.insert("client_secret".to_string(), oidc_client_secret.get());
            config.insert("issuer".to_string(), oidc_issuer.get());
        }

        let req = CreateIdentityProviderRequest {
            name: new_name.get(),
            display_name: new_display_name.get(),
            provider_type: provider_type.clone(),
            enabled: enabled.get(),
            config: serde_json::to_value(config).unwrap(),
            realm_id,
        };

        let method = if selected_provider.get().is_some() { "PUT" } else { "POST" };
        let url = if let Some(p) = selected_provider.get() {
            format!("/api/v1/admin/identity-providers/{}", p.id)
        } else {
            "/api/v1/admin/identity-providers".to_string()
        };

        match authenticated_request(method, &url, Some(&req)).await {
            Ok(res) if res.ok() => {
                set_show_modal.set(false);
                providers_resource.refetch();
            }
            _ => set_error_message.set(Some("Failed to save provider".to_string())),
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
                    on:click=move |_| {
                        set_selected_provider.set(None);
                        set_new_name.set(String::new());
                        set_new_display_name.set(String::new());
                        set_new_type.set("LDAP".to_string());
                        set_enabled.set(true);
                        set_show_modal.set(true);
                    }
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
                                                    let p1 = provider.clone();
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
                                                                <button
                                                                    on:click=move |_| {
                                                                        let p = p1.clone();
                                                                        set_selected_provider.set(Some(p.clone()));
                                                                        set_new_name.set(p.name);
                                                                        set_new_display_name.set(p.display_name);
                                                                        set_new_type.set(p.provider_type.clone());
                                                                        set_enabled.set(p.enabled);

                                                                        if p.provider_type == "LDAP" {
                                                                            set_ldap_url.set(p.config["server_url"].as_str().unwrap_or_default().to_string());
                                                                            set_ldap_base_dn.set(p.config["base_dn"].as_str().unwrap_or_default().to_string());
                                                                            set_ldap_username_attr.set(p.config["username_attribute"].as_str().unwrap_or("uid").to_string());
                                                                            set_ldap_email_attr.set(p.config["email_attribute"].as_str().unwrap_or("mail").to_string());

                                                                            let mappings_json = p.config["role_mappings"].as_str().unwrap_or("{}");
                                                                            let mappings: HashMap<String, String> = serde_json::from_str(mappings_json).unwrap_or_default();
                                                                            set_ldap_role_mappings.set(mappings.into_iter().collect());
                                                                        } else if p.provider_type == "OIDC" {
                                                                            set_oidc_issuer.set(p.config["issuer"].as_str().unwrap_or_default().to_string());
                                                                            set_oidc_client_id.set(p.config["client_id"].as_str().unwrap_or_default().to_string());
                                                                        }

                                                                        set_show_modal.set(true);
                                                                    }
                                                                    style="margin-right: 8px; padding: 6px 12px; border: 1px solid #dee2e6; background: white; border-radius: 4px; cursor: pointer; color: #495057;">
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
                is_open=show_modal
                on_close=move |_| set_show_modal.set(false)
                title=if selected_provider.get().is_some() { "Edit Identity Provider".to_string() } else { "Add Identity Provider".to_string() }
            >
                <div style="display: flex; flex-direction: column; gap: 15px; min-width: 450px; max-height: 80vh; overflow-y: auto;">
                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Type"</label>
                        <select
                            on:change=move |ev| set_new_type.set(event_target_value(&ev))
                            prop:value=new_type
                            style="width: 100%; padding: 8px; border-radius: 4px; border: 1px solid #ccc;"
                            disabled=move || selected_provider.get().is_some()
                        >
                            <option value="LDAP">"LDAP"</option>
                            <option value="OIDC">"OIDC"</option>
                        </select>
                    </div>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Alias / ID"</label>
                            <input type="text" on:input=move |ev| set_new_name.set(event_target_value(&ev)) prop:value=new_name placeholder="e.g. corp-ldap" style="width: 100%; padding: 8px;" />
                        </div>
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Display Name"</label>
                            <input type="text" on:input=move |ev| set_new_display_name.set(event_target_value(&ev)) prop:value=new_display_name placeholder="e.g. Corporate LDAP" style="width: 100%; padding: 8px;" />
                        </div>
                    </div>

                    {move || (new_type.get() == "LDAP").then(|| view! {
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 4px; border: 1px solid #e9ecef; display: flex; flex-direction: column; gap: 10px;">
                            <h4 style="margin: 0;">"LDAP Configuration Wizard"</h4>
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
                            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                                <div>
                                    <label style="display: block; font-size: 0.85em; margin-bottom: 3px;">"Username Attribute"</label>
                                    <input type="text" on:input=move |ev| set_ldap_username_attr.set(event_target_value(&ev)) prop:value=ldap_username_attr style="width: 100%; padding: 6px;" />
                                </div>
                                <div>
                                    <label style="display: block; font-size: 0.85em; margin-bottom: 3px;">"Email Attribute"</label>
                                    <input type="text" on:input=move |ev| set_ldap_email_attr.set(event_target_value(&ev)) prop:value=ldap_email_attr style="width: 100%; padding: 6px;" />
                                </div>
                            </div>

                            <div style="margin-top: 10px;">
                                <label style="display: block; font-size: 0.85em; font-weight: 600; margin-bottom: 5px;">"Role Mappings (LDAP Group → Role)"</label>
                                <div style="display: flex; flex-direction: column; gap: 5px;">
                                    {move || ldap_role_mappings.get().into_iter().enumerate().map(|(idx, (group, role))| {
                                        view! {
                                            <div style="display: flex; gap: 5px;">
                                                <input type="text" placeholder="LDAP Group"
                                                    on:input=move |ev| {
                                                        let mut m = ldap_role_mappings.get();
                                                        m[idx].0 = event_target_value(&ev);
                                                        set_ldap_role_mappings.set(m);
                                                    }
                                                    prop:value=group style="flex: 1; padding: 4px;" />
                                                <input type="text" placeholder="Role"
                                                    on:input=move |ev| {
                                                        let mut m = ldap_role_mappings.get();
                                                        m[idx].1 = event_target_value(&ev);
                                                        set_ldap_role_mappings.set(m);
                                                    }
                                                    prop:value=role style="flex: 1; padding: 4px;" />
                                                <button on:click=move |_| {
                                                    let mut m = ldap_role_mappings.get();
                                                    m.remove(idx);
                                                    set_ldap_role_mappings.set(m);
                                                } style="background: #dc3545; color: white; border: none; padding: 0 8px; cursor: pointer;">"×"</button>
                                            </div>
                                        }
                                    }).collect_view()}
                                    <button on:click=move |_| {
                                        let mut m = ldap_role_mappings.get();
                                        m.push(("".to_string(), "".to_string()));
                                        set_ldap_role_mappings.set(m);
                                    } style="padding: 4px; background: #28a745; color: white; border: none; font-size: 0.8em; cursor: pointer;">"+ Add Mapping"</button>
                                </div>
                            </div>
                        </div>
                    })}

                    {move || (new_type.get() == "OIDC").then(|| view! {
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 4px; border: 1px solid #e9ecef; display: flex; flex-direction: column; gap: 10px;">
                            <h4 style="margin: 0;">"OIDC Configuration"</h4>
                            <div>
                                <label style="display: block; font-size: 0.85em; margin-bottom: 3px;">"Issuer URL"</label>
                                <input type="text" on:input=move |ev| set_oidc_issuer.set(event_target_value(&ev)) prop:value=oidc_issuer placeholder="https://accounts.google.com" style="width: 100%; padding: 6px;" />
                            </div>
                            <div>
                                <label style="display: block; font-size: 0.85em; margin-bottom: 3px;">"Client ID"</label>
                                <input type="text" on:input=move |ev| set_oidc_client_id.set(event_target_value(&ev)) prop:value=oidc_client_id style="width: 100%; padding: 6px;" />
                            </div>
                            <div>
                                <label style="display: block; font-size: 0.85em; margin-bottom: 3px;">"Client Secret"</label>
                                <input type="password" on:input=move |ev| set_oidc_client_secret.set(event_target_value(&ev)) prop:value=oidc_client_secret style="width: 100%; padding: 6px;" />
                            </div>
                        </div>
                    })}

                    <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 10px; padding-top: 15px; border-top: 1px solid #eee;">
                        <button on:click=move |_| set_show_modal.set(false) style="padding: 10px 20px; border: 1px solid #ccc; background: white; border-radius: 4px; cursor: pointer;">"Cancel"</button>
                        <button on:click=move |_| save_provider_action.dispatch(()) style="padding: 10px 20px; border: none; background: #007bff; color: white; border-radius: 4px; cursor: pointer; font-weight: bold;">"Save Provider"</button>
                    </div>
                </div>
            </Modal>
        </div>
    }
}
