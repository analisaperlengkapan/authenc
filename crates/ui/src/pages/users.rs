use leptos::*;
use crate::models::{UserResponse, UpdateUserRequest, WebauthnCredential};
use crate::api_client::authenticated_request;
use uuid::Uuid;
use crate::components::modal::Modal;
use crate::utils::get_realm_id;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SocialAccount {
    pub provider: String,
    pub provider_user_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkSocialRequest {
    pub provider: String,
    pub provider_user_id: String,
    pub email: Option<String>,
}

#[component]
pub fn Users() -> impl IntoView {
    let (error_message, set_error_message) = create_signal::<Option<String>>(None);
    let (selected_user, set_selected_user) = create_signal::<Option<UserResponse>>(None);
    let (show_edit_modal, set_show_edit_modal) = create_signal(false);
    let (show_link_social_modal, set_show_link_social_modal) = create_signal(false);

    // Form signals
    let (username, set_username) = create_signal(String::new());
    let (email, set_email) = create_signal(String::new());
    let (first_name, set_first_name) = create_signal(String::new());
    let (last_name, set_last_name) = create_signal(String::new());
    let (phone_number, set_phone_number) = create_signal(String::new());
    let (org_id, set_org_id) = create_signal(String::new());
    let (enabled, set_enabled) = create_signal(true);
    let (email_verified, set_email_verified) = create_signal(false);
    let (phone_verified, set_phone_verified) = create_signal(false);
    let (require_password_change, set_require_password_change) = create_signal(false);
    let (attributes, set_attributes) = create_signal(String::new());

    // Social signals
    let (social_provider, set_social_provider) = create_signal("google".to_string());
    let (social_user_id, set_social_user_id) = create_signal(String::new());

    let users_resource = create_resource(
        || (),
        move |_| async move {
            set_error_message.set(None);
            let realm_id = get_realm_id();
            let url = format!("/api/v1/auth/realms/{}/users", realm_id);

            match authenticated_request("GET", &url, None::<&()>).await {
                Ok(response) => {
                    if response.ok() {
                        response.json::<Vec<UserResponse>>().await.map_err(|e| e.to_string())
                    } else {
                        let msg = format!("Failed to fetch users: {}", response.status());
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

    let passkeys_resource = create_resource(
        move || selected_user.get(),
        move |user| async move {
            if let Some(u) = user {
                let realm_id = get_realm_id();
                let url = format!("/api/v1/auth/realms/{}/users/{}/passkeys", realm_id, u.id);
                match authenticated_request("GET", &url, None::<&()>).await {
                    Ok(res) if res.ok() => res.json::<Vec<WebauthnCredential>>().await.map_err(|e| e.to_string()),
                    _ => Ok(vec![]),
                }
            } else {
                Ok(vec![])
            }
        }
    );

    let social_accounts_resource = create_resource(
        move || selected_user.get(),
        move |user| async move {
            if let Some(u) = user {
                let realm_id = get_realm_id();
                let url = format!("/api/v1/auth/realms/{}/users/{}/social", realm_id, u.id);
                match authenticated_request("GET", &url, None::<&()>).await {
                    Ok(res) if res.ok() => res.json::<Vec<SocialAccount>>().await.map_err(|e| e.to_string()),
                    _ => Ok(vec![]),
                }
            } else {
                Ok(vec![])
            }
        }
    );

    let update_user_action = create_action(move |_: &()| async move {
        let Some(user) = selected_user.get() else { return };
        let realm_id = get_realm_id();
        let attr_val = attributes.get();
        let attr_json = if attr_val.is_empty() { None } else { serde_json::from_str(&attr_val).ok() };

        let req = UpdateUserRequest {
            username: Some(username.get()),
            email: Some(email.get()),
            first_name: Some(first_name.get()),
            last_name: Some(last_name.get()),
            phone_number: Some(phone_number.get()),
            enabled: Some(enabled.get()),
            email_verified: Some(email_verified.get()),
            phone_verified: Some(phone_verified.get()),
            require_password_change: Some(require_password_change.get()),
            organization_id: Some(Some(Uuid::parse_str(&org_id.get()).ok()).flatten()),
            attributes: attr_json,
        };

        let url = format!("/api/v1/auth/realms/{}/users/{}", realm_id, user.id);
        match authenticated_request("PUT", &url, Some(&req)).await {
            Ok(res) if res.ok() => {
                set_show_edit_modal.set(false);
                users_resource.refetch();
            }
            _ => set_error_message.set(Some("Failed to update user".to_string())),
        }
    });

    let link_social_action = create_action(move |_: &()| async move {
        let Some(user) = selected_user.get() else { return };
        let realm_id = get_realm_id();
        let req = LinkSocialRequest {
            provider: social_provider.get(),
            provider_user_id: social_user_id.get(),
            email: None,
        };

        let url = format!("/api/v1/auth/realms/{}/users/{}/social", realm_id, user.id);
        match authenticated_request("POST", &url, Some(&req)).await {
            Ok(res) if res.ok() => {
                set_show_link_social_modal.set(false);
                social_accounts_resource.refetch();
            }
            _ => set_error_message.set(Some("Failed to link account".to_string())),
        }
    });

    let delete_user_action = create_action(move |id: &Uuid| {
        let id = *id;
        async move {
            let realm_id = get_realm_id();
            let url = format!("/api/v1/auth/realms/{}/users/{}", realm_id, id);
            match authenticated_request("DELETE", &url, None::<&()>).await {
                Ok(res) if res.ok() => users_resource.refetch(),
                _ => set_error_message.set(Some("Failed to delete user".to_string())),
            }
        }
    });

    view! {
        <div class="users-page">
            <div class="header-actions" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <h2 style="margin: 0;">"Users"</h2>
                <button style="background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                    <i class="fas fa-plus" style="margin-right: 5px;"></i> "Create User"
                </button>
            </div>

            {move || error_message.get().map(|msg| view! {
                <div style="color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; padding: .75rem 1.25rem; margin-bottom: 1rem; border: 1px solid transparent; border-radius: .25rem;">
                    {msg}
                </div>
            })}

            <div class="table-container" style="background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;">
                <Suspense fallback=move || view! { <div style="padding: 20px; text-align: center;">"Loading users..."</div> }>
                {move || {
                    users_resource.get().map(|res| {
                        match res {
                            Ok(users) => {
                                if users.is_empty() {
                                    view! {
                                        <div style="padding: 20px; text-align: center; color: #6c757d;">
                                            "No users found in this realm."
                                        </div>
                                    }.into_view()
                                } else {
                                    view! {
                                        <table style="width: 100%; border-collapse: collapse;">
                                            <thead>
                                                <tr style="background: #f8f9fa; border-bottom: 1px solid #dee2e6;">
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Username"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Email"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Status"</th>
                                                    <th style="padding: 15px; text-align: left; font-weight: 600; color: #495057;">"Actions"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {users.into_iter().map(|user| {
                                                    let user_for_edit = user.clone();
                                                    let id = user.id.clone();
                                                    view! {
                                                        <tr style="border-bottom: 1px solid #dee2e6;">
                                                            <td style="padding: 15px;">{user.username}</td>
                                                            <td style="padding: 15px;">{user.email}</td>
                                                            <td style="padding: 15px;">
                                                                <span style={if user.enabled {
                                                                    "background: #d4edda; color: #155724; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;"
                                                                } else {
                                                                    "background: #f8d7da; color: #721c24; padding: 5px 10px; border-radius: 20px; font-size: 0.85em; font-weight: 500;"
                                                                }}>
                                                                    {if user.enabled { "Enabled" } else { "Disabled" }}
                                                                </span>
                                                            </td>
                                                            <td style="padding: 15px;">
                                                                <button
                                                                    on:click=move |_| {
                                                                        set_username.set(user_for_edit.username.clone());
                                                                        set_email.set(user_for_edit.email.clone());
                                                                        set_first_name.set(user_for_edit.first_name.clone().unwrap_or_default());
                                                                        set_last_name.set(user_for_edit.last_name.clone().unwrap_or_default());
                                                                        set_phone_number.set(user_for_edit.phone_number.clone().unwrap_or_default());
                                                                        set_org_id.set(user_for_edit.organization_id.map(|id| id.to_string()).unwrap_or_default());
                                                                        set_enabled.set(user_for_edit.enabled);
                                                                        set_email_verified.set(user_for_edit.email_verified);
                                                                        set_phone_verified.set(user_for_edit.phone_verified);
                                                                        set_require_password_change.set(user_for_edit.require_password_change);
                                                                        set_attributes.set(user_for_edit.attributes.as_ref().map(|a| serde_json::to_string_pretty(a).unwrap_or_default()).unwrap_or_default());
                                                                        set_selected_user.set(Some(user_for_edit.clone()));
                                                                        set_show_edit_modal.set(true);
                                                                    }
                                                                    style="margin-right: 8px; padding: 6px 12px; border: 1px solid #dee2e6; background: white; border-radius: 4px; cursor: pointer; color: #495057;">
                                                                    <i class="fas fa-edit"></i> " Edit"
                                                                </button>
                                                                <button
                                                                    on:click=move |_| {
                                                                        if gloo_utils::window().confirm_with_message("Delete user?").unwrap_or(false) {
                                                                            delete_user_action.dispatch(id);
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
                                    "Error loading users."
                                </div>
                            }.into_view()
                        }
                    })
                }}
                </Suspense>
            </div>

            <Modal
                is_open=show_edit_modal
                on_close=move |_| set_show_edit_modal.set(false)
                title="Edit User"
            >
                <div style="display: flex; flex-direction: column; gap: 15px; max-height: 80vh; overflow-y: auto; padding-right: 10px;">
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Username"</label>
                            <input type="text" on:input=move |ev| set_username.set(event_target_value(&ev)) prop:value=username style="width: 100%; padding: 8px;" />
                        </div>
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Email"</label>
                            <input type="email" on:input=move |ev| set_email.set(event_target_value(&ev)) prop:value=email style="width: 100%; padding: 8px;" />
                        </div>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-weight: 600;">"First Name"</label>
                            <input type="text" on:input=move |ev| set_first_name.set(event_target_value(&ev)) prop:value=first_name style="width: 100%; padding: 8px;" />
                        </div>
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Last Name"</label>
                            <input type="text" on:input=move |ev| set_last_name.set(event_target_value(&ev)) prop:value=last_name style="width: 100%; padding: 8px;" />
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Phone Number"</label>
                            <input type="text" on:input=move |ev| set_phone_number.set(event_target_value(&ev)) prop:value=phone_number style="width: 100%; padding: 8px;" />
                        </div>
                        <div>
                            <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Organization ID"</label>
                            <input type="text" on:input=move |ev| set_org_id.set(event_target_value(&ev)) prop:value=org_id style="width: 100%; padding: 8px;" />
                        </div>
                    </div>

                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; padding: 10px; background: #f8f9fa; border-radius: 4px;">
                        <label style="display: flex; align-items: center; gap: 10px; font-size: 0.9em;">
                            <input type="checkbox" on:change=move |ev| set_enabled.set(event_target_checked(&ev)) prop:checked=enabled />
                            "Enabled"
                        </label>
                        <label style="display: flex; align-items: center; gap: 10px; font-size: 0.9em;">
                            <input type="checkbox" on:change=move |ev| set_email_verified.set(event_target_checked(&ev)) prop:checked=email_verified />
                            "Email Verified"
                        </label>
                        <label style="display: flex; align-items: center; gap: 10px; font-size: 0.9em;">
                            <input type="checkbox" on:change=move |ev| set_phone_verified.set(event_target_checked(&ev)) prop:checked=phone_verified />
                            "Phone Verified"
                        </label>
                        <label style="display: flex; align-items: center; gap: 10px; font-size: 0.9em;">
                            <input type="checkbox" on:change=move |ev| set_require_password_change.set(event_target_checked(&ev)) prop:checked=require_password_change />
                            "Require Password Change"
                        </label>
                    </div>

                    <div>
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">"Attributes (JSON)"</label>
                        <textarea on:input=move |ev| set_attributes.set(event_target_value(&ev)) prop:value=attributes style="width: 100%; padding: 8px; min-height: 100px; font-family: monospace;"></textarea>
                    </div>

                    <div style="margin-top: 10px; padding-top: 15px; border-top: 1px solid #eee;">
                        <h4 style="margin: 0 0 10px 0;">"Security & Credentials"</h4>
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 4px;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <p style="margin: 0; font-weight: 600; font-size: 0.9em;">"MFA Status: "
                                    <span style={move || if selected_user.get().map(|u| u.totp_enabled).unwrap_or(false) { "color: green" } else { "color: gray" }}>
                                        {move || if selected_user.get().map(|u| u.totp_enabled).unwrap_or(false) { "Enabled" } else { "Not Configured" }}
                                    </span>
                                </p>
                                {move || selected_user.get().map(|u| u.totp_enabled).unwrap_or(false).then(|| {
                                    let uid = selected_user.get().map(|u| u.id).unwrap_or_default();
                                    view! {
                                        <button
                                            on:click=move |_| {
                                                if gloo_utils::window().confirm_with_message("Disable TOTP for this user?").unwrap_or(false) {
                                                    let realm_id = get_realm_id();
                                                    let url = format!("/api/v1/auth/realms/{}/users/{}/totp", realm_id, uid);
                                                    spawn_local(async move {
                                                        let _ = authenticated_request("DELETE", &url, None::<&()>).await;
                                                        users_resource.refetch();
                                                    });
                                                }
                                            }
                                            style="background: #dc3545; color: white; border: none; padding: 4px 8px; border-radius: 4px; font-size: 0.75em; cursor: pointer;">
                                            "Disable TOTP"
                                        </button>
                                    }
                                })}
                            </div>

                            <div style="margin-top: 15px;">
                                <label style="display: block; font-size: 0.85em; font-weight: 600; margin-bottom: 5px;">"Registered Passkeys"</label>
                                <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                                    {move || passkeys_resource.get().map(|res| match res {
                                        Ok(pks) if pks.is_empty() => view! { <p style="color: #6c757d; font-size: 0.85em; margin: 0;">"No passkeys registered."</p> }.into_view(),
                                        Ok(pks) => {
                                            let uid = selected_user.get().map(|u| u.id).unwrap_or_default();
                                            view! {
                                            <ul style="list-style: none; padding: 0; margin: 0; font-size: 0.85em;">
                                                {pks.into_iter().map(|pk| {
                                                    let kid = pk.id.clone();
                                                    let uid_clone = uid.clone();
                                                    view! {
                                                    <li style="display: flex; justify-content: space-between; align-items: center; padding: 5px 0; border-bottom: 1px solid #eee;">
                                                        <span>{pk.name.unwrap_or_else(|| "Unnamed Key".to_string())}</span>
                                                        <button
                                                            on:click=move |_| {
                                                                if gloo_utils::window().confirm_with_message("Delete this passkey?").unwrap_or(false) {
                                                                    let rid = get_realm_id();
                                                                    let url = format!("/api/v1/auth/realms/{}/users/{}/passkeys/{}", rid, uid_clone, kid);
                                                                    spawn_local(async move {
                                                                        let _ = authenticated_request("DELETE", &url, None::<&()>).await;
                                                                        passkeys_resource.refetch();
                                                                    });
                                                                }
                                                            }
                                                            style="color: red; background: none; border: none; cursor: pointer;"><i class="fas fa-trash"></i></button>
                                                    </li>
                                                }}).collect_view()}
                                            </ul>
                                        }.into_view()
                                        },
                                        _ => view! { <p>"Error loading passkeys"</p> }.into_view()
                                    })}
                                </Suspense>
                            </div>
                        </div>
                    </div>

                    <div style="margin-top: 10px; padding-top: 15px; border-top: 1px solid #eee;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                            <h4 style="margin: 0;">"Linked Social Accounts"</h4>
                            <button
                                on:click=move |_| set_show_link_social_modal.set(true)
                                style="background: #28a745; color: white; border: none; padding: 4px 8px; border-radius: 4px; font-size: 0.75em; cursor: pointer;">
                                "Link Account"
                            </button>
                        </div>
                        <Suspense fallback=move || view! { <p>"Loading..."</p> }>
                            {move || social_accounts_resource.get().map(|res| match res {
                                Ok(accs) if accs.is_empty() => view! { <p style="color: #6c757d; font-size: 0.85em; margin: 0;">"No linked accounts."</p> }.into_view(),
                                Ok(accs) => {
                                    let uid = selected_user.get().map(|u| u.id).unwrap_or_default();
                                    view! {
                                    <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                                        {accs.into_iter().map(|acc| {
                                            let prov = acc.provider.clone();
                                            let uid_clone = uid.clone();
                                            view! {
                                            <span style="background: #e9ecef; padding: 4px 10px; border-radius: 4px; font-size: 0.85em; display: flex; align-items: center; gap: 5px;">
                                                <i class={format!("fab fa-{}", prov)}></i>
                                                {prov.clone()}
                                                <button
                                                    on:click=move |_| {
                                                        if gloo_utils::window().confirm_with_message(&format!("Unlink {} account?", prov)).unwrap_or(false) {
                                                            let rid = get_realm_id();
                                                            let url = format!("/api/v1/auth/realms/{}/users/{}/social/{}", rid, uid_clone, prov);
                                                            spawn_local(async move {
                                                                let _ = authenticated_request("DELETE", &url, None::<&()>).await;
                                                                social_accounts_resource.refetch();
                                                            });
                                                        }
                                                    }
                                                    style="border: none; background: none; cursor: pointer; color: #6c757d;">"×"</button>
                                            </span>
                                        }}).collect_view()}
                                    </div>
                                }.into_view()
                                },
                                _ => view! { <p>"Error loading social accounts"</p> }.into_view()
                            })}
                        </Suspense>
                    </div>

                    <div style="display: flex; justify-content: flex-end; gap: 10px; margin-top: 15px; padding-top: 15px; border-top: 1px solid #eee;">
                        <button on:click=move |_| set_show_edit_modal.set(false) style="padding: 10px 20px; border: 1px solid #ccc; background: white; border-radius: 4px; cursor: pointer;">"Cancel"</button>
                        <button on:click=move |_| update_user_action.dispatch(()) style="padding: 10px 20px; border: none; background: #007bff; color: white; border-radius: 4px; cursor: pointer; font-weight: bold;">"Save Changes"</button>
                    </div>
                </div>
            </Modal>

            <Modal is_open=show_link_social_modal on_close=move |_| set_show_link_social_modal.set(false) title="Link Social Account">
                <div style="display: flex; flex-direction: column; gap: 15px;">
                    <select on:change=move |ev| set_social_provider.set(event_target_value(&ev)) style="padding: 8px;">
                        <option value="google">"Google"</option>
                        <option value="github">"GitHub"</option>
                        <option value="facebook">"Facebook"</option>
                    </select>
                    <input type="text" placeholder="Provider User ID" on:input=move |ev| set_social_user_id.set(event_target_value(&ev)) prop:value=social_user_id style="padding: 8px;" />
                    <button on:click=move |_| link_social_action.dispatch(()) style="padding: 10px; background: #28a745; color: white; border: none; cursor: pointer;">"Link Account"</button>
                </div>
            </Modal>
        </div>
    }
}
