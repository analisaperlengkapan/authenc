use leptos::*;
use leptos_router::*;
use crate::api_client::authenticated_request;
use serde::{Deserialize, Serialize};
use gloo_utils::window;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    CredentialRequestOptions,
    PublicKeyCredentialRequestOptions,
    AuthenticatorAssertionResponse,
};
use js_sys::Uint8Array;
use base64::Engine;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct LoginRequest {
    username: String,
    password: String,
    realm: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct LoginResponse {
    access_token: String,
}

#[component]
pub fn Login() -> impl IntoView {
    let (username, set_username) = create_signal("admin".to_string());
    let (password, set_password) = create_signal(String::new());
    let (realm, set_realm) = create_signal("master".to_string());
    let (error_msg, set_error_msg) = create_signal::<Option<String>>(None);
    let (is_loading, set_is_loading) = create_signal(false);

    let providers = create_resource(
        move || realm.get(),
        |realm_name| async move {
            let url = format!("/api/v1/admin/identity-providers?realm_name={}", realm_name);
            match authenticated_request("GET", &url, None::<&()>).await {
                Ok(res) if res.ok() => res.json::<Vec<crate::models::IdentityProviderResponse>>().await.ok(),
                _ => None,
            }
        }
    );

    let navigate = use_navigate();

    let initiate_social_login = move |provider_name: String| {
        let realm_val = realm.get();
        set_is_loading.set(true);
        spawn_local(async move {
            let req = serde_json::json!({
                "provider": provider_name,
                "redirect_uri": "/admin/console",
                "realm_id": realm_val
            });
            match authenticated_request("POST", "/api/v1/auth/social/initiate", Some(&req)).await {
                Ok(resp) if resp.ok() => {
                    if let Ok(data) = resp.json::<serde_json::Value>().await {
                        if let Some(url) = data["authorization_url"].as_str() {
                            let _ = window().location().set_href(url);
                        }
                    }
                }
                _ => {
                    set_is_loading.set(false);
                    set_error_msg.set(Some("Failed to initiate social login".to_string()));
                }
            }
        });
    };

    let start_webauthn_login = {
        let navigate = navigate.clone();
        move |_| {
            let username_val = username.get();
            let realm_val = realm.get();
            let navigate = navigate.clone();

            set_is_loading.set(true);
            spawn_local(async move {
                set_error_msg.set(None);

                // 1. Get challenge
                let challenge_req = serde_json::json!({
                    "realm_id": realm_val,
                    "username": username_val
                });

                let res = authenticated_request("POST", "/api/v1/auth/webauthn/login/challenge", Some(&challenge_req)).await;
                let challenge_json = match res {
                    Ok(resp) if resp.ok() => resp.json::<serde_json::Value>().await.ok(),
                    _ => None,
                };

                let Some(challenge) = challenge_json else {
                    set_is_loading.set(false);
                    set_error_msg.set(Some("Failed to get authentication challenge".to_string()));
                    return;
                };

                // 2. Invoke WebAuthn API
                let Some(window) = web_sys::window() else { return };
                let navigator = window.navigator();
                let credentials = navigator.credentials();

                let js_val = match serde_wasm_bindgen::to_value(&challenge) {
                    Ok(v) => v,
                    Err(e) => {
                        set_is_loading.set(false);
                        set_error_msg.set(Some(format!("Failed to convert challenge: {}", e)));
                        return;
                    }
                };

                let options = CredentialRequestOptions::new();
                options.set_public_key(&PublicKeyCredentialRequestOptions::from(js_val));

                let promise = credentials.get_with_options(&options).map_err(|e| {
                    set_is_loading.set(false);
                    set_error_msg.set(Some(format!("Failed to start WebAuthn: {:?}", e)));
                });

                let Ok(p) = promise else { return };
                let result = JsFuture::from(p).await;

                let credential = match result {
                    Ok(c) => web_sys::PublicKeyCredential::from(c),
                    Err(e) => {
                        set_is_loading.set(false);
                        set_error_msg.set(Some(format!("WebAuthn authentication failed: {:?}", e)));
                        return;
                    }
                };

                let response = AuthenticatorAssertionResponse::from(JsValue::from(credential.response()));

                // 3. Send response back to server
                let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
                let auth_resp = serde_json::json!({
                    "id": credential.id(),
                    "rawId": b64.encode(Uint8Array::new(&credential.raw_id()).to_vec()),
                    "type": credential.type_(),
                    "response": {
                        "authenticatorData": b64.encode(Uint8Array::new(&response.authenticator_data()).to_vec()),
                        "clientDataJSON": b64.encode(Uint8Array::new(&response.client_data_json()).to_vec()),
                        "signature": b64.encode(Uint8Array::new(&response.signature()).to_vec()),
                        "userHandle": response.user_handle().map(|h| b64.encode(Uint8Array::new(&h).to_vec())),
                    },
                });

                let url = format!("/api/v1/auth/webauthn/login/verify?realm_id={}&username={}", realm_val, username_val);
                match authenticated_request("POST", &url, Some(&auth_resp)).await {
                    Ok(r) if r.ok() => {
                         if let Ok(data) = r.json::<LoginResponse>().await {
                            if let Ok(Some(storage)) = window.local_storage() {
                                let _ = storage.set_item("authenc_token", &data.access_token);
                                let _ = storage.set_item("authenc_user", &username_val);
                                let _ = storage.set_item("authenc_realm", &realm_val);
                                navigate("/admin/console", Default::default());
                            }
                        }
                    }
                    _ => {
                        set_is_loading.set(false);
                        set_error_msg.set(Some("Failed to verify passkey authentication".to_string()));
                    }
                }
            });
        }
    };

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        set_error_msg.set(None);
        set_is_loading.set(true);

        let req = LoginRequest {
            username: username.get(),
            password: password.get(),
            realm: realm.get(),
        };

        let navigate = navigate.clone();
        spawn_local(async move {
            match authenticated_request("POST", "/api/v1/auth/login", Some(&req)).await {
                Ok(resp) => {
                    if resp.ok() {
                        if let Ok(data) = resp.json::<LoginResponse>().await {
                            if let Ok(Some(storage)) = window().local_storage() {
                                let _ = storage.set_item("authenc_token", &data.access_token);
                                let _ = storage.set_item("authenc_user", &req.username);
                                let _ = storage.set_item("authenc_realm", &req.realm);

                                // Fetch realm ID
                                let realm_resp = authenticated_request("GET", "/api/v1/auth/realms", None::<&()>).await;
                                if let Ok(r_resp) = realm_resp {
                                    if r_resp.ok() {
                                        if let Ok(realms) = r_resp.json::<Vec<crate::models::RealmResponse>>().await {
                                            if let Some(r) = realms.into_iter().find(|x| x.name == req.realm) {
                                                let _ = storage.set_item("authenc_realm_id", &r.id.to_string());
                                            }
                                        }
                                    }
                                }

                                navigate("/admin/console", Default::default());
                            }
                        }
                    } else {
                        set_is_loading.set(false);
                        set_error_msg.set(Some("Login failed. Please check your credentials.".to_string()));
                    }
                }
                Err(e) => {
                    set_is_loading.set(false);
                    set_error_msg.set(Some(format!("Error: {}", e)));
                }
            }
        });
    };

    view! {
        <div class="login-page" style="display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #f3f4f6;">
            <div class="card" style="background: white; padding: 2rem; border-radius: 0.5rem; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 400px;">
                <h1 style="text-align: center; margin-bottom: 0.5rem;">"Authenc Admin"</h1>
                <p style="text-align: center; color: #6b7280; margin-bottom: 2rem;">"Sign in to your account"</p>

                {move || error_msg.get().map(|msg| view! {
                    <div style="color: #ef4444; background: #fee2e2; padding: 0.75rem; border-radius: 0.25rem; margin-bottom: 1rem; text-align: center;">
                        {msg}
                    </div>
                })}

                <form on:submit=on_submit>
                    <div style="margin-bottom: 1rem;">
                        <label style="display: block; margin-bottom: 0.5rem; font-weight: 500;">"Username"</label>
                        <input
                            type="text"
                            required
                            style="width: 100%; padding: 0.5rem; border: 1px solid #d1d5db; border-radius: 0.25rem;"
                            on:input=move |ev| set_username.set(event_target_value(&ev))
                            prop:value=username
                        />
                    </div>
                    <div style="margin-bottom: 1rem;">
                        <label style="display: block; margin-bottom: 0.5rem; font-weight: 500;">"Password"</label>
                        <input
                            type="password"
                            required
                            style="width: 100%; padding: 0.5rem; border: 1px solid #d1d5db; border-radius: 0.25rem;"
                            on:input=move |ev| set_password.set(event_target_value(&ev))
                            prop:value=password
                        />
                    </div>
                    <div style="margin-bottom: 1.5rem;">
                        <label style="display: block; margin-bottom: 0.5rem; font-weight: 500;">"Realm"</label>
                        <input
                            type="text"
                            required
                            style="width: 100%; padding: 0.5rem; border: 1px solid #d1d5db; border-radius: 0.25rem;"
                            on:input=move |ev| set_realm.set(event_target_value(&ev))
                            prop:value=realm
                        />
                    </div>
                    <button
                        type="submit"
                        style="width: 100%; background: #2563eb; color: white; padding: 0.75rem; border: none; border-radius: 0.25rem; cursor: pointer; font-weight: 600;"
                        prop:disabled=is_loading
                    >
                        {move || if is_loading.get() { "Signing in..." } else { "Sign In" }}
                    </button>
                </form>

                <div style="margin-top: 1rem;">
                    <button
                        on:click=start_webauthn_login
                        style="width: 100%; background: #6b7280; color: white; padding: 0.75rem; border: none; border-radius: 0.25rem; cursor: pointer;"
                        prop:disabled=is_loading
                    >
                        {move || if is_loading.get() { "Processing..." } else { "Sign in with Passkey" }}
                    </button>
                </div>

                <Suspense fallback=|| view! { <div>"Loading providers..."</div> }>
                    {move || providers.get().map(|p_list| {
                        if let Some(list) = p_list {
                             let enabled_providers: Vec<_> = list.into_iter().filter(|p| p.enabled && p.provider_type != "LDAP").collect();
                             if !enabled_providers.is_empty() {
                                 view! {
                                     <div style="margin-top: 2rem;">
                                         <div style="display: flex; align-items: center; margin-bottom: 1rem;">
                                             <div style="flex: 1; height: 1px; background: #d1d5db;"></div>
                                             <span style="padding: 0 0.5rem; color: #6b7280; font-size: 0.875rem;">"Or continue with"</span>
                                             <div style="flex: 1; height: 1px; background: #d1d5db;"></div>
                                         </div>
                                         <div style="display: flex; flex-direction: column; gap: 0.5rem;">
                                             {enabled_providers.into_iter().map(|p| {
                                                 let name = p.name.clone();
                                                 let display_name = p.display_name.clone();
                                                 view! {
                                                     <button
                                                         on:click=move |_| initiate_social_login(name.clone())
                                                         style="width: 100%; background: white; border: 1px solid #d1d5db; padding: 0.5rem; border-radius: 0.25rem; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 0.5rem;"
                                                     >
                                                         <i class=format!("fab fa-{}", display_name.to_lowercase())></i>
                                                         {display_name}
                                                     </button>
                                                 }
                                             }).collect_view()}
                                         </div>
                                     </div>
                                 }.into_view()
                             } else {
                                 view! { <div></div> }.into_view()
                             }
                        } else {
                            view! { <div></div> }.into_view()
                        }
                    })}
                </Suspense>

                <div style="margin-top: 1.5rem; text-align: center;">
                    <A href="/forgot-password" class="text-blue-600 hover:text-blue-800">"Forgot Password?"</A>
                </div>
            </div>
        </div>
    }
}
