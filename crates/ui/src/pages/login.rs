use leptos::prelude::*;
use leptos_router::*;
use crate::api_client::authenticated_request;
use serde::{Deserialize, Serialize};
use gloo_utils::window;

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
    let (username, set_username) = signal("admin".to_string());
    let (password, set_password) = signal(String::new());
    let (realm, set_realm) = signal("master".to_string());
    let (error_msg, set_error_msg) = create_signal::<Option<String>>(None);

    let navigate = use_navigate();

    let start_webauthn_login = {
        let _navigate = navigate.clone();
        move |_| {
        let username_val = username.get();
        let realm_val = realm.get();

        spawn_local(async move {
            set_error_msg.set(None);

            // 1. Get challenge
            let challenge_req = serde_json::json!({
                "realm_id": realm_val,
                "username": username_val
            });

            let res = authenticated_request("POST", "/api/v1/auth/webauthn/login/challenge", Some(&challenge_req)).await;
            match res {
                Ok(resp) if resp.ok() => {
                    // Logic to invoke navigator.credentials.get would go here.
                    // Since we are in a headless/WASM environment without direct JS bindings for WebAuthn in this snippet,
                    // we'll mention it's ready for integration with wasm-bindgen/web-sys.
                    set_error_msg.set(Some("WebAuthn browser interaction required".to_string()));
                }
                _ => set_error_msg.set(Some("Failed to get authentication challenge".to_string())),
            }
        });
    }
    };

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        set_error_msg.set(None);

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

                                (use_navigate())("/admin/console", Default::default());
                            }
                        }
                    } else {
                        set_error_msg.set(Some("Login failed. Please check your credentials.".to_string()));
                    }
                }
                Err(e) => set_error_msg.set(Some(format!("Error: {}", e))),
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
                    >
                        "Sign In"
                    </button>
                </form>

                <div style="margin-top: 1rem;">
                    <button
                        on:click=start_webauthn_login
                        style="width: 100%; background: #6b7280; color: white; padding: 0.75rem; border: none; border-radius: 0.25rem; cursor: pointer;"
                    >
                        "Sign in with Passkey"
                    </button>
                </div>

                <div style="margin-top: 1.5rem; text-align: center;">
                    <A href="/forgot-password" class="text-blue-600 hover:text-blue-800">"Forgot Password?"</A>
                </div>
            </div>
        </div>
    }
}
