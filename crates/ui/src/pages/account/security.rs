use leptos::*;
use crate::api_client::authenticated_request;
use crate::models::{TotpStatusResponse, TotpSetupResponse, TotpSetupRequest, VerifyTotpSetupRequest};
use qrcodegen::{QrCode, QrCodeEcc};
use uuid::Uuid;
use crate::utils::{get_realm_id, get_username};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    CredentialCreationOptions,
    PublicKeyCredentialCreationOptions,
    AuthenticatorAttestationResponse,
};
use js_sys::Uint8Array;
use base64::Engine;

fn render_qr_svg(text: &str) -> String {
    let qr = QrCode::encode_text(text, QrCodeEcc::Medium).unwrap();
    let size = qr.size();
    let mut path = String::new();
    for y in 0..size {
        for x in 0..size {
            if qr.get_module(x, y) {
                path.push_str(&format!("M{},{}h1v1h-1z ", x, y));
            }
        }
    }
    format!(r#"<svg viewBox="0 0 {0} {0}" xmlns="http://www.w3.org/2000/svg" shape-rendering="crispEdges"><path d="{1}" /></svg>"#, size, path)
}

#[component]
pub fn Security() -> impl IntoView {
    let (setup_data, set_setup_data) = create_signal::<Option<TotpSetupResponse>>(None);
    let (error_msg, set_error_msg) = create_signal::<Option<String>>(None);
    let (verify_code, set_verify_code) = create_signal(String::new());
    let (success_msg, set_success_msg) = create_signal::<Option<String>>(None);
    let (passkey_name, set_passkey_name) = create_signal(String::new());
    let (editing_passkey, set_editing_passkey) = create_signal::<Option<(Uuid, String)>>(None);

    let totp_status = create_resource(
        || (),
        |_| async move {
            let resp = authenticated_request("GET", "/api/v1/auth/account/totp", None::<&()>).await;
             match resp {
                Ok(response) => {
                    if response.ok() {
                        response.json::<TotpStatusResponse>().await.ok()
                    } else {
                        None
                    }
                }
                Err(_) => None,
            }
        }
    );

    let passkeys = create_resource(
        || (),
        |_| async move {
            let resp = authenticated_request("GET", "/api/v1/auth/account/passkeys", None::<&()>).await;
            match resp {
                Ok(response) if response.ok() => {
                    response.json::<Vec<crate::models::WebauthnCredential>>().await.unwrap_or_default()
                }
                _ => vec![],
            }
        }
    );

    let setup_action = create_action(move |_: &()| async move {
        set_error_msg.set(None);
        set_success_msg.set(None);
        let req = TotpSetupRequest { user_label: Some("Browser".to_string()) };
        let resp = authenticated_request("POST", "/api/v1/auth/account/credentials/totp/setup", Some(&req)).await;
        match resp {
            Ok(response) => {
                if response.ok() {
                    let data = response.json::<TotpSetupResponse>().await.ok();
                    set_setup_data.set(data);
                    // Do NOT refetch status here, wait for verification
                } else {
                    set_error_msg.set(Some("Failed to setup TOTP".to_string()));
                }
            }
            Err(e) => set_error_msg.set(Some(e)),
        }
    });

    let verify_action = create_action(move |_: &()| async move {
        set_error_msg.set(None);
        let code = verify_code.get();
        if code.len() < 6 {
            set_error_msg.set(Some("Please enter a valid 6-digit code".to_string()));
            return;
        }

        let req = VerifyTotpSetupRequest { code };
        // Use the account_credentials endpoint for verification
        let resp = authenticated_request("POST", "/api/v1/auth/account/credentials/totp/verify", Some(&req)).await;
        match resp {
            Ok(response) => {
                if response.ok() {
                    set_success_msg.set(Some("TOTP verified and enabled successfully!".to_string()));
                    set_setup_data.set(None); // Clear secret from DOM
                    set_verify_code.set(String::new());
                    totp_status.refetch();
                } else {
                    set_error_msg.set(Some("Invalid code. Please try again.".to_string()));
                }
            }
            Err(e) => set_error_msg.set(Some(e)),
        }
    });

    let disable_action = create_action(move |_: &()| async move {
        let resp = authenticated_request("DELETE", "/api/v1/auth/account/totp", None::<&()>).await;
        if resp.is_ok() {
            totp_status.refetch();
            set_setup_data.set(None);
            set_error_msg.set(None);
            set_success_msg.set(Some("TOTP disabled successfully.".to_string()));
        } else {
            set_error_msg.set(Some("Failed to disable TOTP".to_string()));
        }
    });

    let cancel_setup = move |_| {
        set_setup_data.set(None);
        set_error_msg.set(None);
        set_verify_code.set(String::new());
    };

    let delete_passkey_action = create_action(move |id: &Uuid| {
        let id = *id;
        async move {
            let url = format!("/api/v1/auth/account/passkeys/{}", id);
            match authenticated_request("DELETE", &url, None::<&()>).await {
                Ok(res) if res.ok() => passkeys.refetch(),
                _ => set_error_msg.set(Some("Failed to delete passkey".to_string())),
            }
        }
    });

    let rename_passkey_action = create_action(move |(id, name): &(Uuid, String)| {
        let id = *id;
        let name = name.clone();
        async move {
            let url = format!("/api/v1/auth/account/passkeys/{}", id);
            let req = serde_json::json!({ "name": name });
            match authenticated_request("PATCH", &url, Some(&req)).await {
                Ok(res) if res.ok() => {
                    set_editing_passkey.set(None);
                    passkeys.refetch();
                }
                _ => set_error_msg.set(Some("Failed to rename passkey".to_string())),
            }
        }
    });

    let register_passkey_action = create_action(move |_: &()| async move {
        set_error_msg.set(None);
        set_success_msg.set(None);

        let username = get_username();
        let realm_id = get_realm_id();
        let name = passkey_name.get();

        if name.is_empty() {
            set_error_msg.set(Some("Please enter a name for this passkey".to_string()));
            return;
        }

        // 1. Get challenge
        let challenge_req = serde_json::json!({
            "username": username,
            "display_name": username,
            "realm_id": realm_id
        });

        let resp = authenticated_request("POST", "/api/v1/auth/webauthn/register/challenge", Some(&challenge_req)).await;
        let challenge_json = match resp {
            Ok(r) if r.ok() => r.json::<serde_json::Value>().await.ok(),
            _ => None,
        };

        let Some(challenge) = challenge_json else {
            set_error_msg.set(Some("Failed to get registration challenge".to_string()));
            return;
        };

        // 2. Invoke WebAuthn API
        let Some(window) = web_sys::window() else { return };
        let navigator = window.navigator();
        let credentials = navigator.credentials();

        // Convert challenge to CredentialCreationOptions
        let js_val = match serde_wasm_bindgen::to_value(&challenge) {
            Ok(v) => v,
            Err(e) => {
                set_error_msg.set(Some(format!("Failed to convert challenge: {}", e)));
                return;
            }
        };

        let options = CredentialCreationOptions::new();
        options.set_public_key(&PublicKeyCredentialCreationOptions::from(js_val));

        let promise = credentials.create_with_options(&options).map_err(|e| {
            set_error_msg.set(Some(format!("Failed to start WebAuthn creation: {:?}", e)));
        });

        let Ok(p) = promise else { return };
        let result = JsFuture::from(p).await;

        let credential = match result {
            Ok(c) => web_sys::PublicKeyCredential::from(c),
            Err(e) => {
                set_error_msg.set(Some(format!("WebAuthn registration failed: {:?}", e)));
                return;
            }
        };

        let response = AuthenticatorAttestationResponse::from(JsValue::from(credential.response()));

        // 3. Send response back to server
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let reg_resp = serde_json::json!({
            "id": credential.id(),
            "rawId": b64.encode(Uint8Array::new(&credential.raw_id()).to_vec()),
            "type": credential.type_(),
            "response": {
                "attestationObject": b64.encode(Uint8Array::new(&response.attestation_object()).to_vec()),
                "clientDataJSON": b64.encode(Uint8Array::new(&response.client_data_json()).to_vec()),
            },
            "name": name,
        });

        let url = format!("/api/v1/auth/webauthn/register/verify?realm_id={}&username={}", realm_id, username);
        match authenticated_request("POST", &url, Some(&reg_resp)).await {
            Ok(r) if r.ok() => {
                set_success_msg.set(Some("Passkey registered successfully!".to_string()));
                set_passkey_name.set(String::new());
                passkeys.refetch();
            }
            _ => set_error_msg.set(Some("Failed to verify passkey registration".to_string())),
        }
    });

    view! {
        <div class="security-page">
            <h2 style="margin-bottom: 20px;">"Security Settings"</h2>

            <div class="card" style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;">
                <h3 style="margin-top: 0;">"Two-Factor Authentication (TOTP)"</h3>

                {move || error_msg.get().map(|msg| view! {
                    <div class="alert" style="background: #f8d7da; color: #721c24; padding: 10px; border-radius: 4px; margin-bottom: 15px;">
                        {msg}
                    </div>
                })}

                {move || success_msg.get().map(|msg| view! {
                    <div class="alert" style="background: #d4edda; color: #155724; padding: 10px; border-radius: 4px; margin-bottom: 15px;">
                        {msg}
                    </div>
                })}

                <Suspense fallback=move || view! { <p>"Loading status..."</p> }>
                    {move || {
                        totp_status.get().map(|status_opt| {
                            match status_opt {
                                Some(status) => {
                                    if status.enabled {
                                        view! {
                                            <div>
                                                <div style="color: green; font-weight: bold; margin-bottom: 15px;">
                                                    <i class="fas fa-check-circle"></i> " Enabled"
                                                </div>
                                                <p>"TOTP is currently enabled for your account."</p>
                                                <button
                                                    on:click=move |_| disable_action.dispatch(())
                                                    style="background: #dc3545; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">
                                                    "Disable TOTP"
                                                </button>
                                            </div>
                                        }.into_view()
                                    } else {
                                        view! {
                                            <div>
                                                <div style="color: #6c757d; margin-bottom: 15px;">
                                                    <i class="fas fa-times-circle"></i> " Disabled"
                                                </div>
                                                <p>"Protect your account by enabling two-factor authentication."</p>
                                                <button
                                                    on:click=move |_| setup_action.dispatch(())
                                                    style="background: #007bff; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;"
                                                    prop:disabled=move || setup_data.get().is_some()>
                                                    "Setup TOTP"
                                                </button>
                                            </div>
                                        }.into_view()
                                    }
                                },
                                None => view! { <p>"Failed to load TOTP status."</p> }.into_view()
                            }
                        })
                    }}
                </Suspense>

                {move || setup_data.get().map(|data| {
                    let qr_svg = render_qr_svg(&data.qr_code_uri);
                    view! {
                        <div class="setup-area" style="margin-top: 20px; border-top: 1px solid #dee2e6; padding-top: 20px;">
                            <h4>"Step 1: Scan QR Code"</h4>
                            <div inner_html=qr_svg style="width: 200px; height: 200px; margin-bottom: 15px;"></div>
                            <p>"Secret: " <code>{data.secret}</code></p>

                            // Backup codes removed as they are not provided by this endpoint

                            <div class="verify-area" style="border-top: 1px solid #eee; padding-top: 15px;">
                                <h4>"Step 2: Verify Code"</h4>
                                <p>"Enter the 6-digit code from your authenticator app to confirm setup."</p>
                                <div style="display: flex; gap: 10px; align-items: center; margin-bottom: 10px;">
                                    <input
                                        type="text"
                                        placeholder="000000"
                                        maxlength="6"
                                        style="padding: 8px; border-radius: 4px; border: 1px solid #ccc; width: 120px; font-size: 1.2em; text-align: center;"
                                        on:input=move |ev| set_verify_code.set(event_target_value(&ev))
                                        prop:value=verify_code
                                    />
                                    <button
                                        on:click=move |_| verify_action.dispatch(())
                                        style="background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                                        "Verify & Enable"
                                    </button>
                                </div>
                                <button
                                    on:click=cancel_setup
                                    style="background: transparent; border: 1px solid #6c757d; color: #6c757d; padding: 6px 12px; border-radius: 4px; cursor: pointer; margin-top: 10px;">
                                    "Cancel"
                                </button>
                            </div>
                        </div>
                    }
                })}
            </div>

            <div class="card" style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;">
                <h3 style="margin-top: 0;">"Passkeys (WebAuthn)"</h3>
                <p>"Passkeys allow for a more secure and convenient way to sign in without passwords."</p>

                <div style="display: flex; gap: 10px; align-items: center; margin-bottom: 15px;">
                    <input
                        type="text"
                        placeholder="Device Name (e.g. My Phone)"
                        style="padding: 8px; border-radius: 4px; border: 1px solid #ccc; flex: 1;"
                        on:input=move |ev| set_passkey_name.set(event_target_value(&ev))
                        prop:value=passkey_name
                    />
                    <button
                        on:click=move |_| register_passkey_action.dispatch(())
                        style="background: #28a745; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold;">
                        "Add Passkey"
                    </button>
                </div>

                <Suspense fallback=move || view! { <p>"Loading passkeys..."</p> }>
                    <div class="passkey-list">
                        {move || {
                            passkeys.get().map(|list| {
                                if list.is_empty() {
                                    view! { <p style="color: #6c757d; font-style: italic;">"No passkeys registered yet."</p> }.into_view()
                                } else {
                                    view! {
                                        <ul style="list-style: none; padding: 0;">
                                            {list.into_iter().map(|c| {
                                                let id = Uuid::parse_str(&c.id).unwrap();
                                                let name = c.name.clone().unwrap_or_else(|| "Unnamed Passkey".to_string());
                                                let c_name = name.clone();
                                                view! {
                                                    <li style="display: flex; justify-content: space-between; align-items: center; padding: 10px; border-bottom: 1px solid #eee;">
                                                        <div>
                                                            {move || if let Some((edit_id, edit_name)) = editing_passkey.get() {
                                                                if edit_id == id {
                                                                    view! {
                                                                        <div style="display: flex; gap: 5px;">
                                                                            <input
                                                                                type="text"
                                                                                prop:value=edit_name
                                                                                on:input=move |ev| set_editing_passkey.set(Some((id, event_target_value(&ev))))
                                                                                style="padding: 4px;"
                                                                            />
                                                                            <button on:click=move |_| rename_passkey_action.dispatch((id, editing_passkey.get().unwrap().1)) class="btn-save">"Save"</button>
                                                                            <button on:click=move |_| set_editing_passkey.set(None) class="btn-cancel">"Cancel"</button>
                                                                        </div>
                                                                    }.into_view()
                                                                } else {
                                                                    view! { <div style="font-weight: 500;">{c_name.clone()}</div> }.into_view()
                                                                }
                                                            } else {
                                                                view! { <div style="font-weight: 500;">{c_name.clone()}</div> }.into_view()
                                                            }}
                                                            <div style="font-size: 0.8em; color: #6c757d;">"Created: " {c.created_at}</div>
                                                        </div>
                                                        <div style="display: flex; gap: 10px;">
                                                            <button
                                                                on:click=move |_| set_editing_passkey.set(Some((id, name.clone())))
                                                                style="background: none; border: 1px solid #ccc; padding: 4px 8px; border-radius: 4px; cursor: pointer;">
                                                                <i class="fas fa-edit"></i>
                                                            </button>
                                                            <button
                                                                on:click=move |_| {
                                                                    if gloo_utils::window().confirm_with_message("Remove this passkey?").unwrap_or(false) {
                                                                        delete_passkey_action.dispatch(id);
                                                                    }
                                                                }
                                                                style="background: none; border: 1px solid #dc3545; color: #dc3545; padding: 4px 8px; border-radius: 4px; cursor: pointer;">
                                                                <i class="fas fa-trash"></i>
                                                            </button>
                                                        </div>
                                                    </li>
                                                }
                                            }).collect_view()}
                                        </ul>
                                    }.into_view()
                                }
                            })
                        }}
                    </div>
                </Suspense>
            </div>

            <div class="card" style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px;">
                <h3 style="margin-top: 0;">"Linked Social Accounts"</h3>
                <p>"Link your account to social providers for easier sign-in."</p>

                // Note: Social account linking UI would go here.
                // For now we show the status based on UserResponse in Profile,
                // or we can fetch /api/v1/auth/account/social here.
                <p style="color: #6c757d; font-style: italic;">"Social account management is coming soon."</p>
            </div>
        </div>
    }
}
