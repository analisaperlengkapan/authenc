use leptos::*;
use crate::api_client::authenticated_request;
use crate::models::{TotpStatusResponse, TotpSetupResponse, TotpSetupRequest, VerifyTotpSetupRequest};
use qrcodegen::{QrCode, QrCodeEcc};

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

    let setup_action = create_action(move |_: &()| async move {
        set_error_msg.set(None);
        set_success_msg.set(None);
        let req = TotpSetupRequest { device_name: Some("Browser".to_string()) };
        let resp = authenticated_request("POST", "/api/v1/auth/account/totp/setup", Some(&req)).await;
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
        // Use the account_credentials endpoint for verification as it supports checking secrets
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
                    let qr_svg = render_qr_svg(&data.qr_code_url);
                    view! {
                        <div class="setup-area" style="margin-top: 20px; border-top: 1px solid #dee2e6; padding-top: 20px;">
                            <h4>"Step 1: Scan QR Code"</h4>
                            <div inner_html=qr_svg style="width: 200px; height: 200px; margin-bottom: 15px;"></div>
                            <p>"Secret: " <code>{data.secret}</code></p>

                            <div class="backup-codes" style="margin-bottom: 20px;">
                                <h5>"Backup Codes"</h5>
                                <p>"Save these codes in a secure place. They can be used to recover access to your account."</p>
                                <ul style="column-count: 2; font-family: monospace;">
                                    {data.backup_codes.into_iter().map(|code| view! { <li>{code}</li> }).collect_view()}
                                </ul>
                            </div>

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
        </div>
    }
}
