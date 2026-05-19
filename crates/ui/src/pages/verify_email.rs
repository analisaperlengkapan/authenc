use leptos::prelude::*;
use leptos_router::*;
use serde::{Deserialize, Serialize};
use gloo_net::http::Request;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct VerifyEmailRequest {
    token: String,
}

#[derive(Params, PartialEq, Clone)]
struct VerifyEmailParams {
    verification_token: Option<String>,
}

#[component]
pub fn VerifyEmail() -> impl IntoView {
    let params = use_params::<VerifyEmailParams>();
    let (status_msg, set_status_msg) = signal(String::new());
    let (error_msg, set_error_msg) = signal(String::new());
    let (loading, set_loading) = signal(true);

    create_effect(move |_| {
        if let Ok(p) = params.get() {
            if let Some(token) = p.verification_token {
                spawn_local(async move {
                    let req_body = VerifyEmailRequest { token };
                    let res = Request::post("/auth/verify-email")
                        .json(&req_body)
                        .unwrap()
                        .send()
                        .await;

                    set_loading.set(false);
                    match res {
                        Ok(r) if r.ok() => set_status_msg.set("Email verified successfully. You can now login.".to_string()),
                        _ => set_error_msg.set("Verification failed. Token might be invalid or expired.".to_string()),
                    }
                });
            } else {
                set_loading.set(false);
                set_error_msg.set("Missing verification token.".to_string());
            }
        }
    });

    view! {
        <div class="auth-page" style="display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #f3f4f6;">
            <div class="card" style="background: white; padding: 2rem; border-radius: 0.5rem; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 400px; text-align: center;">
                <h1 style="margin-bottom: 0.5rem;">"Verify Email"</h1>
                <p style="color: #6b7280; margin-bottom: 2rem;">"Verifying your email address..."</p>

                {move || loading.get().then(|| view! { <div class="spinner" style="margin: 1rem auto; border: 4px solid #f3f3f3; border-top: 4px solid #2563eb; border-radius: 50%; width: 30px; height: 30px; animation: spin 2s linear infinite;"></div> })}

                <p style="color: #10b981; font-weight: 600;">{move || status_msg.get()}</p>
                <p style="color: #ef4444; font-weight: 600;">{move || error_msg.get()}</p>

                <div style="margin-top: 2rem;">
                    <A href="/login" class="bg-blue-600 text-white p-2 rounded block text-center">
                        "Back to Login"
                    </A>
                </div>
            </div>
            <style>
                "@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }"
            </style>
        </div>
    }
}
