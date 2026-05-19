use leptos::prelude::*;
use leptos_router::*;
use serde::{Deserialize, Serialize};
use gloo_net::http::Request;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ForgotPasswordRequest {
    email: String,
    realm_id: Option<String>,
}

#[component]
pub fn ForgotPassword() -> impl IntoView {
    let (email, set_email) = signal(String::new());
    let (status_msg, set_status_msg) = signal(String::new());

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let email_val = email.get();
        spawn_local(async move {
            let req_body = ForgotPasswordRequest {
                email: email_val,
                realm_id: None
            };
            let res = Request::post("/auth/forgot-password")
                .json(&req_body)
                .unwrap()
                .send()
                .await;

            match res {
                Ok(r) if r.ok() => set_status_msg.set("If the email exists, a reset link has been sent.".to_string()),
                _ => set_status_msg.set("Failed to request password reset.".to_string()),
            }
        });
    };

    view! {
        <div class="auth-page" style="display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #f3f4f6;">
            <div class="card" style="background: white; padding: 2rem; border-radius: 0.5rem; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 400px;">
                <h1 style="text-align: center; margin-bottom: 0.5rem;">"Recovery"</h1>
                <p style="text-align: center; color: #6b7280; margin-bottom: 2rem;">"Enter your email to reset password"</p>

                <form class="space-y-6" on:submit=on_submit>
                    <div style="margin-bottom: 1.5rem;">
                        <label for="email" style="display: block; margin-bottom: 0.5rem; font-weight: 500;">
                            "Email address"
                        </label>
                        <input
                            id="email"
                            name="email"
                            type="email"
                            autocomplete="email"
                            required
                            style="width: 100%; padding: 0.5rem; border: 1px solid #d1d5db; border-radius: 0.25rem;"
                            on:input=move |ev| set_email.set(event_target_value(&ev))
                            prop:value=email
                        />
                    </div>

                    <button
                        type="submit"
                        style="width: 100%; background: #2563eb; color: white; padding: 0.75rem; border: none; border-radius: 0.25rem; cursor: pointer; font-weight: 600; margin-bottom: 1rem;"
                    >
                        "Send Reset Link"
                    </button>

                    <A href="/login" class="bg-gray-500 text-white p-2 rounded block text-center">
                        "Back to Login"
                    </A>
                </form>

                <p style="margin-top: 1.5rem; text-align: center; color: #6b7280; font-size: 0.875rem;">
                    {move || status_msg.get()}
                </p>
            </div>
        </div>
    }
}
