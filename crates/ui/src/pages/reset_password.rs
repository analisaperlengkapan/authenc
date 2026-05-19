use leptos::*;
use leptos_router::*;
use serde::{Deserialize, Serialize};
use gloo_net::http::Request;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ResetPasswordRequest {
    token: String,
    new_password: String,
}

#[derive(Params, PartialEq, Clone)]
struct ResetPasswordParams {
    token: Option<String>,
}

#[component]
pub fn ResetPassword() -> impl IntoView {
    let params = use_params::<ResetPasswordParams>();
    let (password, set_password) = create_signal(String::new());
    let (status_msg, set_status_msg) = create_signal(String::new());
    let (token_input, set_token_input) = create_signal(String::new());

    create_effect(move |_| {
        if let Ok(p) = params.get() {
            if let Some(t) = p.token {
                set_token_input.set(t);
            }
        }
    });

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let t = token_input.get();
        let p = password.get();

        spawn_local(async move {
            let req_body = ResetPasswordRequest { token: t, new_password: p };
            let res = Request::post("/auth/reset-password")
                .json(&req_body)
                .unwrap()
                .send()
                .await;

            match res {
                Ok(r) if r.ok() => set_status_msg.set("Password reset successful. You can now login.".to_string()),
                _ => set_status_msg.set("Failed to reset password. Token might be invalid or expired.".to_string()),
            }
        });
    };

    view! {
        <div class="auth-page" style="display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #f3f4f6;">
            <div class="card" style="background: white; padding: 2rem; border-radius: 0.5rem; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 400px;">
                <h1 style="text-align: center; margin-bottom: 0.5rem;">"Reset Password"</h1>
                <p style="text-align: center; color: #6b7280; margin-bottom: 2rem;">"Enter your new password"</p>

                <form class="space-y-6" on:submit=on_submit>
                    <div style="margin-bottom: 1rem;">
                        <label for="token" style="display: block; margin-bottom: 0.5rem; font-weight: 500;">
                            "Reset Token"
                        </label>
                        <input
                            id="token"
                            name="token"
                            type="text"
                            required
                            style="width: 100%; padding: 0.5rem; border: 1px solid #d1d5db; border-radius: 0.25rem;"
                            on:input=move |ev| set_token_input.set(event_target_value(&ev))
                            prop:value=token_input
                        />
                    </div>

                    <div style="margin-bottom: 1.5rem;">
                        <label for="password" style="display: block; margin-bottom: 0.5rem; font-weight: 500;">
                            "New Password"
                        </label>
                        <input
                            id="password"
                            name="password"
                            type="password"
                            required
                            style="width: 100%; padding: 0.5rem; border: 1px solid #d1d5db; border-radius: 0.25rem;"
                            on:input=move |ev| set_password.set(event_target_value(&ev))
                            prop:value=password
                        />
                    </div>

                    <button
                        type="submit"
                        style="width: 100%; background: #2563eb; color: white; padding: 0.75rem; border: none; border-radius: 0.25rem; cursor: pointer; font-weight: 600; margin-bottom: 1rem;"
                    >
                        "Reset Password"
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
