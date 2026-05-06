use leptos::*;
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
    let (status_msg, set_status_msg) = create_signal(String::new());
    let (error_msg, set_error_msg) = create_signal(String::new());
    let (loading, set_loading) = create_signal(true);

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
        <div class="flex min-h-full flex-col justify-center px-6 py-12 lg:px-8">
            <div class="sm:mx-auto sm:w-full sm:max-w-sm">
                <h2 class="mt-10 text-center text-2xl font-bold leading-9 tracking-tight text-gray-900">
                    "Verify Email"
                </h2>
            </div>

            <div class="mt-10 sm:mx-auto sm:w-full sm:max-w-sm text-center">
                {move || loading.get().then(|| view! { <p>"Verifying your email..."</p> })}

                <p class="text-green-600 font-semibold">{move || status_msg.get()}</p>
                <p class="text-red-600 font-semibold">{move || error_msg.get()}</p>

                <div class="mt-6">
                    <A href="/login" class="text-indigo-600 hover:text-indigo-500 font-semibold">"Back to Login"</A>
                </div>
            </div>
        </div>
    }
}
