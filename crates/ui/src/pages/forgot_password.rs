use leptos::*;
use serde::{Deserialize, Serialize};
use gloo_net::http::Request;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ForgotPasswordRequest {
    email: String,
}

#[component]
pub fn ForgotPassword() -> impl IntoView {
    let (email, set_email) = create_signal(String::new());
    let (status_msg, set_status_msg) = create_signal(String::new());

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let email_val = email.get();
        spawn_local(async move {
            let req_body = ForgotPasswordRequest { email: email_val };
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
        <div class="flex min-h-full flex-col justify-center px-6 py-12 lg:px-8">
            <div class="sm:mx-auto sm:w-full sm:max-w-sm">
                <h2 class="mt-10 text-center text-2xl font-bold leading-9 tracking-tight text-gray-900">
                    "Forgot password?"
                </h2>
            </div>

            <div class="mt-10 sm:mx-auto sm:w-full sm:max-w-sm">
                <form class="space-y-6" on:submit=on_submit>
                    <div>
                        <label for="email" class="block text-sm font-medium leading-6 text-gray-900">
                            "Email address"
                        </label>
                        <div class="mt-2">
                            <input
                                id="email"
                                name="email"
                                type="email"
                                autocomplete="email"
                                required
                                class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                on:input=move |ev| set_email.set(event_target_value(&ev))
                                prop:value=email
                            />
                        </div>
                    </div>

                    <div>
                        <button
                            type="submit"
                            class="flex w-full justify-center rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-semibold leading-6 text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
                        >
                            "Send Reset Link"
                        </button>
                    </div>
                </form>

                <p class="mt-10 text-center text-sm text-gray-500">
                    {move || status_msg.get()}
                </p>
            </div>
        </div>
    }
}
