use leptos::*;
use leptos_router::*;
use serde::{Deserialize, Serialize};
use gloo_net::http::Request;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ResetPasswordRequest {
    token: String,
    new_password: String,
}

// #[derive(Params, PartialEq, Clone)]
// struct ResetPasswordParams {
//     token: String,
// }

#[component]
pub fn ResetPassword() -> impl IntoView {
    // let params = use_params::<ResetPasswordParams>();
    let (password, set_password) = create_signal(String::new());
    let (status_msg, set_status_msg) = create_signal(String::new());

    // Extract token from URL query params or route params
    // Assuming route /auth/reset-password?token=... or /auth/reset-password/:token
    // Here using query param logic if possible, or simple input for now.
    // Ideally, the token comes from the URL. Let's assume the user has to paste it or it's in the URL.
    // For simplicity in this demo, we'll ask for token input if not present, or assume it's passed.

    // Simplified: Input for token and new password
    let (token_input, set_token_input) = create_signal(String::new());

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
        <div class="flex min-h-full flex-col justify-center px-6 py-12 lg:px-8">
            <div class="sm:mx-auto sm:w-full sm:max-w-sm">
                <h2 class="mt-10 text-center text-2xl font-bold leading-9 tracking-tight text-gray-900">
                    "Reset Password"
                </h2>
            </div>

            <div class="mt-10 sm:mx-auto sm:w-full sm:max-w-sm">
                <form class="space-y-6" on:submit=on_submit>
                    <div>
                        <label for="token" class="block text-sm font-medium leading-6 text-gray-900">
                            "Reset Token"
                        </label>
                        <div class="mt-2">
                            <input
                                id="token"
                                name="token"
                                type="text"
                                required
                                class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                on:input=move |ev| set_token_input.set(event_target_value(&ev))
                                prop:value=token_input
                            />
                        </div>
                    </div>

                    <div>
                        <label for="password" class="block text-sm font-medium leading-6 text-gray-900">
                            "New Password"
                        </label>
                        <div class="mt-2">
                            <input
                                id="password"
                                name="password"
                                type="password"
                                required
                                class="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"
                                on:input=move |ev| set_password.set(event_target_value(&ev))
                                prop:value=password
                            />
                        </div>
                    </div>

                    <div>
                        <button
                            type="submit"
                            class="flex w-full justify-center rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-semibold leading-6 text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
                        >
                            "Reset Password"
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
