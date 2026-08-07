//! Password reset and email verification pages.

use authenc_contract::validate;
use leptos::prelude::*;
use leptos_router::hooks::use_query_map;

use crate::{
    api,
    ui::{Button, Card, ErrorBanner, Field},
};

/// Read the `token` **query** parameter.
///
/// `use_query_map`, not `use_params`. The previous console used `use_params`,
/// which reads *path* parameters, on a route with no path segment — so the
/// token was always `None` and email verification could never complete.
fn token_from_url() -> Option<String> {
    use_query_map()
        .get()
        .get("token")
        .filter(|value| !value.is_empty())
}

/// Ask for a password-reset link.
#[component]
pub fn ForgotPassword() -> impl IntoView {
    let realm = RwSignal::new("master".to_owned());
    let email = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let sent = RwSignal::new(false);

    let submit = ServerAction::<api::RequestPasswordReset>::new();

    Effect::new(move |_| {
        let Some(result) = submit.value().get() else {
            return;
        };
        match result {
            Ok(()) => {
                error.set(None);
                sent.set(true);
            }
            Err(failure) => error.set(Some(api::describe(&failure))),
        }
    });

    let pending = submit.pending();

    view! {
        <main class="mx-auto flex min-h-full max-w-md flex-col justify-center gap-6 px-6 py-16">
            <h1 class="text-center text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                "Reset your password"
            </h1>

            <Card>
                <Show
                    when=move || sent.get()
                    fallback=move || {
                        view! {
                            <form
                                class="flex flex-col gap-4"
                                on:submit=move |ev| {
                                    ev.prevent_default();
                                    submit
                                        .dispatch(api::RequestPasswordReset {
                                            realm: realm.get_untracked(),
                                            email: email.get_untracked(),
                                        });
                                }
                            >
                                <ErrorBanner message=error />
                                <Field label="Realm" name="realm" value=realm />
                                <Field
                                    label="Email"
                                    name="email"
                                    value=email
                                    kind="email"
                                    autocomplete="email"
                                />
                                <Button
                                    kind="submit"
                                    disabled=Signal::derive(move || {
                                        pending.get() || validate::email(&email.get()).is_err()
                                    })
                                >
                                    "Send reset link"
                                </Button>
                            </form>
                        }
                    }
                >
                    // Deliberately the same message whether or not the address
                    // is registered: saying "no such account" would let anyone
                    // enumerate users.
                    <p class="text-sm text-ink-700 dark:text-ink-300">
                        "If that address belongs to an account, a reset link is on its way.
                         The link is valid for one hour."
                    </p>
                </Show>
            </Card>
        </main>
    }
}

/// Choose a new password using an emailed link.
#[component]
pub fn ResetPassword() -> impl IntoView {
    let password = RwSignal::new(String::new());
    let confirm = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let done = RwSignal::new(false);

    let submit = ServerAction::<api::CompletePasswordReset>::new();

    Effect::new(move |_| {
        let Some(result) = submit.value().get() else {
            return;
        };
        match result {
            Ok(()) => {
                error.set(None);
                done.set(true);
            }
            Err(failure) => error.set(Some(api::describe(&failure))),
        }
    });

    let pending = submit.pending();
    let token = Signal::derive(token_from_url);

    // The same policy the server enforces, from `authenc-contract`.
    let ready = Signal::derive(move || {
        validate::password(&password.get()).is_ok() && password.get() == confirm.get()
    });

    view! {
        <main class="mx-auto flex min-h-full max-w-md flex-col justify-center gap-6 px-6 py-16">
            <h1 class="text-center text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                "Choose a new password"
            </h1>

            <Card>
                <Show
                    when=move || token.get().is_some()
                    fallback=|| {
                        view! {
                            <p class="text-sm text-ink-700 dark:text-ink-300">
                                "This link is missing its token. Request a new one from "
                                <a class="font-semibold text-brand-600" href="/forgot-password">
                                    "the reset page"
                                </a>
                                "."
                            </p>
                        }
                    }
                >
                    <Show
                        when=move || done.get()
                        fallback=move || {
                            view! {
                                <form
                                    class="flex flex-col gap-4"
                                    on:submit=move |ev| {
                                        ev.prevent_default();
                                        if let Some(token) = token.get_untracked() {
                                            submit
                                                .dispatch(api::CompletePasswordReset {
                                                    token,
                                                    new_password: password.get_untracked(),
                                                });
                                        }
                                    }
                                >
                                    <ErrorBanner message=error />
                                    <Field
                                        label="New password"
                                        name="password"
                                        value=password
                                        kind="password"
                                        autocomplete="new-password"
                                    />
                                    <Field
                                        label="Confirm password"
                                        name="confirm"
                                        value=confirm
                                        kind="password"
                                        autocomplete="new-password"
                                    />
                                    <Button
                                        kind="submit"
                                        disabled=Signal::derive(move || {
                                            pending.get() || !ready.get()
                                        })
                                    >
                                        "Set password"
                                    </Button>
                                </form>
                            }
                        }
                    >
                        <p class="text-sm text-ink-700 dark:text-ink-300">
                            "Your password has been changed, and every other session has been
                             signed out. "
                            <a class="font-semibold text-brand-600" href="/login">"Sign in"</a>
                            "."
                        </p>
                    </Show>
                </Show>
            </Card>
        </main>
    }
}

/// Confirm an email address from an emailed link.
#[component]
pub fn VerifyEmail() -> impl IntoView {
    let submit = ServerAction::<api::VerifyEmail>::new();
    let token = Signal::derive(token_from_url);

    // Fire as soon as the page loads: there is nothing for the reader to do.
    Effect::new(move |ran: Option<()>| {
        if ran.is_none()
            && let Some(token) = token.get_untracked()
        {
            submit.dispatch(api::VerifyEmail { token });
        }
    });

    view! {
        <main class="mx-auto flex min-h-full max-w-md flex-col justify-center gap-6 px-6 py-16">
            <h1 class="text-center text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                "Confirm your email"
            </h1>

            <Card>
                {move || match (token.get(), submit.value().get()) {
                    (None, _) => view! {
                        <p class="text-sm text-ink-700 dark:text-ink-300">
                            "This link is missing its token."
                        </p>
                    }
                        .into_any(),
                    (Some(_), None) => view! {
                        <p class="text-sm text-ink-500">"Confirming…"</p>
                    }
                        .into_any(),
                    (Some(_), Some(Ok(()))) => view! {
                        <p class="text-sm text-ink-700 dark:text-ink-300">
                            "Your email address is confirmed. "
                            <a class="font-semibold text-brand-600" href="/login">"Sign in"</a>
                            "."
                        </p>
                    }
                        .into_any(),
                    (Some(_), Some(Err(failure))) => {
                        let message = api::describe(&failure);
                        view! { <ErrorBanner message=Some(message) /> }.into_any()
                    }
                }}
            </Card>
        </main>
    }
}
