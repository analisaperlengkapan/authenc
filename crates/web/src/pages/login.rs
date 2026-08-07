//! Sign-in page.

use authenc_contract::{model::LoginRequest, validate};
use leptos::prelude::*;
use leptos_router::hooks::use_navigate;

use crate::{
    api,
    ui::{Button, Card, ErrorBanner, Field},
};

/// The sign-in form.
#[component]
pub fn Login() -> impl IntoView {
    let realm = RwSignal::new("master".to_owned());
    let identifier = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());

    let submit = ServerAction::<api::LogIn>::new();

    // `RwSignal` rather than a split `(read, write)` pair: the previous console
    // declared 121 separate `create_signal`s, fifteen of them in one form.
    let error = RwSignal::new(None::<String>);

    // The same validation the server runs, from `authenc-contract`. One
    // implementation, so the button and the database cannot disagree.
    let can_submit = Signal::derive(move || {
        !identifier.get().trim().is_empty()
            && !password.get().is_empty()
            && validate::realm_name(&realm.get()).is_ok()
    });

    Effect::new(move |_| {
        let Some(result) = submit.value().get() else {
            return;
        };
        match result {
            Ok(_) => {
                error.set(None);
                // A full navigation, so the server re-renders with the new
                // session cookie in place.
                use_navigate()("/", Default::default());
            }
            Err(failure) => error.set(Some(api::describe(&failure))),
        }
    });

    let pending = submit.pending();

    view! {
        <main class="mx-auto flex min-h-full max-w-md flex-col justify-center gap-6 px-6 py-16">
            <header class="text-center">
                <h1 class="text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                    "Sign in"
                </h1>
            </header>

            <Card>
                <form
                    class="flex flex-col gap-4"
                    on:submit=move |ev| {
                        ev.prevent_default();
                        submit
                            .dispatch(api::LogIn {
                                request: LoginRequest {
                                    realm: realm.get_untracked(),
                                    identifier: identifier.get_untracked(),
                                    password: password.get_untracked(),
                                },
                            });
                    }
                >
                    <ErrorBanner message=error />

                    <Field label="Realm" name="realm" value=realm autocomplete="organization" />
                    <Field
                        label="Username or email"
                        name="identifier"
                        value=identifier
                        autocomplete="username"
                    />
                    <Field
                        label="Password"
                        name="password"
                        value=password
                        kind="password"
                        autocomplete="current-password"
                    />

                    <Button kind="submit" disabled=Signal::derive(move || {
                        pending.get() || !can_submit.get()
                    })>
                        {move || if pending.get() { "Signing in…" } else { "Sign in" }}
                    </Button>
                </form>
            </Card>
        </main>
    }
}
