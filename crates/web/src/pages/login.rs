//! Sign-in page.

use authenc_contract::{
    model::{LoginOutcome, LoginRequest, SecondFactor, SecondFactorPrompt},
    validate,
};
use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_query_map};

use crate::{
    api,
    ui::{Button, Card, ErrorBanner, Field},
};

/// Where to go after signing in.
///
/// Only a path on this origin is ever honoured. A `next` of
/// `https://evil.test/` — or the sneakier `//evil.test/`, which a browser
/// resolves as protocol-relative — would otherwise turn the login page into an
/// open redirect that arrives wearing this domain's name.
fn safe_next(raw: Option<String>) -> String {
    raw.filter(|value| value.starts_with('/') && !value.starts_with("//"))
        .unwrap_or_else(|| "/".to_owned())
}

/// The sign-in page: a password, and then a second factor if one is enrolled.
///
/// Split into two components because the two steps are two different things.
/// The alternative — one component with a `show_code` flag — is how a page ends
/// up rendering the code field and the password field at once, and how "did the
/// server actually ask for a second factor?" turns into a boolean the page can
/// set for itself.
#[component]
pub fn Login() -> impl IntoView {
    // `None` until the server says which step we are on. Nothing here decides
    // whether a second factor is required; the server does, and this only
    // renders the answer.
    let prompt = RwSignal::new(None::<SecondFactorPrompt>);

    view! {
        <main class="mx-auto flex min-h-full max-w-md flex-col justify-center gap-6 px-6 py-16">
            <Show
                when=move || prompt.get().is_some()
                fallback=move || view! { <PasswordStep prompt=prompt /> }
            >
                <SecondFactorStep prompt=prompt />
            </Show>
        </main>
    }
}

/// Step one: realm, identifier, password.
#[component]
fn PasswordStep(prompt: RwSignal<Option<SecondFactorPrompt>>) -> impl IntoView {
    let query = use_query_map();
    let next = Signal::derive(move || safe_next(query.get().get("next")));

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
            Ok(LoginOutcome::Complete(_)) => {
                error.set(None);
                // A full navigation, so the server re-renders with the new
                // session cookie in place. `next` brings an interrupted OAuth
                // authorization request back to where it left off.
                use_navigate()(&next.get_untracked(), Default::default());
            }
            // Not signed in. The session cookie was not set, and the only thing
            // this page received is what to ask for next.
            Ok(LoginOutcome::SecondFactorRequired(asked)) => {
                error.set(None);
                prompt.set(Some(asked));
            }
            Err(failure) => error.set(Some(api::describe(&failure))),
        }
    });

    let pending = submit.pending();

    view! {
        <>
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
        </>
    }
}

/// Step two: the second factor.
///
/// The pending login is identified by an `HttpOnly` cookie the server set, so
/// nothing on this page holds a credential and nothing it submits names whose
/// login to finish.
#[component]
fn SecondFactorStep(prompt: RwSignal<Option<SecondFactorPrompt>>) -> impl IntoView {
    let query = use_query_map();
    let next = Signal::derive(move || safe_next(query.get().get("next")));

    let code = RwSignal::new(String::new());
    let use_recovery = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);

    let submit = ServerAction::<api::SubmitSecondFactor>::new();
    let cancel = ServerAction::<api::CancelSecondFactor>::new();

    Effect::new(move |_| {
        let Some(result) = submit.value().get() else {
            return;
        };
        match result {
            Ok(_) => {
                error.set(None);
                use_navigate()(&next.get_untracked(), Default::default());
            }
            Err(failure) => {
                code.set(String::new());
                error.set(Some(api::describe(&failure)));
            }
        }
    });

    Effect::new(move |_| {
        if cancel.value().get().is_some() {
            prompt.set(None);
        }
    });

    let pending = submit.pending();
    let username = Signal::derive(move || prompt.get().map(|p| p.username).unwrap_or_default());
    let offers_recovery = Signal::derive(move || prompt.get().is_some_and(|p| p.recovery_code));
    let offers_totp = Signal::derive(move || prompt.get().is_some_and(|p| p.totp));

    view! {
        <>
            <header class="text-center">
                <h1 class="text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                    "Two-step verification"
                </h1>
                <p class="mt-1 text-sm text-ink-600 dark:text-ink-400">
                    "Signing in as " <span class="font-medium">{username}</span>
                </p>
            </header>

            <Card>
                <form
                    class="flex flex-col gap-4"
                    on:submit=move |ev| {
                        ev.prevent_default();
                        let entered = code.get_untracked();
                        let factor = if use_recovery.get_untracked() {
                            SecondFactor::RecoveryCode { code: entered }
                        } else {
                            SecondFactor::Totp { code: entered }
                        };
                        submit.dispatch(api::SubmitSecondFactor { factor });
                    }
                >
                    <ErrorBanner message=error />

                    <Show
                        when=move || use_recovery.get()
                        fallback=move || {
                            view! {
                                <Field
                                    label="Authenticator code"
                                    name="code"
                                    value=code
                                    autocomplete="one-time-code"
                                />
                            }
                        }
                    >
                        <Field
                            label="Recovery code"
                            name="recovery_code"
                            value=code
                            autocomplete="off"
                        />
                    </Show>

                    <Button kind="submit" disabled=Signal::derive(move || {
                        pending.get() || code.get().trim().is_empty()
                    })>
                        {move || if pending.get() { "Verifying…" } else { "Verify" }}
                    </Button>
                </form>

                <div class="mt-4 flex flex-col gap-2 text-sm">
                    <Show when=move || offers_recovery.get() && offers_totp.get()>
                        <button
                            type="button"
                            class="text-brand-600 hover:underline dark:text-brand-400"
                            on:click=move |_| {
                                code.set(String::new());
                                error.set(None);
                                use_recovery.update(|value| *value = !*value);
                            }
                        >
                            {move || {
                                if use_recovery.get() {
                                    "Use an authenticator code instead"
                                } else {
                                    "Use a recovery code instead"
                                }
                            }}
                        </button>
                    </Show>
                    <button
                        type="button"
                        class="text-ink-600 hover:underline dark:text-ink-400"
                        on:click=move |_| {
                            cancel.dispatch(api::CancelSecondFactor {});
                        }
                    >
                        "Start over"
                    </button>
                </div>
            </Card>
        </>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_path_on_this_origin_is_followed_after_signing_in() {
        assert_eq!(safe_next(Some("/admin/users".to_owned())), "/admin/users");
        assert_eq!(
            safe_next(Some(
                "/realms/master/protocol/openid-connect/auth?x=1".to_owned()
            )),
            "/realms/master/protocol/openid-connect/auth?x=1",
        );

        // Each of these would send the user somewhere else entirely, having
        // arrived at a link on this domain.
        for hostile in [
            "https://evil.test/",
            "//evil.test/",
            "http://evil.test",
            "javascript:alert(1)",
            "evil.test",
        ] {
            assert_eq!(
                safe_next(Some(hostile.to_owned())),
                "/",
                "followed: {hostile}",
            );
        }

        assert_eq!(safe_next(None), "/");
    }
}
