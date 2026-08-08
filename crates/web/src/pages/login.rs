//! Sign-in page.

use authenc_contract::{model::LoginRequest, validate};
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

/// The sign-in form.
#[component]
pub fn Login() -> impl IntoView {
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
            Ok(_) => {
                error.set(None);
                // A full navigation, so the server re-renders with the new
                // session cookie in place. `next` brings an interrupted OAuth
                // authorization request back to where it left off.
                use_navigate()(&next.get_untracked(), Default::default());
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
