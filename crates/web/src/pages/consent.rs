//! The OAuth consent screen.
//!
//! Reached by a redirect from the authorization endpoint when a client wants
//! scopes the user has not already approved. It is a plain HTML form that
//! posts straight back to that endpoint — no JavaScript required, so a
//! hydration failure degrades to a working page rather than a dead button.
//!
//! Two things are deliberately *not* taken from the query string: the client's
//! name and the scope descriptions. Both are resolved server-side from the
//! client's registration, because a page that renders attacker-supplied text
//! under the operator's own domain is a phishing page with extra steps. The
//! query is used only to say *which* request is being approved.

use leptos::prelude::*;
use leptos_router::hooks::use_query_map;

use crate::{
    api,
    ui::{Button, Card, ErrorBanner, Variant},
};

/// Parameters carried through the approval unchanged.
///
/// They are re-posted as hidden fields so the authorization endpoint
/// re-validates the whole request rather than trusting anything this page
/// decided. `approve` and `csrf_token` are added by the form itself.
const FORWARDED: &[&str] = &[
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
];

/// Ask the user to approve an authorization request.
#[component]
pub fn Consent() -> impl IntoView {
    let query = use_query_map();

    let realm = Signal::derive(move || {
        query
            .get()
            .get("realm")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "master".to_owned())
    });

    let prompt = Resource::new(
        move || {
            let query = query.get();
            (
                realm.get(),
                query.get("client_id").unwrap_or_default(),
                query.get("scope").unwrap_or_default(),
            )
        },
        |(realm, client_id, scope)| async move { api::consent_prompt(realm, client_id, scope).await },
    );

    // The form posts back to the endpoint that redirected here, which
    // re-validates every parameter before issuing anything.
    let action =
        Signal::derive(move || format!("/realms/{}/protocol/openid-connect/auth", realm.get()));

    let hidden = Signal::derive(move || {
        let query = query.get();
        FORWARDED
            .iter()
            .filter_map(|name| {
                let value = query.get(name)?;
                Some(view! { <input type="hidden" name=*name value=value /> })
            })
            .collect_view()
    });

    view! {
        <main class="mx-auto flex min-h-full max-w-md flex-col justify-center gap-6 px-6 py-16">
            <h1 class="text-center text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                "Approve access"
            </h1>

            <Suspense fallback=move || {
                view! {
                    <p class="text-center text-sm text-ink-600 dark:text-ink-400">
                        "Checking the request…"
                    </p>
                }
            }>
                {move || {
                    prompt
                        .get()
                        .map(|result| match result {
                            Err(failure) => {
                                let message = RwSignal::new(Some(api::describe(&failure)));
                                view! { <ErrorBanner message /> }.into_any()
                            }
                            Ok(prompt) => {
                                let scopes = prompt.scopes.clone();
                                view! {
                                    <Card>
                                        <p class="text-sm text-ink-700 dark:text-ink-300">
                                            <span class="font-semibold text-ink-900 dark:text-ink-100">
                                                {prompt.client_name}
                                            </span>
                                            " wants access to your account "
                                            <span class="font-semibold text-ink-900 dark:text-ink-100">
                                                {prompt.username}
                                            </span>
                                            "."
                                        </p>

                                        <ul class="my-4 flex flex-col gap-2">
                                            {scopes
                                                .into_iter()
                                                .map(|scope| {
                                                    view! {
                                                        <li class="flex items-baseline gap-2 text-sm \
                                                                   text-ink-700 dark:text-ink-300">
                                                            <span aria-hidden="true" class="text-brand-600">
                                                                "\u{2022}"
                                                            </span>
                                                            <span>{scope.description}</span>
                                                        </li>
                                                    }
                                                })
                                                .collect_view()}
                                        </ul>

                                        <form
                                            method="post"
                                            action=move || action.get()
                                            class="flex flex-col gap-3"
                                        >
                                            {move || hidden.get()}
                                            <input
                                                type="hidden"
                                                name="csrf_token"
                                                value=prompt.csrf_token.clone()
                                            />

                                            // Two real submit buttons carrying the
                                            // answer. Only the one the user presses is
                                            // submitted, so the choice survives with
                                            // JavaScript switched off.
                                            <div class="flex gap-3">
                                                <Button kind="submit" name="approve" value="true">
                                                    "Allow"
                                                </Button>
                                                <Button
                                                    kind="submit"
                                                    name="approve"
                                                    value="false"
                                                    variant=Variant::Secondary
                                                >
                                                    "Deny"
                                                </Button>
                                            </div>
                                        </form>
                                    </Card>
                                }
                                    .into_any()
                            }
                        })
                }}
            </Suspense>
        </main>
    }
}
