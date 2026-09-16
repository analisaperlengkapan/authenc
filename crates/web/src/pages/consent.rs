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
//!
//! The page is split into three small components rather than one nested
//! `view!`. That is not only style: a single tree this deep overflowed the
//! trait solver's depth limit in the release wasm build, while compiling fine
//! in debug.

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

    let forwarded = Signal::derive(move || {
        let query = query.get();
        FORWARDED
            .iter()
            .filter_map(|name| Some(((*name).to_owned(), query.get(name)?)))
            .collect::<Vec<_>>()
    });

    let body = move || {
        prompt.get().map(|result| match result {
            Err(failure) => {
                let message = RwSignal::new(Some(api::describe(&failure)));
                view! { <ErrorBanner message /> }.into_any()
            }
            Ok(prompt) => view! {
                <Approval prompt action=action.get() forwarded=forwarded.get() />
            }
            .into_any(),
        })
    };

    view! {
        <main class="mx-auto flex min-h-full max-w-md flex-col justify-center gap-6 px-6 py-16">
            <h1 class="text-center text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                "Approve access"
            </h1>
            <Suspense fallback=Checking>{body}</Suspense>
        </main>
    }
}

/// Shown while the server resolves what is being asked for.
#[component]
fn Checking() -> impl IntoView {
    view! {
        <p class="text-center text-sm text-ink-600 dark:text-ink-400">"Checking the request…"</p>
    }
}

/// The approval form.
#[component]
fn Approval(
    /// What the server resolved about this request.
    prompt: api::ConsentPrompt,
    /// Where the form posts.
    action: String,
    /// The original parameters, re-posted verbatim.
    forwarded: Vec<(String, String)>,
) -> impl IntoView {
    let hidden = forwarded
        .into_iter()
        .map(|(name, value)| view! { <input type="hidden" name=name value=value /> })
        .collect_view();

    view! {
        <Card>
            <p class="text-sm text-ink-700 dark:text-ink-300">
                <strong class="font-semibold text-ink-900 dark:text-ink-100">
                    {prompt.client_name}
                </strong>
                " wants access to your account "
                <strong class="font-semibold text-ink-900 dark:text-ink-100">
                    {prompt.username}
                </strong>
                "."
            </p>

            <ScopeList scopes=prompt.scopes />

            <form method="post" action=action class="flex gap-3">
                {hidden}
                <input type="hidden" name="csrf_token" value=prompt.csrf_token />
                // Two real submit buttons carrying the answer. Only the one the
                // user presses is submitted, so the choice survives with
                // JavaScript switched off.
                <Button kind="submit" name="approve" value="true">
                    "Allow"
                </Button>
                <Button kind="submit" name="approve" value="false" variant=Variant::Secondary>
                    "Deny"
                </Button>
            </form>
        </Card>
    }
}

/// What the client is asking for, one line each.
#[component]
fn ScopeList(
    /// The scopes that will actually be granted.
    scopes: Vec<api::ScopeInfo>,
) -> impl IntoView {
    let items = scopes
        .into_iter()
        .map(|scope| {
            view! {
                <li class="flex items-baseline gap-2 text-sm text-ink-700 dark:text-ink-300">
                    <span aria-hidden="true" class="text-brand-600">
                        "\u{2022}"
                    </span>
                    <span>{scope.description}</span>
                </li>
            }
        })
        .collect_view();

    view! { <ul class="my-4 flex flex-col gap-2">{items}</ul> }
}
