//! The OAuth client console.
//!
//! Registering a client used to be a CLI command only, which meant the one
//! operation an incident actually needs — replacing a leaked secret — required
//! shell access to the server. It is here now, alongside the list.
//!
//! The secret is shown **once**, right after it is minted, because that is the
//! only moment it exists outside the caller: the database holds an Argon2 hash
//! and nothing else. A page that could show it again would be a page that could
//! leak it.

use authenc_contract::Permission;
use leptos::prelude::*;

use crate::{
    api,
    ui::{Badge, Button, Card, Cell, DataTable, ErrorBanner, Field, Variant},
};

use super::admin::Session;

/// Registered OAuth clients.
#[component]
pub fn Clients() -> impl IntoView {
    let session = expect_context::<Session>().0;
    let error = RwSignal::new(None::<String>);
    // Held only until the administrator navigates away. Never re-fetchable.
    let revealed = RwSignal::new(None::<Revealed>);

    let register = ServerAction::<api::RegisterClient>::new();
    let rotate = ServerAction::<api::RotateClientSecret>::new();
    let remove = ServerAction::<api::DeleteClient>::new();

    let clients = Resource::new(
        move || {
            (
                register.version().get(),
                rotate.version().get(),
                remove.version().get(),
            )
        },
        |_| api::list_clients(),
    );

    // Surface whichever action last failed, in one place.
    Effect::new(move |_| {
        let failures = [
            register.value().get().map(|r| r.map(|_| ())),
            rotate.value().get().map(|r| r.map(|_| ())),
            remove.value().get(),
        ];
        error.set(
            failures
                .into_iter()
                .flatten()
                .find_map(Result::err)
                .map(|e| api::describe(&e)),
        );
    });

    // A public client is issued no secret, so `Ok(None)` is a success with
    // nothing to show rather than a failure.
    Effect::new(move |_| {
        if let Some(Ok(Some(secret))) = register.value().get() {
            revealed.set(Some(Revealed {
                secret,
                rotated: false,
            }));
        }
    });
    Effect::new(move |_| {
        if let Some(Ok(secret)) = rotate.value().get() {
            revealed.set(Some(Revealed {
                secret,
                rotated: true,
            }));
        }
    });

    let can_write = Signal::derive(move || {
        session
            .get()
            .and_then(Result::ok)
            .flatten()
            .is_some_and(|me| me.can(Permission::ClientWrite))
    });

    view! {
        <div class="flex flex-col gap-6">
            <h1 class="text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                "OAuth clients"
            </h1>

            <ErrorBanner message=error />
            <SecretOnce revealed />

            <Show when=move || can_write.get()>
                <RegisterForm register />
            </Show>

            <Transition fallback=|| {
                view! { <p class="text-sm text-ink-500">"Loading clients…"</p> }
            }>
                {move || Suspend::new(async move {
                    match clients.await {
                        Err(failure) => {
                            let message = api::describe(&failure);
                            view! { <ErrorBanner message=Some(message) /> }.into_any()
                        }
                        Ok(list) => {
                            let rows = Signal::derive(move || list.clone());
                            view! { <ClientTable rows can_write rotate remove /> }.into_any()
                        }
                    }
                })}
            </Transition>
        </div>
    }
}

/// A secret the administrator has one chance to copy.
#[derive(Clone, PartialEq, Eq)]
struct Revealed {
    secret: String,
    rotated: bool,
}

/// Show a freshly minted secret, with the warning that it will not be shown
/// again.
#[component]
fn SecretOnce(
    /// The secret to reveal, if one was just minted.
    revealed: RwSignal<Option<Revealed>>,
) -> impl IntoView {
    view! {
        <Show when=move || revealed.get().is_some()>
            {move || {
                revealed
                    .get()
                    .map(|shown| {
                        let heading = if shown.rotated {
                            "New client secret — the previous one no longer works"
                        } else {
                            "Client secret"
                        };
                        view! {
                            <Card title=heading>
                                <p class="mb-3 text-sm text-ink-600 dark:text-ink-400">
                                    "Copy this now. Only its hash is stored, so it cannot be shown \
                                     again — if you lose it, rotate the secret."
                                </p>
                                <code class="block overflow-x-auto rounded bg-surface-100 p-3 \
                                             font-mono text-sm text-ink-900 \
                                             dark:bg-surface-800 dark:text-ink-100">
                                    {shown.secret}
                                </code>
                                <div class="mt-3">
                                    <Button
                                        variant=Variant::Secondary
                                        on_click=Callback::new(move |()| revealed.set(None))
                                    >
                                        "I have copied it"
                                    </Button>
                                </div>
                            </Card>
                        }
                    })
            }}
        </Show>
    }
}

/// The list of registered clients.
#[component]
fn ClientTable(
    /// The clients to show.
    rows: Signal<Vec<api::ClientSummary>>,
    /// Whether the viewer may change anything.
    can_write: Signal<bool>,
    /// Secret-rotation action.
    rotate: ServerAction<api::RotateClientSecret>,
    /// Deletion action.
    remove: ServerAction<api::DeleteClient>,
) -> impl IntoView {
    view! {
        <DataTable
            headers=vec!["Client", "Kind", "Redirect URIs", "Scopes", ""]
            rows=rows
            key=|client: &api::ClientSummary| client.client_id.clone()
            noun="clients"
            row=move |client: api::ClientSummary| {
                // `<Show>` needs `Fn`, not `FnOnce`, so the id cannot simply be
                // moved into the click handlers. `StoredValue` is `Copy`.
                let id = StoredValue::new(client.client_id.clone());
                let is_confidential = !client.is_public;
                view! {
                    <Cell>
                        <span class="font-medium text-ink-900 dark:text-ink-100">{client.name}</span>
                        <span class="block font-mono text-xs text-ink-500">{client.client_id}</span>
                    </Cell>
                    <Cell>
                        // "ok" is the confidential case: a client that can keep
                        // a secret is the stronger of the two.
                        <Badge
                            ok=!client.is_public
                            label=if client.is_public { "public" } else { "confidential" }
                        />
                    </Cell>
                    <Cell>
                        <span class="font-mono text-xs">{client.redirect_uris.join(", ")}</span>
                    </Cell>
                    <Cell>
                        <span class="text-xs">{client.scopes.join(" ")}</span>
                    </Cell>
                    <Cell>
                        <Show when=move || can_write.get()>
                            <div class="flex gap-2">
                                // A public client holds no secret, so the
                                // control is absent rather than offering an
                                // action the server would refuse.
                                <Show when=move || is_confidential>
                                    <Button
                                        variant=Variant::Secondary
                                        on_click=Callback::new(move |()| {
                                            rotate
                                                .dispatch(api::RotateClientSecret {
                                                    client_id: id.get_value(),
                                                });
                                        })
                                    >
                                        "Rotate secret"
                                    </Button>
                                </Show>
                                <Button
                                    variant=Variant::Danger
                                    on_click=Callback::new(move |()| {
                                        remove
                                            .dispatch(api::DeleteClient {
                                                client_id: id.get_value(),
                                            });
                                    })
                                >
                                    "Delete"
                                </Button>
                            </div>
                        </Show>
                    </Cell>
                }
            }
        />
    }
}

/// The registration form.
#[component]
fn RegisterForm(
    /// Registration action.
    register: ServerAction<api::RegisterClient>,
) -> impl IntoView {
    let client_id = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());
    let redirect_uri = RwSignal::new(String::new());
    let scopes = RwSignal::new("openid profile email".to_owned());
    let is_public = RwSignal::new(false);

    let can_submit = Signal::derive(move || {
        !client_id.get().trim().is_empty()
            && !name.get().trim().is_empty()
            && !redirect_uri.get().trim().is_empty()
    });

    let pending = register.pending();

    view! {
        <Card title="Register a client">
            <form
                class="flex flex-col gap-4"
                on:submit=move |ev| {
                    ev.prevent_default();
                    register
                        .dispatch(api::RegisterClient {
                            client_id: client_id.get_untracked().trim().to_owned(),
                            name: name.get_untracked().trim().to_owned(),
                            is_public: is_public.get_untracked(),
                            redirect_uris: redirect_uri
                                .get_untracked()
                                .split_whitespace()
                                .map(ToOwned::to_owned)
                                .collect(),
                            scopes: scopes
                                .get_untracked()
                                .split_whitespace()
                                .map(ToOwned::to_owned)
                                .collect(),
                        });
                    client_id.set(String::new());
                    name.set(String::new());
                    redirect_uri.set(String::new());
                }
            >
                <Field label="Client ID" name="client_id" value=client_id />
                <Field label="Display name" name="name" value=name />
                <Field
                    label="Redirect URIs (whitespace-separated, matched exactly)"
                    name="redirect_uris"
                    value=redirect_uri
                />
                <Field label="Scopes" name="scopes" value=scopes />

                <label class="flex items-center gap-2 text-sm text-ink-700 dark:text-ink-300">
                    <input
                        type="checkbox"
                        class="rounded border-ink-300"
                        prop:checked=move || is_public.get()
                        on:change=move |ev| is_public.set(event_target_checked(&ev))
                    />
                    "Public client (a SPA or native app: no secret, PKCE required)"
                </label>

                <Button
                    kind="submit"
                    disabled=Signal::derive(move || pending.get() || !can_submit.get())
                >
                    {move || if pending.get() { "Registering…" } else { "Register" }}
                </Button>
            </form>
        </Card>
    }
}
