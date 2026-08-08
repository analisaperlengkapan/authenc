//! The account's own security settings.
//!
//! Everything here acts on the signed-in user and nobody else. No component
//! takes a user id, and neither does any server function behind them — an
//! argument naming whose factors to change is an argument someone will
//! eventually change.
//!
//! Split into small components for the same reason [`crate::pages::consent`]
//! is: a page whose `view!` nests deeply enough overflows the trait solver in
//! the release wasm build while compiling fine in debug, so the failure lands
//! in CI rather than locally.

use authenc_contract::model::MfaStatus;
use leptos::prelude::*;

use crate::{
    api,
    ui::{Badge, Button, Card, ErrorBanner, Field},
};

/// The security settings page.
#[component]
pub fn Security() -> impl IntoView {
    // The guard is `current_user`, not the status call, and the difference is
    // not cosmetic. `mfa_status` refuses an anonymous caller with a 401, and by
    // the time that answer arrives the response status is already set — so
    // `leptos_axum::redirect` cannot override it and the visitor gets a bare
    // 401 with no page. `current_user` answers `Ok(None)` instead, which
    // leaves the redirect free to be the response. This is the same guard the
    // console shell uses, for the same reason.
    let session = Resource::new(|| (), |()| api::current_user());
    let status = Resource::new(|| (), |()| api::mfa_status());
    // Bumped whenever something changes, so the status refetches without the
    // page having to thread a setter through every child.
    let changed = RwSignal::new(0_u32);

    Effect::new(move |_| {
        changed.track();
        status.refetch();
    });

    view! {
        <main class="mx-auto flex max-w-3xl flex-col gap-6 px-6 py-10">
            <header>
                <h1 class="text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                    "Security"
                </h1>
                <p class="mt-1 text-sm text-ink-600 dark:text-ink-400">
                    "Second factors for this account."
                </p>
            </header>

            <Transition fallback=move || view! { <p class="text-sm">"Loading…"</p> }>
                {move || {
                    match session.get() {
                        // Signed in: render, once the status has arrived too.
                        Some(Ok(Some(_))) => {
                            status
                                .get()
                                .map(|result| match result {
                                    Ok(status) => view! { <Panels status changed /> }.into_any(),
                                    Err(error) => {
                                        view! {
                                            <p class="text-sm text-danger-600">
                                                {api::describe(&error)}
                                            </p>
                                        }
                                            .into_any()
                                    }
                                })
                                .into_any()
                        }
                        // Still loading.
                        None => ().into_any(),
                        // Nobody is signed in, or the check itself failed. The
                        // server issues the redirect before any of this page's
                        // markup is produced.
                        Some(_) => {
                            crate::pages::admin::redirect_to_login();
                            ().into_any()
                        }
                    }
                }}
            </Transition>
        </main>
    }
}

/// The three cards, once the status has loaded.
#[component]
fn Panels(status: MfaStatus, changed: RwSignal<u32>) -> impl IntoView {
    let enforced = status.enforced;
    let totp = status.totp;
    let remaining = status.recovery_codes_remaining;
    let passkeys = status.passkeys.clone();

    view! {
        <Card>
            <div class="flex items-center justify-between">
                <h2 class="text-base font-semibold">"Two-step verification"</h2>
                <Badge
                    ok=enforced
                    label=if enforced { "Required at sign-in" } else { "Not required" }
                />
            </div>
            <p class="mt-2 text-sm text-ink-600 dark:text-ink-400">
                // Said plainly, because it is the part people get wrong: codes
                // on their own are a way past a lost factor, not a factor.
                "Recovery codes alone do not turn this on. Enrol an authenticator \
                 or a passkey."
            </p>
        </Card>

        <TotpPanel enrolled=totp changed />
        <PasskeyPanel passkeys changed />
        <RecoveryPanel remaining changed />
    }
}

/// Authenticator app enrolment.
#[component]
fn TotpPanel(enrolled: bool, changed: RwSignal<u32>) -> impl IntoView {
    let begin = ServerAction::<api::BeginTotpEnrolment>::new();
    let confirm = ServerAction::<api::ConfirmTotpEnrolment>::new();
    let disable = ServerAction::<api::DisableTotp>::new();

    let code = RwSignal::new(String::new());
    let error = RwSignal::new(None::<String>);
    let codes = RwSignal::new(Vec::<String>::new());

    Effect::new(move |_| {
        if let Some(Err(failure)) = begin.value().get() {
            error.set(Some(api::describe(&failure)));
        }
    });

    Effect::new(move |_| match confirm.value().get() {
        Some(Ok(issued)) => {
            error.set(None);
            code.set(String::new());
            codes.set(issued);
            changed.update(|n| *n += 1);
        }
        Some(Err(failure)) => error.set(Some(api::describe(&failure))),
        None => {}
    });

    Effect::new(move |_| {
        if disable.value().get().is_some() {
            changed.update(|n| *n += 1);
        }
    });

    let enrolment = Signal::derive(move || begin.value().get().and_then(Result::ok));

    view! {
        <Card>
            <div class="flex items-center justify-between">
                <h2 class="text-base font-semibold">"Authenticator app"</h2>
                <Badge ok=enrolled label=if enrolled { "Enrolled" } else { "Not enrolled" } />
            </div>

            <ErrorBanner message=error />

            <Show when=move || !codes.get().is_empty()>
                <RecoveryCodeList codes />
            </Show>

            <Show
                when=move || enrolled
                fallback=move || {
                    view! {
                        <TotpEnrolmentFlow
                            enrolment
                            code
                            on_begin=move || {
                                begin
                                    .dispatch(api::BeginTotpEnrolment {
                                        label: "Authenticator".to_owned(),
                                    });
                            }
                            on_confirm=move || {
                                confirm
                                    .dispatch(api::ConfirmTotpEnrolment {
                                        code: code.get_untracked(),
                                    });
                            }
                        />
                    }
                }
            >
                <div class="mt-4">
                    <Button on_click=Callback::new(move |()| {
                        disable.dispatch(api::DisableTotp {});
                    })>"Remove authenticator"</Button>
                </div>
            </Show>
        </Card>
    }
}

/// The two steps of enrolling an authenticator.
#[component]
fn TotpEnrolmentFlow(
    enrolment: Signal<Option<authenc_contract::model::TotpEnrolment>>,
    code: RwSignal<String>,
    on_begin: impl Fn() + 'static + Copy + Send + Sync,
    on_confirm: impl Fn() + 'static + Copy + Send + Sync,
) -> impl IntoView {
    view! {
        <Show
            when=move || enrolment.get().is_some()
            fallback=move || {
                view! {
                    <div class="mt-4">
                        <Button on_click=Callback::new(move |()| on_begin())>
                            "Set up an authenticator"
                        </Button>
                    </div>
                }
            }
        >
            <div class="mt-4 flex flex-col gap-3">
                <p class="text-sm text-ink-600 dark:text-ink-400">
                    "Add this secret to your authenticator app, then enter the code it shows."
                </p>
                <code class="block break-all rounded bg-surface-200 p-3 font-mono text-sm dark:bg-surface-800">
                    {move || enrolment.get().map(|e| e.secret).unwrap_or_default()}
                </code>
                <Field label="Code from the app" name="totp_code" value=code />
                <div>
                    <Button on_click=Callback::new(move |()| on_confirm())>"Confirm"</Button>
                </div>
            </div>
        </Show>
    }
}

/// Registered passkeys.
#[component]
fn PasskeyPanel(
    passkeys: Vec<authenc_contract::model::PasskeySummary>,
    changed: RwSignal<u32>,
) -> impl IntoView {
    let remove = ServerAction::<api::RemovePasskey>::new();

    Effect::new(move |_| {
        if remove.value().get().is_some() {
            changed.update(|n| *n += 1);
        }
    });

    let empty = passkeys.is_empty();
    // `<For>` needs `Fn`, and a plain `Vec` moved into the closure gives
    // `FnOnce`. `StoredValue` is `Copy`, which is the recurring answer to this
    // in Leptos.
    let passkeys = StoredValue::new(passkeys);

    view! {
        <Card>
            <h2 class="text-base font-semibold">"Passkeys"</h2>
            <p class="mt-1 text-sm text-ink-600 dark:text-ink-400">
                "Registering one needs a browser; the button below runs the WebAuthn ceremony."
            </p>

            <Show
                when=move || !empty
                fallback=|| {
                    view! {
                        <p class="mt-4 text-sm text-ink-500">"No passkeys registered."</p>
                    }
                }
            >
                <ul class="mt-4 flex flex-col gap-2">
                    <For
                        each=move || passkeys.get_value()
                        key=|passkey| passkey.id
                        children=move |passkey| {
                            let id = passkey.id;
                            view! {
                                <li class="flex items-center justify-between rounded border border-surface-300 p-3 text-sm dark:border-surface-700">
                                    <span class="font-medium">{passkey.label.clone()}</span>
                                    <button
                                        type="button"
                                        class="text-danger-600 hover:underline"
                                        on:click=move |_| {
                                            remove.dispatch(api::RemovePasskey { id });
                                        }
                                    >
                                        "Remove"
                                    </button>
                                </li>
                            }
                        }
                    />
                </ul>
            </Show>

            <div class="mt-4">
                // Driven by `public/passkey.js`: `navigator.credentials` is a
                // browser API, and calling it through wasm bindings would add a
                // web-sys surface for no gain over forty lines of JavaScript
                // that this server hosts itself.
                <button
                    type="button"
                    id="register-passkey"
                    class="rounded bg-brand-600 px-3 py-2 text-sm font-medium text-white hover:bg-brand-700"
                >
                    "Register a passkey"
                </button>
                <p id="passkey-error" class="mt-2 text-sm text-danger-600"></p>
            </div>
        </Card>
    }
}

/// Recovery codes.
#[component]
fn RecoveryPanel(remaining: i64, changed: RwSignal<u32>) -> impl IntoView {
    let regenerate = ServerAction::<api::RegenerateRecoveryCodes>::new();
    let codes = RwSignal::new(Vec::<String>::new());

    Effect::new(move |_| {
        if let Some(Ok(issued)) = regenerate.value().get() {
            codes.set(issued);
            changed.update(|n| *n += 1);
        }
    });

    view! {
        <Card>
            <div class="flex items-center justify-between">
                <h2 class="text-base font-semibold">"Recovery codes"</h2>
                <Badge ok={remaining > 0} label=format!("{remaining} remaining") />
            </div>

            <Show when=move || !codes.get().is_empty()>
                <RecoveryCodeList codes />
            </Show>

            <div class="mt-4">
                <Button on_click=Callback::new(move |()| {
                    regenerate.dispatch(api::RegenerateRecoveryCodes {});
                })>"Generate new codes"</Button>
            </div>
            <p class="mt-2 text-sm text-ink-600 dark:text-ink-400">
                "Generating a new set invalidates the old one."
            </p>
        </Card>
    }
}

/// Freshly issued codes, shown once.
#[component]
fn RecoveryCodeList(codes: RwSignal<Vec<String>>) -> impl IntoView {
    view! {
        <div class="mt-4 rounded border border-brand-400 bg-brand-50 p-4 dark:border-brand-700 dark:bg-brand-950">
            <p class="text-sm font-medium">
                "Save these now. They are not shown again."
            </p>
            <ul class="mt-2 grid grid-cols-2 gap-1 font-mono text-sm">
                <For
                    each=move || codes.get()
                    key=|code| code.clone()
                    children=|code| view! { <li>{code}</li> }
                />
            </ul>
        </div>
    }
}
