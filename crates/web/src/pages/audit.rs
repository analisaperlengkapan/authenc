//! The audit trail, in the console.
//!
//! Deliberately plain: a filtered, paged table. An audit page's job is to
//! answer "what happened to this account?" quickly, and every chart or summary
//! added in front of that is something between the operator and the answer.
//!
//! Split into small components for the reason the rest of `pages` is — a
//! deeply nested `view!` overflows the trait solver in the release wasm build
//! while compiling cleanly in debug.

use authenc_contract::{AuditEvent, event::Outcome};
use leptos::prelude::*;

use crate::{
    api,
    ui::{Badge, Card, Cell, DataTable},
};

/// The namespaces offered as filters.
///
/// Taken from the stored action names rather than from [`Category`], because
/// what the filter does is a `LIKE 'prefix%'` and these are the prefixes that
/// exist. A list derived from the enum would drift from the query the moment
/// a name changed.
///
/// [`Category`]: authenc_contract::Category
const NAMESPACES: &[(&str, &str)] = &[
    ("", "Everything"),
    ("login.", "Sign-in"),
    ("mfa.", "Second factors"),
    ("session.", "Sessions"),
    ("recovery.", "Recovery"),
    ("user.", "Users"),
    ("role.", "Roles"),
    ("client.", "OAuth clients"),
    ("token.", "Tokens"),
    ("consent.", "Consent"),
];

/// How many rows a page shows.
const PAGE: i64 = 50;

/// The audit page.
#[component]
pub fn Audit() -> impl IntoView {
    let namespace = RwSignal::new(String::new());
    let failures_only = RwSignal::new(false);
    let offset = RwSignal::new(0_i64);

    let page = Resource::new(
        move || (namespace.get(), failures_only.get(), offset.get()),
        |(namespace, failures_only, offset)| async move {
            api::list_audit_events(
                (!namespace.is_empty()).then_some(namespace),
                failures_only.then_some(Outcome::Failure),
                PAGE,
                offset,
            )
            .await
        },
    );

    view! {
        <section class="flex flex-col gap-4">
            <header>
                <h1 class="text-xl font-semibold text-ink-900 dark:text-ink-50">"Audit"</h1>
                <p class="mt-1 text-sm text-ink-600 dark:text-ink-400">
                    "Who did what, from where, and whether it worked."
                </p>
            </header>

            <Filters namespace failures_only offset />

            <Transition fallback=move || view! { <p class="text-sm">"Loading…"</p> }>
                {move || {
                    page.get()
                        .map(|result| match result {
                            Ok(page) => {
                                view! { <Trail page offset /> }
                                    .into_any()
                            }
                            Err(error) => {
                                view! {
                                    <p class="text-sm text-danger-600">{api::describe(&error)}</p>
                                }
                                    .into_any()
                            }
                        })
                }}
            </Transition>
        </section>
    }
}

/// The namespace and outcome filters.
#[component]
fn Filters(
    namespace: RwSignal<String>,
    failures_only: RwSignal<bool>,
    offset: RwSignal<i64>,
) -> impl IntoView {
    view! {
        <Card>
            <div class="flex flex-wrap items-center gap-3">
                <label class="text-sm font-medium" for="namespace">"Show"</label>
                <select
                    id="namespace"
                    class="rounded border border-surface-300 bg-surface-50 px-2 py-1 text-sm dark:border-surface-700 dark:bg-surface-900"
                    on:change=move |ev| {
                        // Any change resets to the first page: keeping the
                        // offset across a filter change lands the reader in the
                        // middle of a different result set with no way to tell.
                        offset.set(0);
                        namespace.set(event_target_value(&ev));
                    }
                >
                    <For
                        each=move || NAMESPACES.iter().copied()
                        key=|(prefix, _)| *prefix
                        children=move |(prefix, label)| {
                            view! { <option value=prefix>{label}</option> }
                        }
                    />
                </select>

                <label class="flex items-center gap-2 text-sm">
                    <input
                        type="checkbox"
                        class="rounded border-surface-400"
                        on:change=move |ev| {
                            offset.set(0);
                            failures_only.set(event_target_checked(&ev));
                        }
                    />
                    "Refusals only"
                </label>
            </div>
        </Card>
    }
}

/// The table and its pager.
#[component]
fn Trail(page: api::AuditPage, offset: RwSignal<i64>) -> impl IntoView {
    let total = page.total;
    let shown = i64::try_from(page.events.len()).unwrap_or(i64::MAX);
    let rows = Signal::derive({
        let events = StoredValue::new(page.events);
        move || events.get_value()
    });

    view! {
        <DataTable
            headers=vec!["When", "Action", "Who", "What", "From", ""]
            rows=rows
            key=|event: &AuditEvent| event.id
            noun="events"
            row=move |event: AuditEvent| view! { <Row event /> }
        />

        <div class="flex items-center justify-between text-sm text-ink-600 dark:text-ink-400">
            <span>
                {move || {
                    let first = offset.get() + 1;
                    format!("{first}–{} of {total}", offset.get() + shown)
                }}
            </span>
            <div class="flex gap-2">
                <button
                    type="button"
                    class="rounded border border-surface-300 px-2 py-1 disabled:opacity-40 dark:border-surface-700"
                    disabled=move || offset.get() == 0
                    on:click=move |_| offset.update(|value| *value = (*value - PAGE).max(0))
                >
                    "Newer"
                </button>
                <button
                    type="button"
                    class="rounded border border-surface-300 px-2 py-1 disabled:opacity-40 dark:border-surface-700"
                    disabled=move || offset.get() + shown >= total
                    on:click=move |_| offset.update(|value| *value += PAGE)
                >
                    "Older"
                </button>
            </div>
        </div>
    }
}

/// The cells of one recorded event.
#[component]
fn Row(event: AuditEvent) -> impl IntoView {
    let succeeded = event.outcome == Outcome::Success;
    // A security signal is not the same as a failure: a mistyped password is a
    // daily event, and a lockout firing is not. The rule lives in `contract`
    // so the console and anything else reading the log agree on it.
    let signal = event.action.is_security_signal();

    view! {
        <Cell>
            <span class="whitespace-nowrap font-mono text-xs">{event.occurred_at}</span>
        </Cell>
        <Cell>
            <span class=if signal { "font-semibold text-danger-600" } else { "" }>
                {event.action.description()}
            </span>
        </Cell>
        <Cell>{event.actor_name.unwrap_or_else(|| "—".to_owned())}</Cell>
        <Cell>
            <span class="text-ink-600 dark:text-ink-400">
                {event.target.unwrap_or_else(|| "—".to_owned())}
            </span>
        </Cell>
        <Cell>
            <span class="whitespace-nowrap font-mono text-xs text-ink-600 dark:text-ink-400">
                {event.ip_address.unwrap_or_else(|| "—".to_owned())}
            </span>
        </Cell>
        <Cell>
            <Badge ok=succeeded label=if succeeded { "ok" } else { "refused" } />
        </Cell>
    }
}
