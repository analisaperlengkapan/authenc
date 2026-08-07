//! Design-system primitives.
//!
//! Every visual decision — colour, spacing, radius, shadow — is expressed as a
//! Tailwind class on one of these components, and nowhere else. The previous
//! console inlined `style="..."` strings at every call site; the block
//! `background: white; padding: 20px; border-radius: 8px; box-shadow: ...`
//! appeared verbatim fifteen times, and the five CSS custom properties that
//! were declared were never referenced at all.
//!
//! Adding a page should mean composing these, not inventing new styling.

use leptos::prelude::*;

/// Visual weight of a [`Button`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Variant {
    /// The single affirmative action on a view.
    #[default]
    Primary,
    /// Everything else.
    Secondary,
    /// Destructive actions; always pair with a confirmation.
    Danger,
}

impl Variant {
    const fn classes(self) -> &'static str {
        match self {
            Self::Primary => {
                "bg-brand-600 text-white hover:bg-brand-700 focus-visible:outline-brand-600"
            }
            Self::Secondary => {
                "bg-surface-100 text-ink-700 ring-1 ring-inset ring-ink-300 \
                 hover:bg-surface-200 focus-visible:outline-ink-400 \
                 dark:bg-surface-800 dark:text-ink-200 dark:ring-ink-700 dark:hover:bg-surface-700"
            }
            Self::Danger => {
                "bg-danger-600 text-white hover:bg-danger-700 focus-visible:outline-danger-600"
            }
        }
    }
}

/// A button.
#[component]
pub fn Button(
    /// Visual weight.
    #[prop(optional)]
    variant: Variant,
    /// `type` attribute; `submit` inside forms.
    #[prop(default = "button")]
    kind: &'static str,
    /// Whether the button is disabled.
    #[prop(optional, into)]
    disabled: Signal<bool>,
    /// What to do when clicked. Omitted for submit buttons, whose form
    /// handles the event.
    #[prop(optional)]
    on_click: Option<Callback<()>>,
    /// Button label.
    children: Children,
) -> impl IntoView {
    view! {
        <button
            type=kind
            disabled=move || disabled.get()
            on:click=move |_| {
                if let Some(on_click) = on_click {
                    on_click.run(());
                }
            }
            class=format!(
                "inline-flex items-center justify-center gap-2 rounded-md px-3.5 py-2 \
                 text-sm font-semibold shadow-xs transition-colors \
                 focus-visible:outline-2 focus-visible:outline-offset-2 \
                 disabled:cursor-not-allowed disabled:opacity-50 {}",
                variant.classes(),
            )
        >
            {children()}
        </button>
    }
}

/// A titled content panel.
#[component]
pub fn Card(
    /// Heading shown above the content.
    #[prop(optional, into)]
    title: Option<String>,
    /// Panel content.
    children: Children,
) -> impl IntoView {
    view! {
        <section class="rounded-lg bg-surface-50 p-5 shadow-sm ring-1 ring-ink-200 \
                        dark:bg-surface-900 dark:ring-ink-800">
            {title
                .map(|t| {
                    view! {
                        <h2 class="mb-3 text-base font-semibold text-ink-900 dark:text-ink-100">
                            {t}
                        </h2>
                    }
                })}
            {children()}
        </section>
    }
}

/// An error banner.
///
/// One component, one colour scheme. The previous console had nine copies of
/// this markup across its pages, in two different and inconsistent palettes.
#[component]
pub fn ErrorBanner(
    /// Message to show; renders nothing when `None`.
    #[prop(into)]
    message: Signal<Option<String>>,
) -> impl IntoView {
    view! {
        <Show when=move || message.get().is_some()>
            <div
                role="alert"
                class="rounded-md bg-danger-50 p-3 text-sm text-danger-800 \
                       ring-1 ring-danger-200 dark:bg-danger-950 dark:text-danger-200 \
                       dark:ring-danger-900"
            >
                {move || message.get().unwrap_or_default()}
            </div>
        </Show>
    }
}

/// Placeholder shown where a list would be, when the list is empty.
#[component]
pub fn EmptyState(
    /// What is missing, e.g. `"users"`.
    #[prop(into)]
    noun: String,
) -> impl IntoView {
    view! {
        <p class="px-4 py-10 text-center text-sm text-ink-500 dark:text-ink-400">
            {format!("No {noun} yet.")}
        </p>
    }
}

/// A labelled text input.
///
/// One component for what the previous console repeated about forty times as
/// an inline-styled `<input>` with its own `on:input` closure.
#[component]
pub fn Field(
    /// Visible label.
    #[prop(into)]
    label: String,
    /// Field name, also used as the element id.
    #[prop(into)]
    name: String,
    /// Two-way bound value.
    value: RwSignal<String>,
    /// `type` attribute.
    #[prop(default = "text")]
    kind: &'static str,
    /// Browser autofill hint. Getting this right is what lets a password
    /// manager work.
    #[prop(optional)]
    autocomplete: Option<&'static str>,
) -> impl IntoView {
    view! {
        <div class="flex flex-col gap-1.5">
            <label
                for=name.clone()
                class="text-sm font-medium text-ink-700 dark:text-ink-300"
            >
                {label}
            </label>
            <input
                id=name.clone()
                name=name
                type=kind
                autocomplete=autocomplete
                class="rounded-md border-0 bg-surface-50 px-3 py-2 text-sm text-ink-900 \
                       shadow-xs ring-1 ring-inset ring-ink-300 placeholder:text-ink-400 \
                       focus:ring-2 focus:ring-inset focus:ring-brand-600 \
                       dark:bg-surface-800 dark:text-ink-100 dark:ring-ink-700"
                prop:value=move || value.get()
                on:input=move |ev| value.set(event_target_value(&ev))
            />
        </div>
    }
}

/// A table with a header, a keyed body, and an empty state.
///
/// The previous console copy-pasted the same table chrome across eight pages —
/// the identical `style="padding: 15px; text-align: left; …"` on every `<th>` —
/// and built each `<tbody>` with `.collect_view()` inside a closure, so the
/// whole body was torn down and rebuilt on every refetch. This uses `<For>`
/// with a key, so a refetch touches only the rows that actually changed.
#[component]
pub fn DataTable<T, K, KF, RF, IV>(
    /// Column headings.
    headers: Vec<&'static str>,
    /// The rows to render.
    #[prop(into)]
    rows: Signal<Vec<T>>,
    /// Stable key per row. Identity, not index — an index key defeats the
    /// point by re-associating every row when one is removed.
    key: KF,
    /// Renders the cells of one row.
    row: RF,
    /// What is missing, for the empty state, e.g. `"users"`.
    #[prop(into)]
    noun: String,
) -> impl IntoView
where
    T: Clone + Send + Sync + 'static,
    K: Eq + std::hash::Hash + 'static,
    KF: Fn(&T) -> K + Clone + Send + Sync + 'static,
    RF: Fn(T) -> IV + Clone + Send + Sync + 'static,
    IV: IntoView + 'static,
{
    // `<Show>` calls its children on every re-evaluation, so the closure must
    // be `Fn`. `StoredValue` is `Copy`, which lets the closure read the
    // renderer without taking ownership of it.
    let row = StoredValue::new(row);
    let headers = StoredValue::new(headers);
    let noun = StoredValue::new(noun);

    view! {
        <div class="overflow-x-auto rounded-lg ring-1 ring-ink-200 dark:ring-ink-800">
            <Show
                when=move || !rows.get().is_empty()
                fallback=move || view! { <EmptyState noun=noun.get_value() /> }
            >
                <table class="w-full text-left text-sm">
                    <thead class="bg-surface-100 text-xs uppercase tracking-wide text-ink-600 dark:bg-surface-800 dark:text-ink-400">
                        <tr>
                            {headers
                                .get_value()
                                .into_iter()
                                .map(|heading| {
                                    view! {
                                        <th scope="col" class="px-4 py-3 font-semibold">
                                            {heading}
                                        </th>
                                    }
                                })
                                .collect_view()}
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-ink-200 bg-surface-50 dark:divide-ink-800 dark:bg-surface-900">
                        <For each=move || rows.get() key=key.clone() let:item>
                            <tr class="hover:bg-surface-100 dark:hover:bg-surface-800">
                                {row.get_value()(item)}
                            </tr>
                        </For>
                    </tbody>
                </table>
            </Show>
        </div>
    }
}

/// A single cell, so pages do not repeat the padding.
#[component]
pub fn Cell(
    /// Cell content.
    children: Children,
) -> impl IntoView {
    view! { <td class="px-4 py-3 text-ink-800 dark:text-ink-200">{children()}</td> }
}

/// A small status pill.
#[component]
pub fn Badge(
    /// Whether the state is the good one.
    ok: bool,
    /// Label.
    #[prop(into)]
    label: String,
) -> impl IntoView {
    let tone = if ok {
        "bg-success-50 text-success-700 ring-success-200 \
         dark:bg-success-950 dark:text-success-400 dark:ring-success-900"
    } else {
        "bg-ink-100 text-ink-600 ring-ink-200 \
         dark:bg-ink-900 dark:text-ink-400 dark:ring-ink-800"
    };

    view! {
        <span class=format!(
            "inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium \
             ring-1 ring-inset {tone}",
        )>{label}</span>
    }
}
