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
    /// Button label.
    children: Children,
) -> impl IntoView {
    view! {
        <button
            type=kind
            disabled=move || disabled.get()
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
