//! Landing page.

use leptos::prelude::*;

use crate::{
    api::{self, ServerStatus},
    ui::{Card, ErrorBanner},
};

/// Landing page.
///
/// Loads its data with a [`Resource`] inside `<Suspense>`, which is what makes
/// SSR worthwhile: the server awaits the resource, streams the finished HTML,
/// and hydration picks up the already-resolved value instead of firing the
/// same request again from the browser.
#[component]
pub fn Home() -> impl IntoView {
    let status = Resource::new(|| (), |()| api::server_status());

    view! {
        <main class="mx-auto flex min-h-full max-w-3xl flex-col gap-6 px-6 py-16">
            <header>
                <h1 class="text-3xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                    "Authenc"
                </h1>
                <p class="mt-2 text-sm text-ink-600 dark:text-ink-400">
                    "Identity and access management, built on Leptos and Axum."
                </p>
            </header>

            <Card title="Server status">
                <Suspense fallback=|| {
                    view! { <p class="text-sm text-ink-500">"Checking…"</p> }
                }>
                    {move || Suspend::new(async move {
                        match status.await {
                            Ok(status) => StatusReport(StatusReportProps { status }).into_any(),
                            Err(error) => {
                                let message = api::describe(&error);
                                view! { <ErrorBanner message=Some(message) /> }.into_any()
                            }
                        }
                    })}
                </Suspense>
            </Card>
        </main>
    }
}

/// Renders a resolved [`ServerStatus`].
#[component]
fn StatusReport(
    /// What the server reported.
    status: ServerStatus,
) -> impl IntoView {
    let (database_label, database_class) = if status.database_ready {
        ("connected", "text-success-700 dark:text-success-400")
    } else {
        ("unreachable", "text-danger-700 dark:text-danger-400")
    };

    view! {
        <dl class="grid grid-cols-[auto_1fr] gap-x-6 gap-y-2 text-sm">
            <dt class="text-ink-500 dark:text-ink-400">"Version"</dt>
            <dd class="font-mono text-ink-900 dark:text-ink-100">{status.version}</dd>
            <dt class="text-ink-500 dark:text-ink-400">"Database"</dt>
            <dd class=format!("font-medium {database_class}")>{database_label}</dd>
        </dl>
    }
}
