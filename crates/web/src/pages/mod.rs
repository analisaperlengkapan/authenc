//! Page components, one per route.

pub mod home;
pub mod login;
pub mod recovery;

pub use home::Home;
pub use login::Login;
pub use recovery::{ForgotPassword, ResetPassword, VerifyEmail};

use leptos::prelude::*;

/// Shown for any unmatched route.
#[component]
pub fn NotFound() -> impl IntoView {
    // Make the server answer 404 rather than 200-with-a-404-page, so crawlers
    // and monitoring see the truth.
    #[cfg(feature = "ssr")]
    if let Some(response) = use_context::<leptos_axum::ResponseOptions>() {
        response.set_status(http::StatusCode::NOT_FOUND);
    }

    view! {
        <main class="mx-auto flex min-h-full max-w-3xl flex-col gap-4 px-6 py-16">
            <h1 class="text-3xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                "Not found"
            </h1>
            <p class="text-sm text-ink-600 dark:text-ink-400">
                "That page does not exist."
            </p>
            <a class="text-sm font-semibold text-brand-600 hover:text-brand-700" href="/">
                "Back to the start"
            </a>
        </main>
    }
}
