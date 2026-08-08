//! The isomorphic web application.
//!
//! This crate is compiled **twice**: once to `wasm32-unknown-unknown` with the
//! `hydrate` feature (the half that runs in the browser) and once natively with
//! the `ssr` feature (the half that renders HTML and executes server
//! functions). The two are never enabled together — `leptos` refuses to
//! compile that way — so never build this crate with `--all-features`.
//!
//! Server-function bodies are compiled only under `ssr`. That is what lets a
//! `#[server]` function in [`api`] reach straight into the database while the
//! browser bundle contains nothing but the call site.

// A page is one deeply generic type built by nesting `view!` fragments, and the
// trait solver walks the whole thing. The default limit of 128 is reached by an
// ordinary page with a `<Suspense>` around a `<Card>` around a form — and it is
// reached in the release wasm build before the debug one, so a page that
// compiles locally can still fail CI. Raised here once rather than discovered
// per page.
#![recursion_limit = "256"]

pub mod api;
pub mod pages;
#[cfg(feature = "ssr")]
pub mod server_ctx;
pub mod ui;

use leptos::prelude::*;
use leptos_meta::{HashedStylesheet, MetaTags, Title, provide_meta_context};
use leptos_router::{
    StaticSegment,
    components::{ParentRoute, Route, Router, Routes},
};

/// The HTML document the server streams. Also used by the 404 handler, so a
/// missing asset renders the same chrome as a real page.
pub fn shell(options: LeptosOptions) -> impl IntoView {
    view! {
        <!DOCTYPE html>
        <html lang="en" class="h-full">
            <head>
                <meta charset="utf-8" />
                <meta name="viewport" content="width=device-width, initial-scale=1" />
                // Served from `crates/web/public`, not a CDN. The previous
                // console loaded Font Awesome from a third-party origin, with
                // no integrity hash, into an admin console.
                <link rel="icon" href="/favicon.svg" type="image/svg+xml" />
                // Drives `navigator.credentials` on the security page. Served
                // from `crates/web/public`, `defer` so it does not block the
                // first paint of every other page.
                <script src="/passkey.js" defer></script>
                <AutoReload options=options.clone() />
                <HydrationScripts options=options.clone() />
                <HashedStylesheet options id="leptos" />
                <MetaTags />
            </head>
            <body class="h-full bg-surface-100 text-ink-900 antialiased dark:bg-surface-950 dark:text-ink-100">
                <App />
            </body>
        </html>
    }
}

/// The application root: metadata, then the router.
#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Title text="Authenc" />
        <Router>
            <Routes fallback=pages::NotFound>
                <Route path=StaticSegment("") view=pages::Home />
                <Route path=StaticSegment("login") view=pages::Login />
                <Route path=StaticSegment("forgot-password") view=pages::ForgotPassword />
                <Route path=StaticSegment("reset-password") view=pages::ResetPassword />
                <Route path=StaticSegment("verify-email") view=pages::VerifyEmail />
                <Route path=StaticSegment("consent") view=pages::Consent />
                <Route path=StaticSegment("security") view=pages::Security />
                <ParentRoute path=StaticSegment("admin") view=pages::AdminShell>
                    <Route path=StaticSegment("") view=pages::Overview />
                    <Route path=StaticSegment("users") view=pages::Users />
                    <Route path=StaticSegment("roles") view=pages::Roles />
                    <Route path=StaticSegment("clients") view=pages::Clients />
                </ParentRoute>
            </Routes>
        </Router>
    }
}

/// Browser entry point. Called by the generated JS shim once the wasm module
/// loads; takes over the server-rendered DOM rather than replacing it.
#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
#[allow(unused_qualifications, reason = "`mount` is not in the leptos prelude")]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}
