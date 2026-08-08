//! The admin console: a shell with navigation, and the pages inside it.

use authenc_contract::{Permission, model::LoginResponse};
use leptos::prelude::*;
use leptos_router::components::{A, Outlet};

use crate::{
    api,
    ui::{Badge, Button, Card, Cell, DataTable, ErrorBanner, Field, Variant},
};

/// The signed-in user, resolved once and shared by every page in the console.
///
/// A page reads this rather than fetching for itself, so the whole console
/// makes one identity call per navigation instead of one per component.
#[derive(Clone, Copy)]
pub(super) struct Session(pub(super) Resource<Result<Option<LoginResponse>, ServerFnError>>);

/// Console shell: navigation, the signed-in user, and the sign-out control.
///
/// Anyone who is not signed in is sent to the login page **by the server**,
/// before any of this renders. The previous console decided that in the
/// browser, by reading `localStorage` inside a route closure — which meant the
/// markup was delivered first and the redirect happened afterwards.
#[component]
pub fn AdminShell() -> impl IntoView {
    let session = Resource::new(|| (), |()| api::current_user());
    provide_context(Session(session));

    let sign_out = ServerAction::<api::LogOut>::new();
    Effect::new(move |_| {
        if sign_out.value().get().is_some() {
            window_location_assign("/login");
        }
    });

    view! {
        <div class="flex min-h-full flex-col">
            <Suspense fallback=|| {
                view! { <p class="p-6 text-sm text-ink-500">"Loading…"</p> }
            }>
                {move || Suspend::new(async move {
                    match session.await {
                        Ok(Some(me)) => ShellFrame(ShellFrameProps { me, sign_out }).into_any(),
                        // No session, or the lookup failed: the server has
                        // already been told to redirect, so render nothing.
                        _ => {
                            redirect_to_login();
                            ().into_any()
                        }
                    }
                })}
            </Suspense>
        </div>
    }
}

/// Ask the server to redirect an unauthenticated visitor to the login page.
///
/// `pub(crate)` because the security page needs the same guard: a page that
/// renders "unauthenticated" as an error message has still rendered, and the
/// visitor is left reading a failure instead of a login form.
pub(crate) fn redirect_to_login() {
    #[cfg(feature = "ssr")]
    leptos_axum::redirect("/login");

    #[cfg(feature = "hydrate")]
    window_location_assign("/login");
}

/// Navigate the browser, when there is one.
fn window_location_assign(_path: &str) {
    #[cfg(feature = "hydrate")]
    if let Some(window) = web_sys::window() {
        let _ = window.location().set_href(_path);
    }
}

/// The chrome around a signed-in console page.
#[component]
fn ShellFrame(
    /// Who is signed in.
    me: LoginResponse,
    /// The sign-out action.
    sign_out: ServerAction<api::LogOut>,
) -> impl IntoView {
    let display_name = me.user.display_name();

    view! {
        <header class="border-b border-ink-200 bg-surface-50 dark:border-ink-800 dark:bg-surface-900">
            <div class="mx-auto flex max-w-5xl items-center gap-6 px-6 py-3">
                <span class="font-semibold text-ink-900 dark:text-ink-50">"Authenc"</span>
                <nav class="flex gap-4 text-sm">
                    <NavLink href="/admin" label="Overview" />
                    <NavLink href="/admin/users" label="Users" />
                    <NavLink href="/admin/roles" label="Roles" />
                    <NavLink href="/admin/clients" label="Clients" />
                    <NavLink href="/admin/audit" label="Audit" />
                </nav>
                <div class="ml-auto flex items-center gap-3 text-sm">
                    <span class="text-ink-600 dark:text-ink-400">{display_name}</span>
                    <button
                        type="button"
                        class="font-semibold text-brand-600 hover:text-brand-700"
                        on:click=move |_| {
                            sign_out.dispatch(api::LogOut {});
                        }
                    >
                        "Sign out"
                    </button>
                </div>
            </div>
        </header>
        <main class="mx-auto w-full max-w-5xl flex-1 px-6 py-8">
            <Outlet />
        </main>
    }
}

/// One navigation link.
#[component]
fn NavLink(
    /// Target path.
    href: &'static str,
    /// Visible label.
    label: &'static str,
) -> impl IntoView {
    view! {
        <A
            href=href
            attr:class="text-ink-600 hover:text-ink-900 dark:text-ink-400 dark:hover:text-ink-100"
        >
            {label}
        </A>
    }
}

/// What the console can show about the signed-in session.
#[component]
pub fn Overview() -> impl IntoView {
    let session = expect_context::<Session>().0;

    view! {
        <div class="flex flex-col gap-6">
            <h1 class="text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                "Overview"
            </h1>
            <Card title="Your access">
                <Suspense fallback=|| view! { <p class="text-sm text-ink-500">"Loading…"</p> }>
                    {move || Suspend::new(async move {
                        let permissions = session
                            .await
                            .ok()
                            .flatten()
                            .map(|me| me.permissions)
                            .unwrap_or_default();

                        if permissions.is_empty() {
                            return view! {
                                <p class="text-sm text-ink-600 dark:text-ink-400">
                                    "You hold no permissions. An administrator can grant you a role."
                                </p>
                            }
                                .into_any();
                        }

                        view! {
                            <ul class="flex flex-wrap gap-2">
                                {permissions
                                    .into_iter()
                                    .map(|permission| {
                                        view! {
                                            <li>
                                                <Badge ok=true label=permission.to_string() />
                                            </li>
                                        }
                                    })
                                    .collect_view()}
                            </ul>
                        }
                            .into_any()
                    })}
                </Suspense>
            </Card>
        </div>
    }
}

/// User management.
#[component]
pub fn Users() -> impl IntoView {
    let session = expect_context::<Session>().0;
    let error = RwSignal::new(None::<String>);
    let reload = RwSignal::new(0_u32);

    let create = ServerAction::<api::CreateUser>::new();
    let set_enabled = ServerAction::<api::SetUserEnabled>::new();
    let remove = ServerAction::<api::DeleteUser>::new();

    // One resource, re-read whenever any of the three actions completes. The
    // previous console called `refetch()` from inside each action's success
    // branch, twenty-seven times over.
    let users = Resource::new(
        move || {
            (
                reload.get(),
                create.version().get(),
                set_enabled.version().get(),
                remove.version().get(),
            )
        },
        |_| api::list_users(50, 0),
    );

    // Surface whichever action last failed, in one place. The actions return
    // different success types, so each is mapped to `()` before comparison.
    Effect::new(move |_| {
        let failures = [
            create.value().get().map(|r| r.map(|_| ())),
            set_enabled.value().get(),
            remove.value().get(),
        ];
        error.set(
            failures
                .into_iter()
                .flatten()
                .find_map(|result| result.err())
                .map(|e| api::describe(&e)),
        );
    });

    let can_write = Signal::derive(move || {
        session
            .get()
            .and_then(Result::ok)
            .flatten()
            .is_some_and(|me| me.can(Permission::UserWrite))
    });

    view! {
        <div class="flex flex-col gap-6">
            <h1 class="text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">"Users"</h1>

            <ErrorBanner message=error />

            <Show when=move || can_write.get()>
                <CreateUserForm create=create />
            </Show>

            <Transition fallback=|| {
                view! { <p class="text-sm text-ink-500">"Loading users…"</p> }
            }>
                {move || Suspend::new(async move {
                    match users.await {
                        Err(failure) => {
                            let message = api::describe(&failure);
                            view! { <ErrorBanner message=Some(message) /> }.into_any()
                        }
                        Ok(page) => {
                            let rows = Signal::derive(move || page.items.clone());
                            let total = page.total;
                            view! {
                                <div class="flex flex-col gap-2">
                                    <DataTable
                                        headers=vec!["Username", "Email", "Verified", "Status", ""]
                                        rows=rows
                                        key=|user: &authenc_contract::model::User| user.id
                                        noun="users"
                                        row=move |user: authenc_contract::model::User| {
                                            view! {
                                                <UserRow
                                                    user=user
                                                    can_write=can_write
                                                    set_enabled=set_enabled
                                                    remove=remove
                                                />
                                            }
                                        }
                                    />
                                    <p class="text-xs text-ink-500">
                                        {format!("{total} user(s)")}
                                    </p>
                                </div>
                            }
                                .into_any()
                        }
                    }
                })}
            </Transition>
        </div>
    }
}

/// One row of the user table.
#[component]
fn UserRow(
    /// The user this row shows.
    user: authenc_contract::model::User,
    /// Whether the viewer may change anything.
    can_write: Signal<bool>,
    /// Enable/disable action.
    set_enabled: ServerAction<api::SetUserEnabled>,
    /// Delete action.
    remove: ServerAction<api::DeleteUser>,
) -> impl IntoView {
    let id = user.id;
    let enabled = user.enabled;

    view! {
        <Cell>{user.username}</Cell>
        <Cell>{user.email}</Cell>
        <Cell>
            <Badge
                ok=user.email_verified
                label=if user.email_verified { "verified" } else { "unverified" }
            />
        </Cell>
        <Cell>
            <Badge ok=enabled label=if enabled { "enabled" } else { "disabled" } />
        </Cell>
        <Cell>
            <Show when=move || can_write.get()>
                <div class="flex gap-2">
                    <Button
                        variant=Variant::Secondary
                        on_click=Callback::new(move |()| {
                            set_enabled
                                .dispatch(api::SetUserEnabled {
                                    user_id: id,
                                    enabled: !enabled,
                                });
                        })
                    >
                        {if enabled { "Disable" } else { "Enable" }}
                    </Button>
                    <Button
                        variant=Variant::Danger
                        on_click=Callback::new(move |()| {
                            remove.dispatch(api::DeleteUser { user_id: id });
                        })
                    >
                        "Delete"
                    </Button>
                </div>
            </Show>
        </Cell>
    }
}

/// The form for adding a user.
#[component]
fn CreateUserForm(
    /// The create action.
    create: ServerAction<api::CreateUser>,
) -> impl IntoView {
    let username = RwSignal::new(String::new());
    let email = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());

    // The same rules the server enforces, from `authenc-contract`.
    let ready = Signal::derive(move || {
        use authenc_contract::validate;
        validate::username(&username.get()).is_ok()
            && validate::email(&email.get()).is_ok()
            && validate::password(&password.get()).is_ok()
    });

    let pending = create.pending();

    Effect::new(move |_| {
        if matches!(create.value().get(), Some(Ok(_))) {
            username.set(String::new());
            email.set(String::new());
            password.set(String::new());
        }
    });

    view! {
        <Card title="Add a user">
            <form
                class="grid gap-4 sm:grid-cols-4 sm:items-end"
                on:submit=move |ev| {
                    ev.prevent_default();
                    create
                        .dispatch(api::CreateUser {
                            username: username.get_untracked(),
                            email: email.get_untracked(),
                            password: password.get_untracked(),
                        });
                }
            >
                <Field label="Username" name="new-username" value=username />
                <Field label="Email" name="new-email" value=email kind="email" />
                <Field
                    label="Password"
                    name="new-password"
                    value=password
                    kind="password"
                    autocomplete="new-password"
                />
                <Button
                    kind="submit"
                    disabled=Signal::derive(move || pending.get() || !ready.get())
                >
                    "Create"
                </Button>
            </form>
        </Card>
    }
}

/// Role listing.
#[component]
pub fn Roles() -> impl IntoView {
    let roles = Resource::new(|| (), |()| api::list_roles());

    view! {
        <div class="flex flex-col gap-6">
            <h1 class="text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">"Roles"</h1>

            <Transition fallback=|| {
                view! { <p class="text-sm text-ink-500">"Loading roles…"</p> }
            }>
                {move || Suspend::new(async move {
                    match roles.await {
                        Err(failure) => {
                            let message = api::describe(&failure);
                            view! { <ErrorBanner message=Some(message) /> }.into_any()
                        }
                        Ok(list) => {
                            let rows = Signal::derive(move || list.clone());
                            view! {
                                <DataTable
                                    headers=vec!["Name", "Description"]
                                    rows=rows
                                    key=|role: &authenc_contract::model::Role| role.id
                                    noun="roles"
                                    row=|role: authenc_contract::model::Role| {
                                        view! {
                                            <Cell>{role.name}</Cell>
                                            <Cell>
                                                {role.description.unwrap_or_else(|| "—".into())}
                                            </Cell>
                                        }
                                    }
                                />
                            }
                                .into_any()
                        }
                    }
                })}
            </Transition>
        </div>
    }
}
