//! Social-login providers.
//!
//! Read-only plus enable, disable, and delete. Creating one is deliberately
//! left to `/api/v1` and the CLI: it takes a client id and secret obtained by
//! registering this server at the provider, which is a task done once from a
//! terminal with the provider's console open beside it — not something a form
//! makes easier, and a form that took a secret would put one in a browser
//! field for no gain.
//!
//! What this page is for is the question an operator actually returns to: *how
//! can people get in, and through what?*

use authenc_contract::Permission;
use leptos::prelude::*;

use crate::{
    api,
    pages::admin::Session,
    ui::{Badge, Button, Cell, DataTable, ErrorBanner, Variant},
};

/// Social-login provider management.
#[component]
pub fn Providers() -> impl IntoView {
    let session = expect_context::<Session>().0;
    let error = RwSignal::new(None::<String>);

    let set_enabled = ServerAction::<api::SetProviderEnabled>::new();
    let remove = ServerAction::<api::DeleteProvider>::new();

    let providers = Resource::new(
        move || (set_enabled.version().get(), remove.version().get()),
        |_| api::list_providers(),
    );

    Effect::new(move |_| {
        let failures = [set_enabled.value().get(), remove.value().get()];
        error.set(
            failures
                .into_iter()
                .flatten()
                .find_map(Result::err)
                .map(|failure| api::describe(&failure)),
        );
    });

    let can_write = Signal::derive(move || {
        session
            .get()
            .and_then(Result::ok)
            .flatten()
            .is_some_and(|me| me.can(Permission::IdentityProviderWrite))
    });

    view! {
        <div class="flex flex-col gap-6">
            <h1 class="text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                "Social login"
            </h1>

            <p class="max-w-2xl text-sm text-ink-600 dark:text-ink-400">
                "Each provider is a way into this realm. \
                 Adding one takes a client id and secret from the provider's own console, \
                 so it is done through the API or the CLI rather than here."
            </p>

            <ErrorBanner message=error />

            <ProviderTable
                providers=providers
                can_write=can_write
                set_enabled=set_enabled
                remove=remove
            />
        </div>
    }
}

/// The list itself, or whatever went wrong loading it.
#[component]
fn ProviderTable(
    /// The loaded providers.
    providers: Resource<Result<Vec<api::ProviderSummary>, ServerFnError>>,
    /// Whether the viewer may change anything.
    can_write: Signal<bool>,
    /// Enable/disable action.
    set_enabled: ServerAction<api::SetProviderEnabled>,
    /// Delete action.
    remove: ServerAction<api::DeleteProvider>,
) -> impl IntoView {
    view! {
        <Transition fallback=|| {
            view! { <p class="text-sm text-ink-500">"Loading providers…"</p> }
        }>
            {move || Suspend::new(async move {
                match providers.await {
                    Err(failure) => {
                        let message = api::describe(&failure);
                        view! { <ErrorBanner message=Some(message) /> }.into_any()
                    }
                    Ok(list) => {
                        let rows = Signal::derive(move || list.clone());
                        view! {
                            <DataTable
                                headers=vec![
                                    "Provider",
                                    "Alias",
                                    "Accounts",
                                    "New accounts",
                                    "Adoption",
                                    "Status",
                                    "",
                                ]
                                rows=rows
                                key=|provider: &api::ProviderSummary| provider.id
                                noun="providers"
                                row=move |provider: api::ProviderSummary| {
                                    view! {
                                        <ProviderRow
                                            provider=provider
                                            can_write=can_write
                                            set_enabled=set_enabled
                                            remove=remove
                                        />
                                    }
                                }
                            />
                        }
                            .into_any()
                    }
                }
            })}
        </Transition>
    }
}

/// One row of the provider table.
#[component]
fn ProviderRow(
    /// The provider this row shows.
    provider: api::ProviderSummary,
    /// Whether the viewer may change anything.
    can_write: Signal<bool>,
    /// Enable/disable action.
    set_enabled: ServerAction<api::SetProviderEnabled>,
    /// Delete action.
    remove: ServerAction<api::DeleteProvider>,
) -> impl IntoView {
    let id = provider.id;
    let enabled = provider.enabled;
    let links = provider.links;

    view! {
        <Cell>
            <span class="font-medium text-ink-900 dark:text-ink-100">
                {provider.display_name}
            </span>
            <span class="ml-2 text-xs text-ink-500">{provider.kind}</span>
        </Cell>
        <Cell>
            <code class="text-xs text-ink-600 dark:text-ink-400">{provider.alias}</code>
        </Cell>
        <Cell>{links}</Cell>
        <Cell>
            <Badge
                ok=provider.allow_provisioning
                label=if provider.allow_provisioning { "creates" } else { "existing only" }
            />
        </Cell>
        <Cell>
            // Not a green tick. Adoption lets an upstream account claim an
            // existing local one on a matching verified address, which is the
            // setting worth noticing on this page — so it reads as a warning
            // when on rather than as a feature that is working.
            <Badge
                ok=!provider.link_by_verified_email
                label=if provider.link_by_verified_email { "by email" } else { "off" }
            />
        </Cell>
        <Cell>
            <Badge ok=enabled label=if enabled { "offered" } else { "hidden" } />
        </Cell>
        <Cell>
            <Show when=move || can_write.get()>
                <div class="flex gap-2">
                    <Button
                        variant=Variant::Secondary
                        on_click=Callback::new(move |()| {
                            set_enabled
                                .dispatch(api::SetProviderEnabled { id, enabled: !enabled });
                        })
                    >
                        {if enabled { "Hide" } else { "Offer" }}
                    </Button>
                    <Button
                        variant=Variant::Danger
                        on_click=Callback::new(move |()| {
                            remove.dispatch(api::DeleteProvider { id });
                        })
                    >
                        "Delete"
                    </Button>
                </div>
            </Show>
        </Cell>
    }
}
