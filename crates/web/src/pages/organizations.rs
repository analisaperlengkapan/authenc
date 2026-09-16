//! Organisations: the tenant-facing grouping, separate from realms.
//!
//! A realm is an isolation boundary — separate users, separate roles, separate
//! sign-in. An organisation is a grouping *inside* one, so several customers
//! can share a realm and still be suspended independently. Suspending an
//! organisation stops its members signing in, unless they also belong to
//! another that is still enabled; that exception is what keeps a consultant
//! working for two customers from losing their account when one is suspended.

use authenc_contract::Permission;
use leptos::prelude::*;

use crate::{
    api,
    pages::admin::Session,
    ui::{Badge, Button, Card, Cell, DataTable, ErrorBanner, Field, Variant},
};

/// Organisation management.
#[component]
pub fn Organizations() -> impl IntoView {
    let session = expect_context::<Session>().0;
    let error = RwSignal::new(None::<String>);

    let create = ServerAction::<api::CreateOrganization>::new();
    let set_enabled = ServerAction::<api::SetOrganizationEnabled>::new();
    let remove = ServerAction::<api::DeleteOrganization>::new();

    let organizations = Resource::new(
        move || {
            (
                create.version().get(),
                set_enabled.version().get(),
                remove.version().get(),
            )
        },
        |_| api::list_organizations(),
    );

    Effect::new(move |_| {
        let failures = [
            create.value().get().map(|result| result.map(|_| ())),
            set_enabled.value().get(),
            remove.value().get(),
        ];
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
            .is_some_and(|me| me.can(Permission::OrganizationWrite))
    });

    view! {
        <div class="flex flex-col gap-6">
            <h1 class="text-2xl font-bold tracking-tight text-ink-900 dark:text-ink-50">
                "Organisations"
            </h1>

            <p class="max-w-2xl text-sm text-ink-600 dark:text-ink-400">
                "Suspending an organisation stops its members signing in — unless they also \
                 belong to another organisation that is still enabled."
            </p>

            <ErrorBanner message=error />

            <Show when=move || can_write.get()>
                <CreateOrganizationForm create=create />
            </Show>

            <OrganizationTable
                organizations=organizations
                can_write=can_write
                set_enabled=set_enabled
                remove=remove
            />
        </div>
    }
}

/// The list itself, or whatever went wrong loading it.
#[component]
fn OrganizationTable(
    /// The loaded organisations.
    organizations: Resource<Result<Vec<api::OrganizationSummary>, ServerFnError>>,
    /// Whether the viewer may change anything.
    can_write: Signal<bool>,
    /// Suspend/restore action.
    set_enabled: ServerAction<api::SetOrganizationEnabled>,
    /// Delete action.
    remove: ServerAction<api::DeleteOrganization>,
) -> impl IntoView {
    view! {
        <Transition fallback=|| {
            view! { <p class="text-sm text-ink-500">"Loading organisations…"</p> }
        }>
            {move || Suspend::new(async move {
                match organizations.await {
                    Err(failure) => {
                        let message = api::describe(&failure);
                        view! { <ErrorBanner message=Some(message) /> }.into_any()
                    }
                    Ok(list) => {
                        let rows = Signal::derive(move || list.clone());
                        view! {
                            <DataTable
                                headers=vec!["Name", "Slug", "Members", "Invited", "Status", ""]
                                rows=rows
                                key=|organization: &api::OrganizationSummary| organization.id
                                noun="organisations"
                                row=move |organization: api::OrganizationSummary| {
                                    view! {
                                        <OrganizationRow
                                            organization=organization
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

/// One row of the organisation table.
#[component]
fn OrganizationRow(
    /// The organisation this row shows.
    organization: api::OrganizationSummary,
    /// Whether the viewer may change anything.
    can_write: Signal<bool>,
    /// Suspend/restore action.
    set_enabled: ServerAction<api::SetOrganizationEnabled>,
    /// Delete action.
    remove: ServerAction<api::DeleteOrganization>,
) -> impl IntoView {
    let id = organization.id;
    let enabled = organization.enabled;
    let invited = organization.pending_invitations;

    view! {
        <Cell>{organization.name}</Cell>
        <Cell>
            <code class="text-xs text-ink-600 dark:text-ink-400">{organization.slug}</code>
        </Cell>
        <Cell>{organization.members}</Cell>
        <Cell>{if invited == 0 { "—".to_owned() } else { invited.to_string() }}</Cell>
        <Cell>
            <Badge ok=enabled label=if enabled { "enabled" } else { "suspended" } />
        </Cell>
        <Cell>
            <Show when=move || can_write.get()>
                <div class="flex gap-2">
                    <Button
                        variant=Variant::Secondary
                        on_click=Callback::new(move |()| {
                            set_enabled
                                .dispatch(api::SetOrganizationEnabled {
                                    id,
                                    enabled: !enabled,
                                });
                        })
                    >
                        {if enabled { "Suspend" } else { "Restore" }}
                    </Button>
                    <Button
                        variant=Variant::Danger
                        on_click=Callback::new(move |()| {
                            remove.dispatch(api::DeleteOrganization { id });
                        })
                    >
                        "Delete"
                    </Button>
                </div>
            </Show>
        </Cell>
    }
}

/// The form for adding an organisation.
#[component]
fn CreateOrganizationForm(
    /// The create action.
    create: ServerAction<api::CreateOrganization>,
) -> impl IntoView {
    let slug = RwSignal::new(String::new());
    let name = RwSignal::new(String::new());

    // The same rule `identity::organization::create` enforces, so a slug it
    // will refuse cannot be submitted.
    let ready = Signal::derive(move || {
        let slug = slug.get();
        let slug = slug.trim();
        !slug.is_empty()
            && !name.get().trim().is_empty()
            && slug
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });

    let pending = create.pending();

    Effect::new(move |_| {
        if matches!(create.value().get(), Some(Ok(_))) {
            slug.set(String::new());
            name.set(String::new());
        }
    });

    view! {
        <Card title="Add an organisation">
            <form
                class="grid gap-4 sm:grid-cols-3 sm:items-end"
                on:submit=move |ev| {
                    ev.prevent_default();
                    create
                        .dispatch(api::CreateOrganization {
                            slug: slug.get_untracked().trim().to_owned(),
                            name: name.get_untracked().trim().to_owned(),
                        });
                }
            >
                <Field label="Name" name="new-org-name" value=name />
                <Field label="Slug" name="new-org-slug" value=slug />
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
