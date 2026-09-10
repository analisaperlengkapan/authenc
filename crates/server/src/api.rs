//! The REST API under `/api/v1`, and its OpenAPI document.
//!
//! This is the second of the two thin surfaces over the same use cases. The
//! console uses server functions; scripts, Terraform providers, and CI use
//! this. Neither is the "real" one, and neither holds any business logic —
//! every handler here is a few lines that unwrap an extractor, call
//! `authenc_identity::admin`, and wrap the result.
//!
//! Authorisation is **not** applied here. It lives in the use case, which
//! takes the [`Actor`] and decides. A handler that forgot to authorise would
//! still be refused, which is the property the previous design lacked: there,
//! access control was a middleware matched on URL prefixes, so a route mounted
//! on the wrong router silently lost it.

use authenc_contract::{
    GroupId, IdentityProviderId, InvitationId, OrganizationId, Permission, RoleId, UserId,
    model::{Realm, Role, User},
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::{auth::CurrentUser, error::ApiError, state::AppState};

/// Page of results plus the total, so a caller can size its own paging.
#[derive(Debug, Serialize, ToSchema)]
pub struct Page<T> {
    /// The rows on this page.
    pub items: Vec<T>,
    /// How many rows exist in total.
    pub total: i64,
}

/// Paging parameters.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct Paging {
    /// Maximum rows to return. Clamped server-side to 200.
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Rows to skip.
    #[serde(default)]
    pub offset: i64,
}

const fn default_limit() -> i64 {
    50
}

/// A group, as `/api/v1` returns it.
#[derive(Debug, Serialize, ToSchema)]
pub struct GroupView {
    /// Stable identifier.
    pub id: Uuid,
    /// Parent, if it is not at the root.
    pub parent_id: Option<Uuid>,
    /// Name, unique among its siblings.
    pub name: String,
    /// What it is for.
    pub description: Option<String>,
    /// Full path from the root, e.g. `/engineering/backend`.
    pub path: String,
}

impl From<authenc_identity::group::Group> for GroupView {
    fn from(group: authenc_identity::group::Group) -> Self {
        Self {
            id: group.id.0,
            parent_id: group.parent_id.map(|id| id.0),
            name: group.name,
            description: group.description,
            path: group.path,
        }
    }
}

/// Body for replacing a role's permissions.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetRolePermissions {
    /// The complete set the role should hold, by name (`user:read`).
    /// Anything absent is removed.
    ///
    /// Strings rather than a typed enum, so an unrecognised name is a 400 that
    /// says which one — `authenc-contract` stays free of `utoipa`, and a serde
    /// variant rejection would report only that the body was unparseable.
    pub permissions: Vec<String>,
}

/// Body for creating a group.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateGroup {
    /// Parent group, or null for a root group.
    pub parent_id: Option<Uuid>,
    /// Name, unique among its siblings.
    pub name: String,
    /// What it is for.
    pub description: Option<String>,
}

/// Body for moving a group.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct MoveGroup {
    /// The new parent, or null to move it to the root.
    pub parent_id: Option<Uuid>,
}

/// An organisation, as `/api/v1` returns it.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationView {
    /// Stable identifier.
    pub id: Uuid,
    /// URL-safe handle.
    pub slug: String,
    /// Human-facing name.
    pub name: String,
    /// Whether its members may sign in.
    pub enabled: bool,
}

impl From<authenc_identity::organization::Organization> for OrganizationView {
    fn from(organization: authenc_identity::organization::Organization) -> Self {
        Self {
            id: organization.id.0,
            slug: organization.slug,
            name: organization.name,
            enabled: organization.enabled,
        }
    }
}

/// Body for creating an organisation.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateOrganization {
    /// URL-safe handle: lowercase letters, digits, and hyphens.
    pub slug: String,
    /// Human-facing name.
    pub name: String,
}

/// Body for setting someone's role in an organisation.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetOrganizationMember {
    /// `owner`, `admin`, or `member`.
    pub role: String,
}

/// Body for inviting an address to an organisation.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct InviteToOrganization {
    /// Where to send the link.
    pub email: String,
    /// The role they will hold once they accept.
    pub role: String,
}

/// A member and their standing.
///
/// Flattened rather than nesting the whole `User`: what a membership list needs
/// is who and in what capacity, and every extra field published here becomes a
/// compatibility obligation the moment a caller reads it.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationMemberView {
    /// Stable identifier.
    pub id: Uuid,
    /// Login name.
    pub username: String,
    /// Email address.
    pub email: String,
    /// Their role inside the organisation: `owner`, `admin`, or `member`.
    pub role: String,
}

/// An invitation, without its token.
///
/// The link exists once, at the moment it is created. An endpoint that could
/// hand one back would let anyone who can read the list join as anyone who was
/// invited.
#[derive(Debug, Serialize, ToSchema)]
pub struct InvitationView {
    /// Stable identifier.
    pub id: Uuid,
    /// Who was invited.
    pub email: String,
    /// The role they will hold.
    pub role: String,
    /// Whether it has been used.
    pub accepted: bool,
    /// When it stops working, RFC 3339.
    pub expires_at: String,
}

/// A social-login provider, as `/api/v1` returns it.
///
/// Carries the client id, which is public. It carries **no** client secret,
/// because there is no read path that decrypts one — `federation::Provider`
/// has no field for it either, so a secret cannot reach here by accident.
#[derive(Debug, Serialize, ToSchema)]
pub struct IdentityProviderView {
    /// Stable identifier.
    pub id: Uuid,
    /// URL-safe handle, appearing in the callback path.
    pub alias: String,
    /// Which claim mapping is used: `google`, `github`, `microsoft`,
    /// `facebook`, `apple`, or `oidc`.
    pub kind: String,
    /// What the login page calls it.
    pub display_name: String,
    /// The OAuth client id registered with the provider.
    pub client_id: String,
    /// Where the browser is sent.
    pub authorization_endpoint: String,
    /// Where the code is redeemed.
    pub token_endpoint: String,
    /// Where the claims are read, if not from the ID token.
    pub userinfo_endpoint: Option<String>,
    /// The expected `iss`.
    pub issuer: Option<String>,
    /// What is asked for.
    pub scopes: Vec<String>,
    /// Whether it is offered on the login page.
    pub enabled: bool,
    /// Whether an unrecognised upstream account may create a local one.
    pub allow_provisioning: bool,
    /// Whether a verified upstream address may adopt an existing local
    /// account. Off unless deliberately turned on; see `ROADMAP.md`.
    pub link_by_verified_email: bool,
}

impl From<authenc_identity::federation::Provider> for IdentityProviderView {
    fn from(provider: authenc_identity::federation::Provider) -> Self {
        Self {
            id: provider.id.0,
            alias: provider.alias,
            kind: provider.kind.as_str().to_owned(),
            display_name: provider.display_name,
            client_id: provider.client_id,
            authorization_endpoint: provider.authorization_endpoint,
            token_endpoint: provider.token_endpoint,
            userinfo_endpoint: provider.userinfo_endpoint,
            issuer: provider.issuer,
            scopes: provider.scopes,
            enabled: provider.enabled,
            allow_provisioning: provider.allow_provisioning,
            link_by_verified_email: provider.link_by_verified_email,
        }
    }
}

/// Body for configuring a social-login provider.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateIdentityProvider {
    /// URL-safe handle: lowercase letters, digits, and hyphens.
    pub alias: String,
    /// `google`, `github`, `microsoft`, `facebook`, `apple`, or `oidc`.
    ///
    /// A string rather than a typed enum for the same reason
    /// `SetRolePermissions` takes names: `authenc-contract` stays free of
    /// `utoipa`, and an unrecognised value should be a 400 that says which.
    pub kind: String,
    /// What the login page calls it.
    pub display_name: String,
    /// The OAuth client id registered with the provider.
    pub client_id: String,
    /// The OAuth client secret. Sealed at rest and never returned.
    pub client_secret: String,
    /// Where to send the browser.
    pub authorization_endpoint: String,
    /// Where to redeem the code.
    pub token_endpoint: String,
    /// Where to read the claims, for a provider that does not use an ID token.
    pub userinfo_endpoint: Option<String>,
    /// The expected `iss`, for a provider that issues one.
    pub issuer: Option<String>,
    /// What to ask for.
    pub scopes: Vec<String>,
    /// Whether an unrecognised upstream account may create a local one.
    #[serde(default = "yes")]
    pub allow_provisioning: bool,
    /// Whether a *verified* upstream address may adopt an existing local
    /// account.
    ///
    /// Defaults to **false**, and the default is the safe half of this
    /// feature: turned on for a provider that will assert an address it has
    /// not checked, it hands over whichever local account matches.
    #[serde(default)]
    pub link_by_verified_email: bool,
}

/// An upstream account attached to a user.
#[derive(Debug, Serialize, ToSchema)]
pub struct IdentityLinkView {
    /// The provider it belongs to.
    pub provider_id: Uuid,
    /// Its alias.
    pub provider_alias: String,
    /// What the login page calls it.
    pub provider_display_name: String,
    /// The address the upstream reported when the link was made.
    pub upstream_email: Option<String>,
    /// When it was linked, RFC 3339.
    pub linked_at: String,
    /// When it was last used to sign in, RFC 3339.
    pub last_login_at: Option<String>,
}

/// Filters for the audit trail.
///
/// `action_prefix` is a namespace such as `mfa.`, not free text. The stored
/// action names are namespaced precisely so a category can be selected without
/// enumerating it; accepting arbitrary text here would turn a bounded filter
/// into a `LIKE` over user input.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct AuditQuery {
    /// Exact action name, e.g. `login.failed`.
    pub action: Option<String>,
    /// Namespace to select, e.g. `mfa.`.
    pub action_prefix: Option<String>,
    /// `success` or `failure`.
    pub outcome: Option<String>,
    /// Only what this user did.
    pub actor_id: Option<Uuid>,
    /// Only events at or after this RFC 3339 moment.
    pub since: Option<String>,
    /// Only events before this RFC 3339 moment.
    pub until: Option<String>,
    /// Maximum rows. Clamped server-side to 500.
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Rows to skip.
    #[serde(default)]
    pub offset: i64,
}

/// One recorded event, as `/api/v1` returns it.
///
/// A DTO rather than `contract::AuditEvent` directly, for the same reason
/// `ClientView` exists: what a public response contains becomes a
/// compatibility obligation, and the internal type is free to change.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEventView {
    /// Stable identifier.
    pub id: Uuid,
    /// Stored action name, e.g. `login.failed`.
    pub action: String,
    /// `success` or `failure`.
    pub outcome: String,
    /// Whether this action is, on its own, evidence of an attack.
    ///
    /// Included so a consumer does not have to re-derive the rule and get a
    /// different answer from the console's.
    pub security_signal: bool,
    /// Who did it, if a known user did.
    pub actor_id: Option<Uuid>,
    /// Their name at the time.
    pub actor_name: Option<String>,
    /// What kind of thing it was done to.
    pub target_type: Option<String>,
    /// Which one.
    pub target: Option<String>,
    /// Where the request came from.
    pub ip_address: Option<String>,
    /// What client made it.
    pub user_agent: Option<String>,
    /// When, RFC 3339.
    pub occurred_at: String,
}

impl From<authenc_contract::AuditEvent> for AuditEventView {
    fn from(event: authenc_contract::AuditEvent) -> Self {
        Self {
            id: event.id,
            action: event.action.as_str().to_owned(),
            outcome: event.outcome.as_str().to_owned(),
            security_signal: event.action.is_security_signal(),
            actor_id: event.actor_id.map(|id| id.0),
            actor_name: event.actor_name,
            target_type: event.target_type,
            target: event.target,
            ip_address: event.ip_address,
            user_agent: event.user_agent,
            occurred_at: event.occurred_at,
        }
    }
}

/// Body for creating a user.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateUser {
    /// Login name, unique within the realm.
    pub username: String,
    /// Email address, unique within the realm.
    pub email: String,
    /// Initial password. Validated against policy before hashing.
    pub password: String,
    /// Given name, if known.
    pub first_name: Option<String>,
    /// Family name, if known.
    pub last_name: Option<String>,
}

/// Body for enabling or disabling a user.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SetEnabled {
    /// Whether the user may authenticate.
    pub enabled: bool,
}

/// Body for registering an OAuth client.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RegisterClient {
    /// The `client_id` the client will present.
    pub client_id: String,
    /// Display name, shown on the consent screen.
    pub name: String,
    /// Whether it is a public client: no secret, PKCE required.
    #[serde(default)]
    pub public: bool,
    /// Exact redirect URIs. At least one is required; prefixes do not match.
    pub redirect_uris: Vec<String>,
    /// Scopes it may request. Defaults to `openid profile email` when empty.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Whether the user is asked before the first issuance.
    #[serde(default = "yes")]
    pub require_consent: bool,
}

const fn yes() -> bool {
    true
}

/// Body for changing a registered client.
///
/// An omitted field is left alone. A present one **replaces** — withdrawing a
/// redirect URI is the operation an incident needs, and a merge could not do it.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateClient {
    /// New exact redirect URIs.
    pub redirect_uris: Option<Vec<String>>,
    /// New scope allow-list.
    pub scopes: Option<Vec<String>>,
    /// Whether to ask the user before issuing.
    pub require_consent: Option<bool>,
}

/// A registered client, as this API reports it.
///
/// Deliberately not `authenc_oauth::Client`: that type carries the row's
/// database id and its realm id, and neither is anything a caller needs. An
/// internal identifier in a public response is a detail that becomes a
/// compatibility obligation the moment someone stores it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientView {
    /// The `client_id` the client presents.
    pub client_id: String,
    /// Display name, shown on the consent screen.
    pub name: String,
    /// Whether it is a public client: no secret, PKCE required.
    pub is_public: bool,
    /// Exact redirect URIs. Prefixes do not match.
    pub redirect_uris: Vec<String>,
    /// Grant types it may use.
    pub grant_types: Vec<String>,
    /// Scopes it may request.
    pub scopes: Vec<String>,
    /// Whether the user is asked before issuance.
    pub require_consent: bool,
}

impl From<authenc_oauth::Client> for ClientView {
    fn from(client: authenc_oauth::Client) -> Self {
        Self {
            client_id: client.client_id,
            name: client.name,
            is_public: client.is_public,
            redirect_uris: client.redirect_uris,
            grant_types: client.grant_types,
            scopes: client.scopes,
            require_consent: client.require_consent,
        }
    }
}

/// A registered client plus the one sight of its secret.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientCredentials {
    /// The stored record.
    pub client: ClientView,
    /// The generated secret, absent for a public client. Returned **once**;
    /// only its Argon2 hash is stored, so it cannot be read again.
    pub client_secret: Option<String>,
}

/// Body for creating a role.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateRole {
    /// Machine name, unique within the realm.
    pub name: String,
    /// What the role is for.
    pub description: Option<String>,
}

/// The CSRF token for the caller's session.
#[derive(Debug, Serialize, ToSchema)]
pub struct Csrf {
    /// Send this back in the `X-CSRF-Token` header on unsafe methods.
    pub token: String,
}

/// Who the caller is, and what they may do.
#[derive(Debug, Serialize, ToSchema)]
pub struct Whoami {
    /// The caller's username.
    pub username: String,
    /// Roles they hold.
    pub roles: Vec<String>,
    /// Permissions those roles carry.
    pub permissions: Vec<String>,
}

/// The OpenAPI document for `/api/v1`.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Authenc Admin API",
        description = "Administrative API for scripts and automation. \
                       The browser console uses Leptos server functions instead; \
                       both sit on the same use cases.",
        license(name = "Apache-2.0"),
    ),
    paths(
        csrf,
        whoami,
        list_permissions,
        get_realm,
        list_users,
        create_user,
        set_user_enabled,
        delete_user,
        list_roles,
        create_role,
        set_role_permissions,
        grant_role,
        revoke_role,
        list_clients,
        register_client,
        get_client,
        update_client,
        delete_client,
        rotate_client_secret,
        list_audit,
        export_audit,
        list_organizations,
        create_organization,
        get_organization,
        delete_organization,
        set_organization_enabled,
        list_organization_members,
        set_organization_member,
        remove_organization_member,
        list_organization_invitations,
        invite_to_organization,
        revoke_organization_invitation,
        list_identity_providers,
        create_identity_provider,
        get_identity_provider,
        set_identity_provider_enabled,
        delete_identity_provider,
        list_identity_links,
        unlink_identity,
        list_groups,
        create_group,
        get_group,
        delete_group,
        move_group,
        list_group_members,
        add_group_member,
        remove_group_member,
        list_group_roles,
        grant_group_role,
        revoke_group_role,
    ),
    components(schemas(
        CreateOrganization,
        SetOrganizationMember,
        InviteToOrganization,
        OrganizationView,
        OrganizationMemberView,
        InvitationView,
        CreateIdentityProvider,
        IdentityProviderView,
        IdentityLinkView,
        CreateGroup,
        MoveGroup,
        GroupView,
        CreateUser,
        SetEnabled,
        SetRolePermissions,
        CreateRole,
        Whoami,
        Csrf,
        RegisterClient,
        UpdateClient,
        ClientView,
        ClientCredentials,
    )),
    tags(
        (name = "identity", description = "Realms, users, and roles"),
        (name = "oauth", description = "Registered OAuth 2.0 clients"),
        (name = "meta", description = "Information about the caller and the server"),
    ),
)]
pub struct ApiDoc;

/// Build the `/api/v1` router.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/csrf", get(csrf))
        .route("/whoami", get(whoami))
        .route("/permissions", get(list_permissions))
        .route("/realm", get(get_realm))
        .route("/users", get(list_users).post(create_user))
        .route("/users/{user_id}", delete(delete_user))
        .route("/users/{user_id}/enabled", post(set_user_enabled))
        .route("/roles", get(list_roles).post(create_role))
        .route("/roles/{role_id}/permissions", put(set_role_permissions))
        .route("/roles/{role_id}/users/{user_id}", post(grant_role))
        .route("/roles/{role_id}/users/{user_id}", delete(revoke_role))
        .route("/clients", get(list_clients).post(register_client))
        .route(
            "/clients/{client_id}",
            get(get_client).patch(update_client).delete(delete_client),
        )
        .route("/clients/{client_id}/secret", post(rotate_client_secret))
        .route(
            "/identity-providers",
            get(list_identity_providers).post(create_identity_provider),
        )
        .route(
            "/identity-providers/{provider_id}",
            get(get_identity_provider).delete(delete_identity_provider),
        )
        .route(
            "/identity-providers/{provider_id}/enabled",
            post(set_identity_provider_enabled),
        )
        .route("/users/{user_id}/identities", get(list_identity_links))
        .route(
            "/users/{user_id}/identities/{provider_id}",
            delete(unlink_identity),
        )
        .route("/groups", get(list_groups).post(create_group))
        .route("/groups/{group_id}", get(get_group).delete(delete_group))
        .route("/groups/{group_id}/parent", post(move_group))
        .route("/groups/{group_id}/members", get(list_group_members))
        .route(
            "/groups/{group_id}/members/{user_id}",
            post(add_group_member).delete(remove_group_member),
        )
        .route("/groups/{group_id}/roles", get(list_group_roles))
        .route(
            "/groups/{group_id}/roles/{role_id}",
            post(grant_group_role).delete(revoke_group_role),
        )
        .route(
            "/organizations",
            get(list_organizations).post(create_organization),
        )
        .route(
            "/organizations/{organization_id}",
            get(get_organization).delete(delete_organization),
        )
        .route(
            "/organizations/{organization_id}/enabled",
            post(set_organization_enabled),
        )
        .route(
            "/organizations/{organization_id}/members",
            get(list_organization_members),
        )
        .route(
            "/organizations/{organization_id}/members/{user_id}",
            put(set_organization_member).delete(remove_organization_member),
        )
        .route(
            "/organizations/{organization_id}/invitations",
            get(list_organization_invitations).post(invite_to_organization),
        )
        .route(
            "/organizations/{organization_id}/invitations/{invitation_id}",
            delete(revoke_organization_invitation),
        )
        .route("/audit", get(list_audit))
        .route("/audit.csv", get(export_audit))
        .route("/openapi.json", get(openapi))
}

/// Serve the OpenAPI document.
///
/// Deliberately unauthenticated: the schema describes the shape of the API,
/// not its contents, and a client needs it before it has credentials.
async fn openapi() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

/// Fetch the CSRF token for the current session.
///
/// Every unsafe method on this API requires it in `X-CSRF-Token`, because the
/// API is authenticated by the same cookie the browser console uses, and a
/// cookie is sent by the browser whether or not the page meant to send it.
///
/// This is a `GET`, so it needs no token itself, and it needs a session, so an
/// attacker cannot fetch a victim's token from their own origin.
///
/// Machine-to-machine clients should eventually use an API token instead of a
/// session — see ROADMAP.md. Until then, sign in, read this, and echo it back.
#[utoipa::path(
    get, path = "/api/v1/csrf", tag = "meta",
    responses((status = 200, body = Csrf), (status = 401, description = "Not signed in")),
)]
async fn csrf(session: crate::auth::CurrentSession) -> Json<Csrf> {
    Json(Csrf {
        token: session.0.csrf_token(),
    })
}

/// Who the caller is.
#[utoipa::path(
    get, path = "/api/v1/whoami", tag = "meta",
    responses((status = 200, body = Whoami), (status = 401, description = "Not signed in")),
)]
async fn whoami(CurrentUser(actor): CurrentUser) -> Json<Whoami> {
    Json(Whoami {
        username: actor.username,
        roles: actor.roles,
        permissions: actor
            .permissions
            .iter()
            .map(|p| p.as_str().to_owned())
            .collect(),
    })
}

/// Every permission this system understands.
#[utoipa::path(
    get, path = "/api/v1/permissions", tag = "meta",
    responses((status = 200, description = "Name and description of each permission")),
)]
async fn list_permissions(CurrentUser(_actor): CurrentUser) -> Json<Vec<Permission>> {
    Json(Permission::ALL.to_vec())
}

/// The caller's own realm.
#[utoipa::path(
    get, path = "/api/v1/realm", tag = "identity",
    responses((status = 200), (status = 403, description = "Missing realm:read")),
)]
async fn get_realm(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
) -> Result<Json<Realm>, ApiError> {
    Ok(Json(
        authenc_identity::admin::own_realm(&state.db, &actor).await?,
    ))
}

/// List users in the caller's realm.
#[utoipa::path(
    get, path = "/api/v1/users", tag = "identity",
    params(Paging),
    responses((status = 200), (status = 403, description = "Missing user:read")),
)]
async fn list_users(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Query(paging): Query<Paging>,
) -> Result<Json<Page<User>>, ApiError> {
    let items = authenc_identity::admin::list_users(
        &state.db,
        &actor,
        actor.realm_id,
        paging.limit,
        paging.offset,
    )
    .await?;
    let total = authenc_identity::admin::count_users(&state.db, &actor, actor.realm_id).await?;

    Ok(Json(Page { items, total }))
}

/// Create a user in the caller's realm.
#[utoipa::path(
    post, path = "/api/v1/users", tag = "identity",
    request_body = CreateUser,
    responses(
        (status = 201), (status = 400, description = "Validation failed"),
        (status = 403, description = "Missing user:write"),
        (status = 409, description = "Username or email taken"),
    ),
)]
async fn create_user(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Json(body): Json<CreateUser>,
) -> Result<(StatusCode, Json<User>), ApiError> {
    let user = authenc_identity::admin::create_user(
        &state.db,
        &actor,
        &state.hasher,
        authenc_identity::user::NewUser {
            realm_id: actor.realm_id,
            username: &body.username,
            email: &body.email,
            password: &body.password,
            first_name: body.first_name.as_deref(),
            last_name: body.last_name.as_deref(),
        },
    )
    .await?;

    Ok((StatusCode::CREATED, Json(user)))
}

/// Enable or disable a user.
#[utoipa::path(
    post, path = "/api/v1/users/{user_id}/enabled", tag = "identity",
    request_body = SetEnabled,
    responses(
        (status = 200), (status = 400, description = "Cannot disable your own account"),
        (status = 403, description = "Missing user:write"), (status = 404),
    ),
)]
async fn set_user_enabled(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(user_id): Path<Uuid>,
    Json(body): Json<SetEnabled>,
) -> Result<Json<User>, ApiError> {
    Ok(Json(
        authenc_identity::admin::set_user_enabled(&state.db, &actor, UserId(user_id), body.enabled)
            .await?,
    ))
}

/// Delete a user.
#[utoipa::path(
    delete, path = "/api/v1/users/{user_id}", tag = "identity",
    responses(
        (status = 204), (status = 400, description = "Cannot delete your own account"),
        (status = 403, description = "Missing user:write"), (status = 404),
    ),
)]
async fn delete_user(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    authenc_identity::admin::delete_user(&state.db, &actor, UserId(user_id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// List roles in the caller's realm.
#[utoipa::path(
    get, path = "/api/v1/roles", tag = "identity",
    responses((status = 200), (status = 403, description = "Missing role:read")),
)]
async fn list_roles(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
) -> Result<Json<Vec<Role>>, ApiError> {
    Ok(Json(
        authenc_identity::admin::list_roles(&state.db, &actor, actor.realm_id).await?,
    ))
}

/// Create a role.
#[utoipa::path(
    post, path = "/api/v1/roles", tag = "identity",
    request_body = CreateRole,
    responses((status = 201), (status = 403, description = "Missing role:write")),
)]
async fn create_role(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Json(body): Json<CreateRole>,
) -> Result<(StatusCode, Json<Role>), ApiError> {
    let role = authenc_identity::admin::create_role(
        &state.db,
        &actor,
        actor.realm_id,
        &body.name,
        body.description.as_deref(),
    )
    .await?;

    Ok((StatusCode::CREATED, Json(role)))
}

/// Replace a role's permissions.
///
/// The whole set, not a delta. `PUT` rather than `PATCH` for that reason: the
/// body is what the role will hold, and nothing about the previous state
/// survives.
#[utoipa::path(
    put, path = "/api/v1/roles/{role_id}/permissions", tag = "rbac",
    request_body = SetRolePermissions,
    responses(
        (status = 204),
        (status = 400, description = "An unknown permission name"),
        (status = 403, description = "Missing role:write"),
        (status = 404),
    ),
)]
async fn set_role_permissions(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(role_id): Path<Uuid>,
    Json(body): Json<SetRolePermissions>,
) -> Result<StatusCode, ApiError> {
    let mut permissions = Vec::with_capacity(body.permissions.len());
    for name in &body.permissions {
        permissions.push(name.parse::<Permission>().map_err(|_| {
            ApiError::from(authenc_contract::AppError::field(
                "permissions",
                format!("`{name}` is not a permission this system grants"),
            ))
        })?);
    }

    authenc_identity::admin::set_role_permissions(&state.db, &actor, RoleId(role_id), &permissions)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Grant a role to a user.
#[utoipa::path(
    post, path = "/api/v1/roles/{role_id}/users/{user_id}", tag = "identity",
    responses((status = 204), (status = 403, description = "Missing role:write"), (status = 404)),
)]
async fn grant_role(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((role_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    authenc_identity::admin::grant_role(&state.db, &actor, UserId(user_id), RoleId(role_id))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Revoke a role from a user.
#[utoipa::path(
    delete, path = "/api/v1/roles/{role_id}/users/{user_id}", tag = "identity",
    responses((status = 204), (status = 403, description = "Missing role:write"), (status = 404)),
)]
async fn revoke_role(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((role_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    authenc_identity::admin::revoke_role(&state.db, &actor, UserId(user_id), RoleId(role_id))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Organisations
// ---------------------------------------------------------------------------

/// Parse an organisation role name, refusing anything else.
fn member_role(value: &str) -> Result<authenc_identity::organization::MemberRole, ApiError> {
    Ok(authenc_identity::organization::MemberRole::parse(value)?)
}

/// Every organisation in the caller's realm.
#[utoipa::path(
    get, path = "/api/v1/organizations", tag = "organizations",
    responses((status = 200), (status = 403, description = "Missing organization:read")),
)]
async fn list_organizations(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
) -> Result<Json<Vec<OrganizationView>>, ApiError> {
    let organizations = authenc_identity::admin::list_organizations(&state.db, &actor).await?;
    Ok(Json(
        organizations
            .into_iter()
            .map(OrganizationView::from)
            .collect(),
    ))
}

/// Create an organisation.
#[utoipa::path(
    post, path = "/api/v1/organizations", tag = "organizations",
    request_body = CreateOrganization,
    responses(
        (status = 201),
        (status = 400, description = "A slug that is not URL-safe"),
        (status = 403, description = "Missing organization:write"),
        (status = 409, description = "The slug is taken"),
    ),
)]
async fn create_organization(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Json(body): Json<CreateOrganization>,
) -> Result<(StatusCode, Json<OrganizationView>), ApiError> {
    let created =
        authenc_identity::admin::create_organization(&state.db, &actor, &body.slug, &body.name)
            .await?;
    Ok((StatusCode::CREATED, Json(OrganizationView::from(created))))
}

/// Fetch one organisation.
#[utoipa::path(
    get, path = "/api/v1/organizations/{organization_id}", tag = "organizations",
    responses((status = 200), (status = 403), (status = 404)),
)]
async fn get_organization(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<OrganizationView>, ApiError> {
    let found = authenc_identity::admin::get_organization(
        &state.db,
        &actor,
        OrganizationId(organization_id),
    )
    .await?;
    Ok(Json(OrganizationView::from(found)))
}

/// Suspend or restore an organisation.
///
/// Suspending stops every member signing in — unless they also belong to
/// another organisation that is still enabled.
#[utoipa::path(
    post, path = "/api/v1/organizations/{organization_id}/enabled", tag = "organizations",
    request_body = SetEnabled,
    responses((status = 200), (status = 403), (status = 404)),
)]
async fn set_organization_enabled(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(organization_id): Path<Uuid>,
    Json(body): Json<SetEnabled>,
) -> Result<Json<OrganizationView>, ApiError> {
    let changed = authenc_identity::admin::set_organization_enabled(
        &state.db,
        &actor,
        OrganizationId(organization_id),
        body.enabled,
    )
    .await?;
    Ok(Json(OrganizationView::from(changed)))
}

/// Delete an organisation. Its members remain as users.
#[utoipa::path(
    delete, path = "/api/v1/organizations/{organization_id}", tag = "organizations",
    responses((status = 204), (status = 403), (status = 404)),
)]
async fn delete_organization(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(organization_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    authenc_identity::admin::delete_organization(
        &state.db,
        &actor,
        OrganizationId(organization_id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Everyone in an organisation, with their role.
#[utoipa::path(
    get, path = "/api/v1/organizations/{organization_id}/members", tag = "organizations",
    responses((status = 200), (status = 403), (status = 404)),
)]
async fn list_organization_members(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<OrganizationMemberView>>, ApiError> {
    let members = authenc_identity::admin::organization_members(
        &state.db,
        &actor,
        OrganizationId(organization_id),
    )
    .await?;
    Ok(Json(
        members
            .into_iter()
            .map(|(user, role)| OrganizationMemberView {
                id: user.id.0,
                username: user.username,
                email: user.email,
                role: role.as_str().to_owned(),
            })
            .collect(),
    ))
}

/// Add someone, or change the role they hold.
#[utoipa::path(
    put, path = "/api/v1/organizations/{organization_id}/members/{user_id}",
    tag = "organizations", request_body = SetOrganizationMember,
    responses(
        (status = 204),
        (status = 400, description = "An unknown role"),
        (status = 403), (status = 404),
    ),
)]
async fn set_organization_member(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((organization_id, user_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<SetOrganizationMember>,
) -> Result<StatusCode, ApiError> {
    authenc_identity::admin::set_organization_member(
        &state.db,
        &actor,
        OrganizationId(organization_id),
        UserId(user_id),
        member_role(&body.role)?,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Remove someone from an organisation.
///
/// Refused if they are the last owner: an organisation nobody can administer
/// needs a database console to fix.
#[utoipa::path(
    delete, path = "/api/v1/organizations/{organization_id}/members/{user_id}",
    tag = "organizations",
    responses(
        (status = 204),
        (status = 400, description = "They are the last owner"),
        (status = 403), (status = 404),
    ),
)]
async fn remove_organization_member(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((organization_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    authenc_identity::admin::remove_organization_member(
        &state.db,
        &actor,
        OrganizationId(organization_id),
        UserId(user_id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Invitations for an organisation.
#[utoipa::path(
    get, path = "/api/v1/organizations/{organization_id}/invitations", tag = "organizations",
    responses((status = 200), (status = 403), (status = 404)),
)]
async fn list_organization_invitations(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<Vec<InvitationView>>, ApiError> {
    use time::format_description::well_known::Rfc3339;

    let invitations = authenc_identity::admin::organization_invitations(
        &state.db,
        &actor,
        OrganizationId(organization_id),
    )
    .await?;

    Ok(Json(
        invitations
            .into_iter()
            .map(|invitation| InvitationView {
                id: invitation.id.0,
                email: invitation.email,
                role: invitation.role.as_str().to_owned(),
                accepted: invitation.accepted,
                expires_at: invitation
                    .expires_at
                    .format(&Rfc3339)
                    .unwrap_or_else(|_| String::new()),
            })
            .collect(),
    ))
}

/// Invite an address to an organisation.
///
/// The response carries the token **once**. It is not stored in a form anyone
/// can read back, so a caller that discards it must issue a fresh invitation.
#[utoipa::path(
    post, path = "/api/v1/organizations/{organization_id}/invitations", tag = "organizations",
    request_body = InviteToOrganization,
    responses(
        (status = 201, description = "The invitation, with its token"),
        (status = 400, description = "A malformed address or an unknown role"),
        (status = 403), (status = 404),
    ),
)]
async fn invite_to_organization(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(organization_id): Path<Uuid>,
    Json(body): Json<InviteToOrganization>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let invited = authenc_identity::admin::invite_to_organization(
        &state.db,
        &actor,
        OrganizationId(organization_id),
        &body.email,
        member_role(&body.role)?,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "id": invited.invitation.id.0,
            "email": invited.invitation.email,
            "role": invited.invitation.role.as_str(),
            "token": invited.token.expose(),
        })),
    ))
}

/// Withdraw an invitation that has not been accepted.
#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{organization_id}/invitations/{invitation_id}",
    tag = "organizations",
    responses((status = 204), (status = 403), (status = 404)),
)]
async fn revoke_organization_invitation(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((organization_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    authenc_identity::admin::revoke_organization_invitation(
        &state.db,
        &actor,
        OrganizationId(organization_id),
        InvitationId(invitation_id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Social-login providers
// ---------------------------------------------------------------------------

/// Every social-login provider configured in the realm.
#[utoipa::path(
    get, path = "/api/v1/identity-providers", tag = "federation",
    responses(
        (status = 200),
        (status = 403, description = "Missing identity_provider:read"),
    ),
)]
async fn list_identity_providers(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
) -> Result<Json<Vec<IdentityProviderView>>, ApiError> {
    let providers = authenc_identity::admin::list_identity_providers(&state.db, &actor).await?;
    Ok(Json(
        providers
            .into_iter()
            .map(IdentityProviderView::from)
            .collect(),
    ))
}

/// Configure a social-login provider.
///
/// The client secret is sealed at rest and never returned by any endpoint.
#[utoipa::path(
    post, path = "/api/v1/identity-providers", tag = "federation",
    request_body = CreateIdentityProvider,
    responses(
        (status = 201),
        (status = 400, description = "An unknown kind, or a malformed alias"),
        (status = 403, description = "Missing identity_provider:write"),
        (status = 409, description = "That alias is taken in this realm"),
    ),
)]
async fn create_identity_provider(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Json(body): Json<CreateIdentityProvider>,
) -> Result<(StatusCode, Json<IdentityProviderView>), ApiError> {
    let kind = authenc_identity::federation::Kind::parse(&body.kind).map_err(ApiError)?;

    let created = authenc_identity::admin::create_identity_provider(
        &state.db,
        &actor,
        &state.master_key,
        authenc_identity::admin::NewIdentityProvider {
            alias: &body.alias,
            kind,
            display_name: &body.display_name,
            client_id: &body.client_id,
            client_secret: &body.client_secret,
            authorization_endpoint: &body.authorization_endpoint,
            token_endpoint: &body.token_endpoint,
            userinfo_endpoint: body.userinfo_endpoint.as_deref(),
            issuer: body.issuer.as_deref(),
            scopes: &body.scopes,
            allow_provisioning: body.allow_provisioning,
            link_by_verified_email: body.link_by_verified_email,
        },
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(IdentityProviderView::from(created)),
    ))
}

/// Fetch one provider.
#[utoipa::path(
    get, path = "/api/v1/identity-providers/{provider_id}", tag = "federation",
    responses((status = 200), (status = 403), (status = 404)),
)]
async fn get_identity_provider(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(provider_id): Path<Uuid>,
) -> Result<Json<IdentityProviderView>, ApiError> {
    let found = authenc_identity::admin::get_identity_provider(
        &state.db,
        &actor,
        IdentityProviderId(provider_id),
    )
    .await?;
    Ok(Json(IdentityProviderView::from(found)))
}

/// Offer a provider on the login page, or stop offering it.
#[utoipa::path(
    post, path = "/api/v1/identity-providers/{provider_id}/enabled", tag = "federation",
    request_body = SetEnabled,
    responses((status = 200), (status = 403), (status = 404)),
)]
async fn set_identity_provider_enabled(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(provider_id): Path<Uuid>,
    Json(body): Json<SetEnabled>,
) -> Result<Json<IdentityProviderView>, ApiError> {
    let changed = authenc_identity::admin::set_identity_provider_enabled(
        &state.db,
        &actor,
        IdentityProviderId(provider_id),
        body.enabled,
    )
    .await?;
    Ok(Json(IdentityProviderView::from(changed)))
}

/// Delete a provider **and every account link through it**.
///
/// Anyone whose only credential was this provider is left unable to sign in.
/// The audit record says how many links went with it.
#[utoipa::path(
    delete, path = "/api/v1/identity-providers/{provider_id}", tag = "federation",
    responses((status = 204), (status = 403), (status = 404)),
)]
async fn delete_identity_provider(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(provider_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    authenc_identity::admin::delete_identity_provider(
        &state.db,
        &actor,
        IdentityProviderId(provider_id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The upstream accounts attached to a user.
#[utoipa::path(
    get, path = "/api/v1/users/{user_id}/identities", tag = "federation",
    responses(
        (status = 200),
        (status = 403, description = "Missing user:read"),
        (status = 404),
    ),
)]
async fn list_identity_links(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<IdentityLinkView>>, ApiError> {
    use time::format_description::well_known::Rfc3339;

    let links = authenc_identity::admin::identity_links(&state.db, &actor, UserId(user_id)).await?;

    Ok(Json(
        links
            .into_iter()
            .map(|link| IdentityLinkView {
                provider_id: link.provider_id.0,
                provider_alias: link.provider_alias,
                provider_display_name: link.provider_display_name,
                upstream_email: link.upstream_email,
                linked_at: link
                    .linked_at
                    .format(&Rfc3339)
                    .unwrap_or_else(|_| String::new()),
                last_login_at: link.last_login_at.and_then(|at| at.format(&Rfc3339).ok()),
            })
            .collect(),
    ))
}

/// Detach an upstream account from a user.
///
/// Refused if it is that account's only way in: an account with no password
/// and no other link is one whose owner needs an administrator to recover, and
/// the moment to say so is before it happens.
#[utoipa::path(
    delete, path = "/api/v1/users/{user_id}/identities/{provider_id}", tag = "federation",
    responses(
        (status = 204),
        (status = 400, description = "It is the account's only credential"),
        (status = 403, description = "Missing user:write"),
        (status = 404),
    ),
)]
async fn unlink_identity(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((user_id, provider_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    authenc_identity::admin::unlink_identity(
        &state.db,
        &actor,
        IdentityProviderId(provider_id),
        UserId(user_id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

/// The realm's group tree, ordered by path.
#[utoipa::path(
    get, path = "/api/v1/groups", tag = "groups",
    responses((status = 200), (status = 403, description = "Missing group:read")),
)]
async fn list_groups(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
) -> Result<Json<Vec<GroupView>>, ApiError> {
    let groups = authenc_identity::admin::list_groups(&state.db, &actor, actor.realm_id).await?;
    Ok(Json(groups.into_iter().map(GroupView::from).collect()))
}

/// Create a group in the caller's realm.
#[utoipa::path(
    post, path = "/api/v1/groups", tag = "groups", request_body = CreateGroup,
    responses(
        (status = 201),
        (status = 400, description = "Blank name, or a move that would cycle"),
        (status = 403, description = "Missing group:write"),
        (status = 409, description = "A sibling already has that name"),
    ),
)]
async fn create_group(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Json(body): Json<CreateGroup>,
) -> Result<(StatusCode, Json<GroupView>), ApiError> {
    let created = authenc_identity::admin::create_group(
        &state.db,
        &actor,
        body.parent_id.map(GroupId),
        &body.name,
        body.description.as_deref(),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(GroupView::from(created))))
}

/// Fetch one group.
#[utoipa::path(
    get, path = "/api/v1/groups/{group_id}", tag = "groups",
    responses((status = 200), (status = 403), (status = 404)),
)]
async fn get_group(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GroupView>, ApiError> {
    let found = authenc_identity::admin::get_group(&state.db, &actor, GroupId(group_id)).await?;
    Ok(Json(GroupView::from(found)))
}

/// Delete a group **and its whole subtree**.
#[utoipa::path(
    delete, path = "/api/v1/groups/{group_id}", tag = "groups",
    responses((status = 204), (status = 403), (status = 404)),
)]
async fn delete_group(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(group_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    authenc_identity::admin::delete_group(&state.db, &actor, GroupId(group_id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Move a group under a different parent, or to the root.
#[utoipa::path(
    post, path = "/api/v1/groups/{group_id}/parent", tag = "groups",
    request_body = MoveGroup,
    responses(
        (status = 200),
        (status = 400, description = "The move would create a cycle"),
        (status = 403), (status = 404),
    ),
)]
async fn move_group(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(group_id): Path<Uuid>,
    Json(body): Json<MoveGroup>,
) -> Result<Json<GroupView>, ApiError> {
    let moved = authenc_identity::admin::move_group(
        &state.db,
        &actor,
        GroupId(group_id),
        body.parent_id.map(GroupId),
    )
    .await?;
    Ok(Json(GroupView::from(moved)))
}

/// Who is directly in a group.
#[utoipa::path(
    get, path = "/api/v1/groups/{group_id}/members", tag = "groups",
    responses((status = 200), (status = 403), (status = 404)),
)]
async fn list_group_members(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(group_id): Path<Uuid>,
) -> Result<Json<Vec<User>>, ApiError> {
    let users =
        authenc_identity::admin::group_members(&state.db, &actor, GroupId(group_id)).await?;
    Ok(Json(users))
}

/// Put a user in a group.
#[utoipa::path(
    post, path = "/api/v1/groups/{group_id}/members/{user_id}", tag = "groups",
    responses((status = 204), (status = 403), (status = 404)),
)]
async fn add_group_member(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    authenc_identity::admin::add_group_member(
        &state.db,
        &actor,
        GroupId(group_id),
        UserId(user_id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Take a user out of a group.
#[utoipa::path(
    delete, path = "/api/v1/groups/{group_id}/members/{user_id}", tag = "groups",
    responses((status = 204), (status = 403), (status = 404)),
)]
async fn remove_group_member(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    authenc_identity::admin::remove_group_member(
        &state.db,
        &actor,
        GroupId(group_id),
        UserId(user_id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The roles granted directly to a group.
#[utoipa::path(
    get, path = "/api/v1/groups/{group_id}/roles", tag = "groups",
    responses((status = 200), (status = 403), (status = 404)),
)]
async fn list_group_roles(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(group_id): Path<Uuid>,
) -> Result<Json<Vec<Role>>, ApiError> {
    let roles = authenc_identity::admin::group_roles(&state.db, &actor, GroupId(group_id)).await?;
    Ok(Json(roles))
}

/// Grant a role to a group, and so to everyone in it and below it.
#[utoipa::path(
    post, path = "/api/v1/groups/{group_id}/roles/{role_id}", tag = "groups",
    responses(
        (status = 204),
        (status = 403, description = "Missing group:write or role:write"),
        (status = 404),
    ),
)]
async fn grant_group_role(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((group_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    authenc_identity::admin::grant_group_role(
        &state.db,
        &actor,
        GroupId(group_id),
        RoleId(role_id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Take a role away from a group.
#[utoipa::path(
    delete, path = "/api/v1/groups/{group_id}/roles/{role_id}", tag = "groups",
    responses((status = 204), (status = 403), (status = 404)),
)]
async fn revoke_group_role(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((group_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    authenc_identity::admin::revoke_group_role(
        &state.db,
        &actor,
        GroupId(group_id),
        RoleId(role_id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// Turn query parameters into a filter, refusing anything unparseable.
///
/// A bad filter is a 400, not a silently ignored parameter: a caller asking for
/// `outcome=failed` and receiving every event would draw exactly the wrong
/// conclusion from the answer.
fn audit_filter(
    query: &AuditQuery,
) -> Result<
    (
        authenc_identity::audit::Filter<'_>,
        Option<time::OffsetDateTime>,
        Option<time::OffsetDateTime>,
    ),
    ApiError,
> {
    use authenc_contract::{
        AppError,
        event::{Action, Outcome},
    };
    use time::format_description::well_known::Rfc3339;

    let action = query
        .action
        .as_deref()
        .map(|name| {
            name.parse::<Action>()
                .map_err(|_| AppError::field("action", "is not an action this system records"))
        })
        .transpose()?;

    let outcome = query
        .outcome
        .as_deref()
        .map(|value| match value {
            "success" => Ok(Outcome::Success),
            "failure" => Ok(Outcome::Failure),
            _ => Err(AppError::field("outcome", "must be `success` or `failure`")),
        })
        .transpose()?;

    let parse_time = |value: &Option<String>, field: &'static str| {
        value
            .as_deref()
            .map(|raw| {
                time::OffsetDateTime::parse(raw, &Rfc3339)
                    .map_err(|_| AppError::field(field, "must be an RFC 3339 timestamp"))
            })
            .transpose()
    };

    let since = parse_time(&query.since, "since")?;
    let until = parse_time(&query.until, "until")?;

    Ok((
        authenc_identity::audit::Filter {
            action,
            prefix: query.action_prefix.as_deref(),
            outcome,
            actor_id: query.actor_id.map(UserId),
            since,
            until,
        },
        since,
        until,
    ))
}

/// Read the realm's audit trail.
#[utoipa::path(
    get, path = "/api/v1/audit", tag = "audit",
    params(AuditQuery),
    responses(
        (status = 200),
        (status = 400, description = "Unparseable filter"),
        (status = 403, description = "Missing audit:read"),
    ),
)]
async fn list_audit(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Page<AuditEventView>>, ApiError> {
    let (filter, _, _) = audit_filter(&query)?;

    let total =
        authenc_identity::admin::count_audit(&state.db, &actor, actor.realm_id, filter).await?;
    let items = authenc_identity::admin::list_audit(
        &state.db,
        &actor,
        actor.realm_id,
        filter,
        query.limit,
        query.offset,
    )
    .await?;

    Ok(Json(Page {
        items: items.into_iter().map(AuditEventView::from).collect(),
        total,
    }))
}

/// Export the realm's audit trail as CSV.
///
/// One page per request, using the same filters and the same limit as
/// [`list_audit`]. Deliberately **not** a stream of the whole table: an export
/// endpoint that holds a cursor open over an unbounded result set is a way to
/// exhaust the server from a single request, and a caller that wants
/// everything can walk the pages.
#[utoipa::path(
    get, path = "/api/v1/audit.csv", tag = "audit",
    params(AuditQuery),
    responses(
        (status = 200, content_type = "text/csv"),
        (status = 400, description = "Unparseable filter"),
        (status = 403, description = "Missing audit:read"),
    ),
)]
async fn export_audit(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Query(query): Query<AuditQuery>,
) -> Result<axum::response::Response, ApiError> {
    use axum::{
        http::header::{CONTENT_DISPOSITION, CONTENT_TYPE},
        response::IntoResponse,
    };

    let (filter, _, _) = audit_filter(&query)?;
    let events = authenc_identity::admin::list_audit(
        &state.db,
        &actor,
        actor.realm_id,
        filter,
        query.limit,
        query.offset,
    )
    .await?;

    let mut csv = String::from(
        "occurred_at,action,outcome,actor_name,target_type,target,ip_address,user_agent\n",
    );
    for event in events {
        let view = AuditEventView::from(event);
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            csv_field(&view.occurred_at),
            csv_field(&view.action),
            csv_field(&view.outcome),
            csv_field(view.actor_name.as_deref().unwrap_or_default()),
            csv_field(view.target_type.as_deref().unwrap_or_default()),
            csv_field(view.target.as_deref().unwrap_or_default()),
            csv_field(view.ip_address.as_deref().unwrap_or_default()),
            csv_field(view.user_agent.as_deref().unwrap_or_default()),
        ));
    }

    Ok((
        [
            (CONTENT_TYPE, "text/csv; charset=utf-8"),
            (CONTENT_DISPOSITION, "attachment; filename=\"audit.csv\""),
        ],
        csv,
    )
        .into_response())
}

/// Quote one CSV field.
///
/// Always quoted, and a leading `=`, `+`, `-`, or `@` is prefixed with a single
/// quote. Those four characters make a spreadsheet treat the cell as a formula,
/// and an audit log contains attacker-supplied strings — a `user_agent` is
/// whatever the client sent. The export is opened in Excel by definition, so
/// this is the one place that matters.
fn csv_field(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    let guarded = if escaped.starts_with(['=', '+', '-', '@']) {
        format!("'{escaped}")
    } else {
        escaped
    };
    format!("\"{guarded}\"")
}

// ---------------------------------------------------------------------------
// OAuth clients
// ---------------------------------------------------------------------------

/// List the OAuth clients registered in the caller's realm.
#[utoipa::path(
    get, path = "/api/v1/clients", tag = "oauth",
    responses((status = 200), (status = 403, description = "Missing client:read")),
)]
async fn list_clients(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
) -> Result<Json<Vec<ClientView>>, ApiError> {
    let clients = authenc_oauth::admin::list(&state.db, &actor, actor.realm_id).await?;
    Ok(Json(clients.into_iter().map(ClientView::from).collect()))
}

/// Fetch one client.
#[utoipa::path(
    get, path = "/api/v1/clients/{client_id}", tag = "oauth",
    responses((status = 200), (status = 403, description = "Missing client:read"), (status = 404)),
)]
async fn get_client(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(client_id): Path<String>,
) -> Result<Json<ClientView>, ApiError> {
    Ok(Json(
        authenc_oauth::admin::get(&state.db, &actor, &client_id)
            .await?
            .into(),
    ))
}

/// Register a client.
///
/// The response carries the generated secret, and is the only time it exists
/// outside the caller: the database holds its Argon2 hash and nothing else.
#[utoipa::path(
    post, path = "/api/v1/clients", tag = "oauth",
    request_body = RegisterClient,
    responses(
        (status = 201, body = ClientCredentials),
        (status = 400, description = "Metadata the server will not accept"),
        (status = 403, description = "Missing client:write"),
    ),
)]
async fn register_client(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Json(body): Json<RegisterClient>,
) -> Result<(StatusCode, Json<ClientCredentials>), ApiError> {
    let registered = authenc_oauth::admin::register(
        &state.db,
        &actor,
        &state.hasher,
        authenc_oauth::admin::Registration {
            client_id: &body.client_id,
            name: &body.name,
            is_public: body.public,
            redirect_uris: &body.redirect_uris,
            scopes: &body.scopes,
            require_consent: body.require_consent,
        },
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(ClientCredentials {
            client: registered.client.into(),
            client_secret: registered
                .client_secret
                .map(|secret| secret.expose().to_owned()),
        }),
    ))
}

/// Change a client's redirect URIs, scopes, or consent requirement.
#[utoipa::path(
    patch, path = "/api/v1/clients/{client_id}", tag = "oauth",
    request_body = UpdateClient,
    responses(
        (status = 200), (status = 400, description = "A redirect URI that cannot be matched"),
        (status = 403, description = "Missing client:write"), (status = 404),
    ),
)]
async fn update_client(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(client_id): Path<String>,
    Json(body): Json<UpdateClient>,
) -> Result<Json<ClientView>, ApiError> {
    Ok(Json(
        authenc_oauth::admin::update(
            &state.db,
            &actor,
            &client_id,
            authenc_oauth::client::Changes {
                redirect_uris: body.redirect_uris.as_deref(),
                scopes: body.scopes.as_deref(),
                require_consent: body.require_consent,
            },
        )
        .await?
        .into(),
    ))
}

/// Delete a client, and with it every code, token, and consent it holds.
#[utoipa::path(
    delete, path = "/api/v1/clients/{client_id}", tag = "oauth",
    responses((status = 204), (status = 403, description = "Missing client:write"), (status = 404)),
)]
async fn delete_client(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(client_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    authenc_oauth::admin::delete(&state.db, &actor, &client_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Replace a client's secret and return the new one.
///
/// Tokens the client already holds keep working; what stops working is the old
/// secret at the token endpoint. That is what makes this usable during an
/// incident rather than only at setup.
#[utoipa::path(
    post, path = "/api/v1/clients/{client_id}/secret", tag = "oauth",
    responses(
        (status = 200, body = ClientCredentials),
        (status = 400, description = "A public client holds no secret"),
        (status = 403, description = "Missing client:write"), (status = 404),
    ),
)]
async fn rotate_client_secret(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(client_id): Path<String>,
) -> Result<Json<ClientCredentials>, ApiError> {
    let secret =
        authenc_oauth::admin::rotate_secret(&state.db, &actor, &state.hasher, &client_id).await?;
    let client = authenc_oauth::admin::get(&state.db, &actor, &client_id).await?;

    Ok(Json(ClientCredentials {
        client: client.into(),
        client_secret: Some(secret.expose().to_owned()),
    }))
}
