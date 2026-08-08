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
    Permission, RoleId, UserId,
    model::{Realm, Role, User},
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
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

/// Body for creating a user.
#[derive(Debug, Deserialize, ToSchema)]
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
pub struct SetEnabled {
    /// Whether the user may authenticate.
    pub enabled: bool,
}

/// Body for registering an OAuth client.
#[derive(Debug, Deserialize, ToSchema)]
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
        grant_role,
        revoke_role,
        list_clients,
        register_client,
        get_client,
        update_client,
        delete_client,
        rotate_client_secret,
    ),
    components(schemas(
        CreateUser,
        SetEnabled,
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
        .route("/roles/{role_id}/users/{user_id}", post(grant_role))
        .route("/roles/{role_id}/users/{user_id}", delete(revoke_role))
        .route("/clients", get(list_clients).post(register_client))
        .route(
            "/clients/{client_id}",
            get(get_client).patch(update_client).delete(delete_client),
        )
        .route("/clients/{client_id}/secret", post(rotate_client_secret))
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
