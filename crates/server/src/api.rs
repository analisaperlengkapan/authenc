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
    ),
    components(schemas(CreateUser, SetEnabled, CreateRole, Whoami, Csrf)),
    tags(
        (name = "identity", description = "Realms, users, and roles"),
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
