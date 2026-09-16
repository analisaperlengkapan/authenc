//! The OAuth 2.0 and OpenID Connect endpoints.
//!
//! Thin, like the REST surface: each handler parses a request, calls
//! `authenc_oauth`, and shapes the answer. Every protocol rule — PKCE, code
//! single-use, refresh rotation, redirect-URI matching, client authentication
//! — lives in that crate and is tested there without an HTTP stack.
//!
//! What this module is responsible for is the part that only exists at the
//! HTTP boundary, and it is where the previous implementation went wrong:
//!
//! * **The discovery path.** `/.well-known/openid-configuration`, with
//!   hyphens. The old router registered `openid_configuration`, which no
//!   conformant client looks for.
//! * **Which failures may be redirected.** An unknown client or an
//!   unregistered `redirect_uri` is reported *here*, never by redirecting; the
//!   old authorize endpoint bounced the browser to whatever URI it was handed.
//! * **No test endpoints.** The old router mounted `/oauth2/authorize/test`,
//!   `/oauth2/token/test`, and `/oauth2/consent/test` unauthenticated, with a
//!   hardcoded user id, and `POST /oidc/token` returned a signed token for
//!   `demo_user` to any caller at all.

use authenc_contract::{AppError, RealmId, UserId, model::Realm};
use authenc_identity::{Db, SecretToken, realm, session, user};
use authenc_oauth::{
    Client, OAuthError,
    client::{self, Credentials, GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN},
    code::{self, Challenge, Redemption},
    consent, discovery,
    error::OAuthErrorCode,
    grant, keyring, refresh, scope, token,
};
use axum::{
    Form, Json, Router,
    extract::{OriginalUri, Path, Query, RawQuery, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::CookieJar;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};

use crate::{error::ApiError, state::AppState};

/// Build the protocol routes.
///
/// Mounted at the root rather than under `/api`, because their paths are part
/// of the specification and are what a discovery document has to advertise.
pub fn router() -> Router<AppState> {
    Router::new()
        // Both spellings of discovery: the realm-specific one a client is
        // normally pointed at, and the root one for tooling that only knows
        // how to look at an origin.
        .route("/.well-known/openid-configuration", get(default_discovery))
        .route(
            "/.well-known/oauth-authorization-server",
            get(default_discovery),
        )
        .route(
            "/realms/{realm}/.well-known/openid-configuration",
            get(realm_discovery),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/auth",
            get(authorize).post(approve),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/token",
            post(exchange),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/userinfo",
            get(userinfo).post(userinfo),
        )
        .route("/realms/{realm}/protocol/openid-connect/certs", get(jwks))
        .route(
            "/realms/{realm}/protocol/openid-connect/token/introspect",
            post(introspect),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/revoke",
            post(revoke),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/register",
            post(register),
        )
        .route(
            "/realms/{realm}/protocol/openid-connect/logout",
            get(logout).post(logout),
        )
}

// ---------------------------------------------------------------------------
// Error responses
// ---------------------------------------------------------------------------

/// An [`OAuthError`] rendered the way the specifications require.
#[derive(Debug)]
pub struct OidcError(pub OAuthError);

impl IntoResponse for OidcError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.0.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

        let mut response = (status, Json(&self.0)).into_response();
        no_store(response.headers_mut());

        // RFC 6749 §5.2 and RFC 6750 §3: a 401 from these endpoints carries a
        // challenge saying how to authenticate, not a bare status.
        if status == StatusCode::UNAUTHORIZED {
            let scheme = if self.0.code == OAuthErrorCode::InvalidToken {
                format!(
                    r#"Bearer error="invalid_token", error_description="{}""#,
                    self.0.description.replace('"', "'"),
                )
            } else {
                r#"Basic realm="oauth", charset="UTF-8""#.to_owned()
            };
            if let Ok(value) = HeaderValue::from_str(&scheme) {
                response
                    .headers_mut()
                    .insert(header::WWW_AUTHENTICATE, value);
            }
        }

        response
    }
}

impl From<OAuthError> for OidcError {
    fn from(error: OAuthError) -> Self {
        Self(error)
    }
}

impl From<AppError> for OidcError {
    fn from(error: AppError) -> Self {
        Self(error.into())
    }
}

/// A token response must never be cached: it carries credentials.
fn no_store(headers: &mut HeaderMap) {
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate"),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

// ---------------------------------------------------------------------------
// Discovery and keys
// ---------------------------------------------------------------------------

async fn default_discovery(
    State(state): State<AppState>,
) -> Result<Json<discovery::Metadata>, ApiError> {
    let name = state.config.oauth.default_realm.clone();
    document_for(&state, &name).await
}

async fn realm_discovery(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<discovery::Metadata>, ApiError> {
    document_for(&state, &name).await
}

async fn document_for(state: &AppState, name: &str) -> Result<Json<discovery::Metadata>, ApiError> {
    // Answering for a realm that does not exist would advertise endpoints that
    // reject everything, which is worse than a plain 404.
    realm::by_name(&state.db, name).await?;
    Ok(Json(discovery::metadata(state.config.origin(), name)))
}

async fn jwks(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<keyring::JwkSet>, ApiError> {
    let realm = realm::by_name(&state.db, &name).await?;
    // Reaching for the active key first means a realm that has never signed
    // anything still publishes a usable document, rather than an empty one a
    // client would cache.
    keyring::active(&state.db, &state.master_key, realm.id).await?;
    Ok(Json(keyring::jwks(&state.db, realm.id).await?))
}

// ---------------------------------------------------------------------------
// Authorization endpoint
// ---------------------------------------------------------------------------

/// Everything the authorization endpoint reads, from a query string or a form.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizeRequest {
    /// Must be `code`.
    #[serde(default)]
    pub response_type: String,
    /// The client asking.
    #[serde(default)]
    pub client_id: String,
    /// Where to send the browser back to. Required, and matched exactly.
    pub redirect_uri: Option<String>,
    /// Space-delimited scopes.
    #[serde(default)]
    pub scope: String,
    /// Opaque value echoed back, for the client's own CSRF defence.
    pub state: Option<String>,
    /// Echoed into the ID token.
    pub nonce: Option<String>,
    /// PKCE challenge.
    pub code_challenge: Option<String>,
    /// PKCE method. Must be `S256`.
    pub code_challenge_method: Option<String>,
    /// `none` forbids any interaction; `login` and `consent` force it.
    pub prompt: Option<String>,
    /// Set by the consent form when the user approves.
    pub approve: Option<String>,
    /// The session's CSRF token, on the consent form only.
    pub csrf_token: Option<String>,
}

/// A validated authorization request.
struct Validated {
    realm: Realm,
    client: Client,
    redirect_uri: String,
    scopes: Vec<String>,
    challenge: Option<Challenge>,
}

/// How an authorization request failed.
enum Refusal {
    /// Cannot be reported to the client: there is no address we trust.
    Direct(OAuthError),
    /// Report by redirecting, as RFC 6749 §4.1.2.1 requires.
    Redirect {
        uri: String,
        error: OAuthError,
        state: Option<String>,
    },
}

impl Refusal {
    fn redirect(validated: &Validated, request: &AuthorizeRequest, error: OAuthError) -> Self {
        Self::Redirect {
            uri: validated.redirect_uri.clone(),
            error,
            state: request.state.clone(),
        }
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        match self {
            Self::Direct(error) => OidcError(error).into_response(),
            Self::Redirect { uri, error, state } => {
                let mut params = vec![
                    ("error", error.code.as_str().to_owned()),
                    ("error_description", error.description),
                ];
                if let Some(state) = state {
                    params.push(("state", state));
                }
                Redirect::to(&with_query(&uri, &params)).into_response()
            }
        }
    }
}

/// Validate as far as a request can be validated without a user.
///
/// The order is deliberate: the client and the redirect URI are settled first,
/// because until both are known-good there is nowhere an error may be sent.
async fn validate(
    db: &Db,
    realm_name: &str,
    request: &AuthorizeRequest,
) -> Result<Validated, Refusal> {
    let realm = realm::by_name(db, realm_name)
        .await
        .map_err(|_| Refusal::Direct(OAuthError::invalid_request("no such realm")))?;

    let client = client::by_client_id(db, realm.id, &request.client_id)
        .await
        .map_err(|_| Refusal::Direct(OAuthError::invalid_client("unknown client")))?;

    let Some(redirect_uri) = request.redirect_uri.clone() else {
        return Err(Refusal::Direct(OAuthError::invalid_request(
            "redirect_uri is required",
        )));
    };
    if !client.allows_redirect(&redirect_uri) {
        return Err(Refusal::Direct(OAuthError::invalid_redirect_uri(
            "redirect_uri is not registered for this client",
        )));
    }

    let mut validated = Validated {
        realm,
        client,
        redirect_uri,
        scopes: Vec::new(),
        challenge: None,
    };

    // From here the client and the address are trusted, so failures go back to
    // the client rather than to the user's screen.
    if validated.response_type_is_wrong(request) {
        return Err(Refusal::redirect(
            &validated,
            request,
            OAuthError::new(
                OAuthErrorCode::UnsupportedResponseType,
                "only response_type=code is supported",
            ),
        ));
    }
    if !validated.client.allows_grant(GRANT_AUTHORIZATION_CODE) {
        return Err(Refusal::redirect(
            &validated,
            request,
            OAuthError::new(
                OAuthErrorCode::UnauthorizedClient,
                "this client may not use the authorization code grant",
            ),
        ));
    }

    validated.scopes = scope::resolve(&scope::parse(&request.scope), &validated.client.scopes)
        .map_err(|error| Refusal::redirect(&validated, request, error))?;

    validated.challenge = match request.code_challenge.as_deref() {
        Some(value) => Some(
            Challenge::new(value, request.code_challenge_method.as_deref())
                .map_err(|error| Refusal::redirect(&validated, request, error))?,
        ),
        None if validated.client.requires_pkce() => {
            return Err(Refusal::redirect(
                &validated,
                request,
                OAuthError::invalid_request("code_challenge is required for a public client"),
            ));
        }
        None => None,
    };

    Ok(validated)
}

impl Validated {
    fn response_type_is_wrong(&self, request: &AuthorizeRequest) -> bool {
        request.response_type != "code"
    }
}

/// `GET /realms/{realm}/protocol/openid-connect/auth`.
///
/// Where a browser arrives from a client application.
async fn authorize(
    State(state): State<AppState>,
    Path(realm_name): Path<String>,
    OriginalUri(uri): OriginalUri,
    RawQuery(query): RawQuery,
    jar: CookieJar,
    Query(request): Query<AuthorizeRequest>,
) -> Response {
    let validated = match validate(&state.db, &realm_name, &request).await {
        Ok(validated) => validated,
        Err(refusal) => return refusal.into_response(),
    };

    let prompt_is_none = request.prompt.as_deref() == Some("none");

    let Some(signed_in) = signed_in_user(&state, &jar, validated.realm.id).await else {
        return if prompt_is_none {
            Refusal::redirect(
                &validated,
                &request,
                OAuthError::new(
                    OAuthErrorCode::LoginRequired,
                    "no signed-in user and prompt=none was requested",
                ),
            )
            .into_response()
        } else {
            // Back here once they have signed in, with the request intact.
            Redirect::to(&with_query("/login", &[("next", uri.to_string())])).into_response()
        };
    };

    let asks_for_consent = request.prompt.as_deref() == Some("consent");
    let needs_consent = validated.client.require_consent
        && (asks_for_consent
            || !matches!(
                consent::is_satisfied(
                    &state.db,
                    signed_in.user_id,
                    validated.client.key,
                    &validated.scopes,
                )
                .await,
                Ok(true)
            ));

    if needs_consent {
        return if prompt_is_none {
            Refusal::redirect(
                &validated,
                &request,
                OAuthError::new(
                    OAuthErrorCode::ConsentRequired,
                    "the user has not approved these scopes and prompt=none was requested",
                ),
            )
            .into_response()
        } else {
            // The consent screen is a Leptos page; it posts the same
            // parameters back to this endpoint once the user decides. The
            // realm travels with them so the page knows where to post, and
            // everything else is re-validated here on the way back.
            let target = match query {
                Some(query) => format!("/consent?{query}"),
                None => "/consent".to_owned(),
            };
            Redirect::to(&with_query(&target, &[("realm", realm_name)])).into_response()
        };
    }

    grant_code(&state, &validated, &request, &signed_in).await
}

/// `POST /realms/{realm}/protocol/openid-connect/auth`.
///
/// The consent form's submission. Requires the session's CSRF token: without
/// it, a page on another origin could approve scopes on the user's behalf by
/// submitting this form for them.
async fn approve(
    State(state): State<AppState>,
    Path(realm_name): Path<String>,
    jar: CookieJar,
    Form(request): Form<AuthorizeRequest>,
) -> Response {
    let validated = match validate(&state.db, &realm_name, &request).await {
        Ok(validated) => validated,
        Err(refusal) => return refusal.into_response(),
    };

    let policy = crate::auth::cookie_policy(&state.config);
    let session = match crate::auth::session_for(&state.db, policy, &jar).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return OidcError(OAuthError::new(
                OAuthErrorCode::LoginRequired,
                "sign in before approving",
            ))
            .into_response();
        }
        Err(error) => return OidcError::from(error).into_response(),
    };

    let presented = request.csrf_token.as_deref().unwrap_or_default();
    if !session.csrf_token_matches(presented) {
        return OidcError(OAuthError::invalid_request(
            "the approval did not carry this session's CSRF token",
        ))
        .into_response();
    }

    if request.approve.as_deref() != Some("true") {
        return Refusal::redirect(
            &validated,
            &request,
            OAuthError::new(
                OAuthErrorCode::AccessDenied,
                "the user declined the request",
            ),
        )
        .into_response();
    }

    let signed_in = SignedIn {
        user_id: session.user_id,
        authenticated_with: session.authenticated_with.clone(),
    };
    let user_id = signed_in.user_id;
    if !user_belongs_to(&state, user_id, validated.realm.id).await {
        return OidcError(OAuthError::new(
            OAuthErrorCode::LoginRequired,
            "sign in to this realm before approving",
        ))
        .into_response();
    }

    if let Err(error) =
        consent::record(&state.db, user_id, validated.client.key, &validated.scopes).await
    {
        return OidcError::from(error).into_response();
    }

    grant_code(&state, &validated, &request, &signed_in).await
}

/// Issue a code and send the browser back to the client.
async fn grant_code(
    state: &AppState,
    validated: &Validated,
    request: &AuthorizeRequest,
    signed_in: &SignedIn,
) -> Response {
    let issued = code::issue(
        &state.db,
        code::NewCode {
            client: validated.client.key,
            realm_id: validated.realm.id,
            user_id: signed_in.user_id,
            // Snapshotted onto the code, so the ID token minted when it is
            // redeemed describes the sign-in that actually authorised it.
            authenticated_with: &signed_in.authenticated_with,
            redirect_uri: &validated.redirect_uri,
            scopes: &validated.scopes,
            nonce: request.nonce.as_deref(),
            challenge: validated.challenge.as_ref(),
        },
    )
    .await;

    match issued {
        Ok(code) => {
            let mut params = vec![("code", code.expose().to_owned())];
            if let Some(state) = request.state.clone() {
                params.push(("state", state));
            }
            Redirect::to(&with_query(&validated.redirect_uri, &params)).into_response()
        }
        Err(error) => Refusal::redirect(validated, request, error.into()).into_response(),
    }
}

/// The signed-in user, if there is one and they belong to this realm.
/// The session behind an authorization request, as the protocol layer needs it.
///
/// Carries the `amr` as well as the user, because the ID token this eventually
/// produces has to describe *this* sign-in. Recomputing it at issuance would
/// answer a different question — what the account has enrolled now, rather than
/// what was actually presented.
struct SignedIn {
    user_id: UserId,
    authenticated_with: Vec<String>,
}

async fn signed_in_user(state: &AppState, jar: &CookieJar, realm_id: RealmId) -> Option<SignedIn> {
    let policy = crate::auth::cookie_policy(&state.config);
    let session = crate::auth::session_for(&state.db, policy, jar)
        .await
        .ok()
        .flatten()?;

    user_belongs_to(state, session.user_id, realm_id)
        .await
        .then_some(SignedIn {
            user_id: session.user_id,
            authenticated_with: session.authenticated_with,
        })
}

/// Whether a user is an enabled member of this realm.
///
/// Both halves matter. A session in realm A must not authorise anything in
/// realm B, and a disabled account must stop working the instant it is
/// disabled, even while its session row still exists.
async fn user_belongs_to(state: &AppState, user_id: UserId, realm_id: RealmId) -> bool {
    match user::by_id(&state.db, user_id).await {
        Ok(user) => user.enabled && user.realm_id == realm_id,
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

/// The token endpoint's request body.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenRequest {
    /// `authorization_code` or `refresh_token`.
    #[serde(default)]
    pub grant_type: String,
    /// The code, for the authorization-code grant.
    pub code: Option<String>,
    /// Must equal the URI the code was issued against.
    pub redirect_uri: Option<String>,
    /// The PKCE verifier.
    pub code_verifier: Option<String>,
    /// The token, for the refresh grant.
    pub refresh_token: Option<String>,
    /// Client id, for `client_secret_post` and public clients.
    pub client_id: Option<String>,
    /// Client secret, for `client_secret_post`.
    pub client_secret: Option<String>,
    /// Optional narrowing on the refresh grant.
    pub scope: Option<String>,
}

/// `POST /realms/{realm}/protocol/openid-connect/token`.
async fn exchange(
    State(state): State<AppState>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> Result<Response, OidcError> {
    let realm = realm::by_name(&state.db, &realm_name)
        .await
        .map_err(|_| OidcError(OAuthError::invalid_client("unknown client")))?;

    let credentials = credentials_from(
        &headers,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    )?;
    let client = client::authenticate(&state.db, &state.hasher, realm.id, &credentials).await?;

    let issuer = token::issuer_for(state.config.origin(), &realm.name);

    let response = match request.grant_type.as_str() {
        GRANT_AUTHORIZATION_CODE => {
            authorization_code_grant(&state, &realm, &client, &issuer, &request).await?
        }
        GRANT_REFRESH_TOKEN => refresh_grant(&state, &realm, &client, &issuer, &request).await?,
        "" => {
            return Err(OidcError(OAuthError::invalid_request(
                "grant_type is required",
            )));
        }
        other => {
            return Err(OidcError(OAuthError::new(
                OAuthErrorCode::UnsupportedGrantType,
                format!("grant type '{other}' is not supported"),
            )));
        }
    };

    let mut response = Json(response).into_response();
    no_store(response.headers_mut());
    Ok(response)
}

async fn authorization_code_grant(
    state: &AppState,
    realm: &Realm,
    client: &Client,
    issuer: &str,
    request: &TokenRequest,
) -> Result<grant::TokenResponse, OidcError> {
    if !client.allows_grant(GRANT_AUTHORIZATION_CODE) {
        return Err(OidcError(OAuthError::new(
            OAuthErrorCode::UnauthorizedClient,
            "this client may not use the authorization code grant",
        )));
    }

    let (Some(code_value), Some(redirect_uri)) =
        (request.code.as_deref(), request.redirect_uri.as_deref())
    else {
        return Err(OidcError(OAuthError::invalid_request(
            "code and redirect_uri are both required",
        )));
    };

    let redeemed = code::redeem(
        &state.db,
        &SecretToken::from_client(code_value),
        client.key,
        redirect_uri,
        request.code_verifier.as_deref(),
    )
    .await?;

    let authorization = match redeemed {
        Redemption::Granted(authorization) => authorization,
        Redemption::Replayed { family_id } => {
            // The code leaked. Whatever it minted is in the same hands.
            refresh::revoke_family(&state.db, family_id).await?;
            return Err(OidcError(OAuthError::invalid_grant(
                "authorization code has already been used",
            )));
        }
    };

    Ok(grant::issue(
        &state.db,
        &state.master_key,
        grant::Issue {
            realm_id: realm.id,
            issuer,
            client,
            user_id: authorization.user_id,
            scopes: &authorization.scopes,
            nonce: authorization.nonce.as_deref(),
            authenticated_with: &authorization.authenticated_with,
            family_id: authorization.id,
            refresh: grant::Refresh::IfGranted,
        },
    )
    .await?)
}

async fn refresh_grant(
    state: &AppState,
    realm: &Realm,
    client: &Client,
    issuer: &str,
    request: &TokenRequest,
) -> Result<grant::TokenResponse, OidcError> {
    if !client.allows_grant(GRANT_REFRESH_TOKEN) {
        return Err(OidcError(OAuthError::new(
            OAuthErrorCode::UnauthorizedClient,
            "this client may not use the refresh token grant",
        )));
    }

    let Some(presented) = request.refresh_token.as_deref() else {
        return Err(OidcError(OAuthError::invalid_request(
            "refresh_token is required",
        )));
    };

    let rotated =
        refresh::rotate(&state.db, &SecretToken::from_client(presented), client.key).await?;

    // RFC 6749 §6 lets a client ask for less than it holds, never for more.
    let scopes = match request.scope.as_deref() {
        Some(requested) => scope::resolve(&scope::parse(requested), &rotated.scopes)?,
        None => rotated.scopes.clone(),
    };

    // A disabled account must not be able to refresh its way back in.
    if !user_belongs_to(state, rotated.user_id, realm.id).await {
        refresh::revoke_family(&state.db, rotated.family_id).await?;
        return Err(OidcError(OAuthError::invalid_grant(
            "the account behind this token can no longer sign in",
        )));
    }

    Ok(grant::issue(
        &state.db,
        &state.master_key,
        grant::Issue {
            realm_id: realm.id,
            issuer,
            client,
            user_id: rotated.user_id,
            scopes: &scopes,
            nonce: None,
            authenticated_with: &rotated.authenticated_with,
            family_id: rotated.family_id,
            refresh: grant::Refresh::Existing(rotated.token.expose().to_owned()),
        },
    )
    .await?)
}

/// Read client credentials from exactly one place.
///
/// RFC 6749 §2.3 says a client must not use more than one authentication
/// method in a single request. Accepting both and preferring one silently
/// lets a caller smuggle a second identity past whatever logs the first.
fn credentials_from(
    headers: &HeaderMap,
    body_client_id: Option<&str>,
    body_secret: Option<&str>,
) -> Result<Credentials, OidcError> {
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .map(str::trim);

    match (basic, body_secret) {
        (Some(_), Some(_)) => Err(OidcError(OAuthError::invalid_request(
            "present client credentials once, not in both the header and the body",
        ))),
        (Some(encoded), None) => {
            let decoded = BASE64
                .decode(encoded)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .ok_or_else(|| {
                    OidcError(OAuthError::invalid_client("malformed Basic credentials"))
                })?;
            let (id, secret) = decoded.split_once(':').ok_or_else(|| {
                OidcError(OAuthError::invalid_client("malformed Basic credentials"))
            })?;

            Ok(Credentials {
                client_id: form_decode(id),
                secret: Some(form_decode(secret)),
            })
        }
        (None, secret) => {
            let client_id = body_client_id
                .ok_or_else(|| OidcError(OAuthError::invalid_client("client_id is required")))?;
            Ok(Credentials {
                client_id: client_id.to_owned(),
                secret: secret.map(ToOwned::to_owned),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// UserInfo
// ---------------------------------------------------------------------------

/// `GET|POST /realms/{realm}/protocol/openid-connect/userinfo`.
async fn userinfo(
    State(state): State<AppState>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
) -> Result<Response, OidcError> {
    let realm = realm::by_name(&state.db, &realm_name).await.map_err(|_| {
        OidcError(OAuthError::new(
            OAuthErrorCode::InvalidToken,
            "unknown realm",
        ))
    })?;

    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            OidcError(OAuthError::new(
                OAuthErrorCode::InvalidToken,
                "a bearer access token is required",
            ))
        })?;

    let claims = verify_access_token(&state, &realm, presented).await?;

    let user_id = claims
        .sub
        .parse::<uuid::Uuid>()
        .map(UserId)
        .map_err(|_| invalid_token("the token names no valid subject"))?;

    // The account may have been disabled since the token was issued; an access
    // token is not a licence to keep reading claims about a closed account.
    if !user_belongs_to(&state, user_id, realm.id).await {
        return Err(invalid_token("the account is no longer active"));
    }

    let scopes = claims
        .scope
        .as_deref()
        .map(scope::parse)
        .unwrap_or_default();

    let mut response = Json(grant::userinfo(&state.db, user_id, &scopes).await?).into_response();
    no_store(response.headers_mut());
    Ok(response)
}

/// Verify a token this provider issued, whichever client it was issued to.
async fn verify_access_token(
    state: &AppState,
    realm: &Realm,
    presented: &str,
) -> Result<token::Claims, OidcError> {
    let kid = token::kid_of(presented).map_err(|_| invalid_token("malformed token"))?;

    let public = keyring::verifying_key(&state.db, &kid)
        .await?
        .ok_or_else(|| invalid_token("the token was signed by an unknown key"))?;

    let issuer = token::issuer_for(state.config.origin(), &realm.name);
    token::verify_any_audience(presented, &public, &issuer)
        .map_err(|_| invalid_token("the token is expired or not valid here"))
}

fn invalid_token(description: &str) -> OidcError {
    OidcError(OAuthError::new(OAuthErrorCode::InvalidToken, description))
}

// ---------------------------------------------------------------------------
// Introspection and revocation
// ---------------------------------------------------------------------------

/// RFC 7662 and RFC 7009 both take a token and an optional hint.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenIntrospection {
    /// The token in question.
    #[serde(default)]
    pub token: String,
    /// What the caller believes it is. Advisory only.
    pub token_type_hint: Option<String>,
    /// Client id, for `client_secret_post`.
    pub client_id: Option<String>,
    /// Client secret, for `client_secret_post`.
    pub client_secret: Option<String>,
}

/// `POST /realms/{realm}/protocol/openid-connect/token/introspect`.
///
/// Authenticated with **client** credentials, not a bearer token. The previous
/// implementation gated introspection on a bearer JWT, which meant any token
/// the server had ever issued could be used to inspect any other.
async fn introspect(
    State(state): State<AppState>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
    Form(request): Form<TokenIntrospection>,
) -> Result<Response, OidcError> {
    let realm = realm::by_name(&state.db, &realm_name)
        .await
        .map_err(|_| OidcError(OAuthError::invalid_client("unknown client")))?;

    let credentials = credentials_from(
        &headers,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    )?;
    let client = client::authenticate(&state.db, &state.hasher, realm.id, &credentials).await?;

    let mut response =
        Json(describe_token(&state, &realm, &client, &request.token).await).into_response();
    no_store(response.headers_mut());
    Ok(response)
}

/// The introspection response (RFC 7662 §2.2).
#[derive(Debug, Default, Serialize)]
struct Introspection {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<String>,
}

async fn describe_token(
    state: &AppState,
    realm: &Realm,
    client: &Client,
    presented: &str,
) -> Introspection {
    if presented.is_empty() {
        return Introspection::default();
    }

    // An access token is a JWT; a refresh token is opaque. Try both rather
    // than trusting `token_type_hint`, which RFC 7662 §2.1 calls advisory.
    if let Ok(claims) = verify_access_token(state, realm, presented).await {
        // A client may only ever look at a token minted for itself. Otherwise
        // any registered client can inspect every other client's tokens.
        if claims.aud != client.client_id {
            return Introspection::default();
        }
        return Introspection {
            active: true,
            scope: claims.scope,
            client_id: Some(claims.aud),
            sub: Some(claims.sub),
            exp: Some(claims.exp),
            iat: Some(claims.iat),
            iss: Some(claims.iss),
            token_type: Some("Bearer".to_owned()),
        };
    }

    match refresh::introspect(&state.db, &SecretToken::from_client(presented), client.key).await {
        Ok(Some(found)) => Introspection {
            active: true,
            scope: Some(scope::join(&found.scopes)),
            client_id: Some(client.client_id.clone()),
            sub: Some(found.user_id.to_string()),
            exp: Some(found.expires_at.unix_timestamp()),
            iss: Some(token::issuer_for(state.config.origin(), &realm.name)),
            token_type: Some("Refresh".to_owned()),
            iat: None,
        },
        // Unknown, expired, or someone else's. RFC 7662 §2.2 is explicit that
        // this is a 200 with `active: false`, not an error: an error would let
        // a caller tell "not yours" apart from "does not exist".
        Ok(None) => Introspection::default(),
        Err(error) => {
            tracing::error!(?error, "introspection lookup failed");
            Introspection::default()
        }
    }
}

/// `POST /realms/{realm}/protocol/openid-connect/revoke`.
///
/// RFC 7009 §2.2: a token the server does not recognise is a *successful*
/// revocation. Reporting otherwise turns this endpoint into an oracle for
/// which tokens exist.
async fn revoke(
    State(state): State<AppState>,
    Path(realm_name): Path<String>,
    headers: HeaderMap,
    Form(request): Form<TokenIntrospection>,
) -> Result<StatusCode, OidcError> {
    let realm = realm::by_name(&state.db, &realm_name)
        .await
        .map_err(|_| OidcError(OAuthError::invalid_client("unknown client")))?;

    let credentials = credentials_from(
        &headers,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    )?;
    let client = client::authenticate(&state.db, &state.hasher, realm.id, &credentials).await?;

    if !request.token.is_empty() {
        let revoked = refresh::revoke(
            &state.db,
            &SecretToken::from_client(&request.token),
            client.key,
        )
        .await?;
        tracing::debug!(revoked, client = %client.client_id, "revocation processed");
    }

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Dynamic client registration (RFC 7591)
// ---------------------------------------------------------------------------

/// The registration request (RFC 7591 §2).
#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationRequest {
    /// Display name.
    pub client_name: Option<String>,
    /// Redirect URIs. At least one is required.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// Grant types.
    #[serde(default)]
    pub grant_types: Vec<String>,
    /// Space-delimited scopes.
    pub scope: Option<String>,
    /// `none` registers a public client; anything else a confidential one.
    pub token_endpoint_auth_method: Option<String>,
}

/// The registration response (RFC 7591 §3.2.1).
#[derive(Debug, Serialize)]
struct RegistrationResponse {
    client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
    client_id_issued_at: i64,
    /// `0` means the secret does not expire.
    client_secret_expires_at: i64,
    client_name: String,
    redirect_uris: Vec<String>,
    grant_types: Vec<String>,
    scope: String,
    token_endpoint_auth_method: String,
}

/// `POST /realms/{realm}/protocol/openid-connect/register`.
///
/// Off unless `oauth.allow_dynamic_registration` is set. Open registration on
/// an IAM server lets anyone create a client whose redirect URI they control,
/// which is a phishing page wearing the operator's own domain.
async fn register(
    State(state): State<AppState>,
    Path(realm_name): Path<String>,
    Json(request): Json<RegistrationRequest>,
) -> Result<Response, OidcError> {
    if !state.config.oauth.allow_dynamic_registration {
        return Err(OidcError(OAuthError::new(
            OAuthErrorCode::AccessDenied,
            "dynamic client registration is disabled on this server",
        )));
    }

    let realm = realm::by_name(&state.db, &realm_name)
        .await
        .map_err(|_| OidcError(OAuthError::invalid_request("no such realm")))?;

    let is_public = request.token_endpoint_auth_method.as_deref() == Some("none");
    let scopes = request
        .scope
        .as_deref()
        .map(scope::parse)
        .unwrap_or_default();
    let name = request.client_name.as_deref().unwrap_or("Unnamed client");

    let registered = client::register(
        &state.db,
        &state.hasher,
        client::NewClient {
            realm_id: realm.id,
            client_id: None,
            name,
            is_public,
            redirect_uris: &request.redirect_uris,
            grant_types: &request.grant_types,
            scopes: &scopes,
            require_consent: true,
        },
    )
    .await?;

    let body = RegistrationResponse {
        client_id: registered.client.client_id.clone(),
        client_secret: registered
            .client_secret
            .as_ref()
            .map(|secret| secret.expose().to_owned()),
        client_id_issued_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        client_secret_expires_at: 0,
        client_name: registered.client.name.clone(),
        redirect_uris: registered.client.redirect_uris.clone(),
        grant_types: registered.client.grant_types.clone(),
        scope: scope::join(&registered.client.scopes),
        token_endpoint_auth_method: if is_public {
            "none".to_owned()
        } else {
            "client_secret_basic".to_owned()
        },
    };

    let mut response = (StatusCode::CREATED, Json(body)).into_response();
    no_store(response.headers_mut());
    Ok(response)
}

// ---------------------------------------------------------------------------
// RP-initiated logout
// ---------------------------------------------------------------------------

/// Parameters for RP-initiated logout.
#[derive(Debug, Clone, Deserialize)]
pub struct LogoutRequest {
    /// Where to send the browser afterwards.
    pub post_logout_redirect_uri: Option<String>,
    /// The client asking, so the redirect URI can be checked against it.
    pub client_id: Option<String>,
    /// Echoed back.
    pub state: Option<String>,
}

/// `GET|POST /realms/{realm}/protocol/openid-connect/logout`.
///
/// Ends the session and clears the cookie. The redirect target is only
/// honoured when it is registered for the named client — an unchecked
/// `post_logout_redirect_uri` is an open redirect wearing a specification's
/// name.
async fn logout(
    State(state): State<AppState>,
    Path(realm_name): Path<String>,
    jar: CookieJar,
    Query(request): Query<LogoutRequest>,
) -> Response {
    let policy = crate::auth::cookie_policy(&state.config);

    if let Some(token) = policy.read(&jar)
        && let Err(error) = session::revoke(&state.db, &token).await
    {
        tracing::error!(?error, "failed to revoke session on logout");
    }

    let target = resolve_logout_target(&state, &realm_name, &request)
        .await
        .unwrap_or_else(|| "/".to_owned());

    let redirect = match request.state.clone() {
        Some(value) => with_query(&target, &[("state", value)]),
        None => target,
    };

    // Clear the cookie on the way out, whatever the destination.
    (jar.add(policy.revoke()), Redirect::to(&redirect)).into_response()
}

async fn resolve_logout_target(
    state: &AppState,
    realm_name: &str,
    request: &LogoutRequest,
) -> Option<String> {
    let uri = request.post_logout_redirect_uri.as_deref()?;
    let client_id = request.client_id.as_deref()?;
    let realm = realm::by_name(&state.db, realm_name).await.ok()?;
    let client = client::by_client_id(&state.db, realm.id, client_id)
        .await
        .ok()?;

    client.allows_redirect(uri).then(|| uri.to_owned())
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

/// Append query parameters to a URL that may already have some.
fn with_query(base: &str, params: &[(&str, String)]) -> String {
    let mut out = base.to_owned();
    let mut separator = if base.contains('?') { '&' } else { '?' };

    for (key, value) in params {
        out.push(separator);
        out.push_str(key);
        out.push('=');
        out.push_str(&form_encode(value));
        separator = '&';
    }

    out
}

/// Percent-encode a value for a query string.
///
/// Hand-written rather than pulled in as a dependency: the rule is short, and
/// the set of characters left alone is the security-relevant part — `&`, `=`,
/// `#`, and `/` must all be encoded, or a `state` value could add parameters
/// to the redirect it travels in.
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Reverse [`form_encode`], for the two halves of a Basic credential.
fn form_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(decoded) => {
                        out.push(decoded);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_state_value_cannot_smuggle_extra_parameters_into_the_redirect() {
        // Without encoding, this `state` would add its own `code` to the URL.
        let url = with_query(
            "https://app.example.com/callback",
            &[("state", "a&code=stolen#x".to_owned())],
        );
        assert_eq!(
            url,
            "https://app.example.com/callback?state=a%26code%3Dstolen%23x",
        );
    }

    #[test]
    fn parameters_are_appended_to_a_uri_that_already_has_a_query() {
        let url = with_query(
            "https://app.example.com/callback?tenant=acme",
            &[("code", "abc".to_owned())],
        );
        assert_eq!(url, "https://app.example.com/callback?tenant=acme&code=abc");
    }

    #[test]
    fn basic_credentials_are_form_decoded_as_the_rfc_requires() {
        // RFC 6749 §2.3.1 form-encodes each half before base64, so a secret
        // containing a colon or a space still round-trips.
        let mut headers = HeaderMap::new();
        let raw = BASE64.encode("my%3Aclient:s%20e%26cret");
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {raw}").parse().unwrap(),
        );

        let credentials = credentials_from(&headers, None, None).unwrap();
        assert_eq!(credentials.client_id, "my:client");
        assert_eq!(credentials.secret.as_deref(), Some("s e&cret"));
    }

    #[test]
    fn credentials_may_not_be_presented_twice() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {}", BASE64.encode("a:b")).parse().unwrap(),
        );

        let error = credentials_from(&headers, Some("a"), Some("b")).unwrap_err();
        assert_eq!(error.0.code, OAuthErrorCode::InvalidRequest);
    }

    #[test]
    fn a_public_client_may_identify_itself_with_no_secret_at_all() {
        let credentials = credentials_from(&HeaderMap::new(), Some("spa"), None).unwrap();
        assert_eq!(credentials.client_id, "spa");
        assert!(credentials.secret.is_none());
    }

    #[test]
    fn a_request_with_no_client_id_anywhere_is_refused() {
        let error = credentials_from(&HeaderMap::new(), None, None).unwrap_err();
        assert_eq!(error.0.code, OAuthErrorCode::InvalidClient);
    }

    #[test]
    fn a_token_response_is_never_cacheable() {
        let mut headers = HeaderMap::new();
        no_store(&mut headers);
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "no-store, no-cache, must-revalidate",
        );
    }
}
