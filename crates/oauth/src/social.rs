//! The OAuth client half of social login.
//!
//! Everything here talks to somebody else's server, which is why it is the one
//! module in this crate behind a trait. [`Transport`] exists so the protocol
//! rules — what is sent, what is refused, how each provider's claims are read
//! — are testable without a network, because no provider's credentials can run
//! in CI. The real implementation is thirty lines at the bottom; the rules
//! above it are the part worth reviewing.
//!
//! # Being a client is not the mirror image of being a provider
//!
//! The endpoints in this crate defend against a client that lies. Here the
//! roles swap: this server is the client, and what it defends against is a
//! *browser* that lies and a *provider* that is not the one we meant.
//!
//! * `state` is bound to the pending sign-in, stored hashed, and single-use.
//!   Without it an attacker completes a sign-in with their own upstream
//!   account inside the victim's browser, and everything the victim then does
//!   happens in the attacker's account.
//! * PKCE is sent even though this is a confidential client, because a code
//!   that leaks through a `Referer` or a shared device is otherwise redeemable
//!   by whoever holds it.
//! * `nonce` is echoed in the ID token, so a token minted for one sign-in
//!   cannot be replayed into another.
//! * The `redirect_uri` is stored and replayed verbatim; providers compare it,
//!   and a mismatch is otherwise an afternoon of guessing.
//!
//! # What is *not* verified, and why that is defensible
//!
//! An ID token's signature is not checked. The token arrives on a direct TLS
//! connection to the provider's token endpoint, authenticated with this
//! client's own credentials, which is exactly the case OpenID Connect Core
//! §3.1.3.7 point 6 allows: "the TLS server validation MAY be used to validate
//! the issuer in place of checking the token signature". `iss`, `aud`, `exp`,
//! and `nonce` *are* checked, because those say something TLS does not.
//!
//! If this ever accepts an ID token from anywhere but that back channel — a
//! front-channel `id_token` response mode, say — the signature check stops
//! being optional and this note stops being true.

use std::collections::HashMap;

use authenc_contract::{AppError, IdentityProviderId, Result};
use authenc_identity::{
    Db, SecretToken,
    federation::{Claims, Kind, Provider},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

/// How long a pending sign-in stays completable.
///
/// Long enough to type a password and approve a consent screen at the
/// provider, short enough that an abandoned one is not lying around.
pub const STATE_LIFETIME: Duration = Duration::minutes(15);

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// The two HTTP calls an OAuth client makes.
///
/// A trait because the alternative is a module that cannot be tested at all:
/// every provider needs credentials this repository does not have and CI must
/// never hold. The mock in the tests below returns canned bodies, which is
/// enough to exercise every rule that is ours rather than the network's.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Redeem the authorization code. `form` is the token request; `basic` is
    /// the client credentials, when the provider wants them in the header.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not JSON.
    async fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> Result<serde_json::Value>;

    /// Read the claims, for a provider that does not put them in an ID token.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is not JSON.
    async fn get_json(&self, url: &str, bearer: &str) -> Result<serde_json::Value>;
}

// ---------------------------------------------------------------------------
// Beginning a sign-in
// ---------------------------------------------------------------------------

/// A sign-in that has been started but not completed.
#[derive(Debug)]
pub struct Started {
    /// Where to send the browser.
    pub authorization_url: String,
    /// The `state` to put in the cookie. Available once.
    pub state: SecretToken,
}

/// Start a sign-in: record the state and build the URL to redirect to.
///
/// `return_to` must be a same-origin path. It is not validated here — the
/// column's own constraint refuses anything else, so the rule cannot be
/// bypassed by a second caller that forgets to check.
///
/// # Errors
///
/// * [`AppError::Validation`] — `return_to` is not a same-origin path.
/// * [`AppError::Internal`] — entropy is unavailable or the insert fails.
pub async fn begin(
    db: &Db,
    provider: &Provider,
    redirect_uri: &str,
    return_to: Option<&str>,
) -> Result<Started> {
    let state = SecretToken::generate()
        .map_err(|e| AppError::internal_from("generating a login state", e))?;
    // `SecretToken` is 32 bytes base64url-encoded, which is 43 characters —
    // inside RFC 7636's 43-to-128 range for a code verifier, and the same
    // entropy every other token here carries.
    let verifier = SecretToken::generate()
        .map_err(|e| AppError::internal_from("generating a PKCE verifier", e))?;
    let nonce =
        SecretToken::generate().map_err(|e| AppError::internal_from("generating a nonce", e))?;

    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.expose().as_bytes()));
    let expires_at = OffsetDateTime::now_utc() + STATE_LIFETIME;

    sqlx::query!(
        r#"
        INSERT INTO federation_login_states
            (provider_id, state_hash, pkce_verifier, nonce, redirect_uri,
             return_to, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
        provider.id.0,
        state.hash(),
        verifier.expose(),
        nonce.expose(),
        redirect_uri,
        return_to,
        expires_at,
    )
    .execute(db)
    .await
    .map_err(|e| match &e {
        // The column's CHECK, which is where the open-redirect rule lives.
        sqlx::Error::Database(error) if error.code().as_deref() == Some("23514") => {
            AppError::field("return_to", "must be a path on this site")
        }
        _ => AppError::internal_from("recording a login state", e),
    })?;

    let mut url = form_urlencoded_url(
        &provider.authorization_endpoint,
        &[
            ("response_type", "code"),
            ("client_id", &provider.client_id),
            ("redirect_uri", redirect_uri),
            ("scope", &provider.scopes.join(" ")),
            ("state", state.expose()),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ],
    );

    // Only an OIDC provider will echo it, and sending it to one that will not
    // is harmless — but GitHub rejects unknown parameters on some endpoints,
    // so it is sent only where it means something.
    if provider.kind != Kind::GitHub {
        url = format!("{url}&nonce={}", urlencode(nonce.expose()));
    }

    Ok(Started {
        authorization_url: url,
        state,
    })
}

/// What `begin` stored, recovered by the callback.
#[derive(Debug)]
pub struct Pending {
    /// Which provider this sign-in was started with.
    pub provider_id: IdentityProviderId,
    /// The PKCE verifier to prove.
    pub verifier: String,
    /// The nonce the ID token must echo.
    pub nonce: String,
    /// The redirect URI to replay.
    pub redirect_uri: String,
    /// Where to send the browser afterwards.
    pub return_to: Option<String>,
}

/// Claim the state a callback presents.
///
/// One atomic `UPDATE … WHERE consumed_at IS NULL`, so two concurrent
/// callbacks with the same `state` produce one sign-in rather than two.
/// Unknown, expired, and already-spent are one answer to the caller.
///
/// # Errors
///
/// [`AppError::Unauthenticated`] if the state is not claimable.
pub async fn claim_state(db: &Db, state: &SecretToken) -> Result<Pending> {
    let row = sqlx::query!(
        r#"
        UPDATE federation_login_states
           SET consumed_at = now()
         WHERE state_hash = $1 AND consumed_at IS NULL AND expires_at > now()
        RETURNING provider_id, pkce_verifier, nonce, redirect_uri, return_to
        "#,
        state.hash(),
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("claiming a login state", e))?
    .ok_or(AppError::Unauthenticated)?;

    Ok(Pending {
        provider_id: IdentityProviderId(row.provider_id),
        verifier: row.pkce_verifier,
        nonce: row.nonce,
        redirect_uri: row.redirect_uri,
        return_to: row.return_to,
    })
}

/// Delete states that are past their expiry, for `authenc purge`.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn purge_expired(db: &Db) -> Result<u64> {
    let result = sqlx::query!("DELETE FROM federation_login_states WHERE expires_at < now()")
        .execute(db)
        .await
        .map_err(|e| AppError::internal_from("purging login states", e))?;
    Ok(result.rows_affected())
}

// ---------------------------------------------------------------------------
// Completing a sign-in
// ---------------------------------------------------------------------------

/// Redeem the code and read the claims.
///
/// # Errors
///
/// [`AppError::Unauthenticated`] if the provider refuses the code, returns no
/// access token, or returns an ID token whose `iss`, `aud`, `exp`, or `nonce`
/// is not what this sign-in asked for.
pub async fn complete(
    transport: &dyn Transport,
    provider: &Provider,
    client_secret: &str,
    pending: &Pending,
    code: &str,
) -> Result<Claims> {
    let response = transport
        .post_form(
            &provider.token_endpoint,
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &pending.redirect_uri),
                ("code_verifier", &pending.verifier),
                ("client_id", &provider.client_id),
                ("client_secret", client_secret),
            ],
            Some((&provider.client_id, client_secret)),
        )
        .await?;

    if let Some(error) = response.get("error").and_then(serde_json::Value::as_str) {
        tracing::warn!(provider = %provider.alias, %error, "a token exchange was refused");
        return Err(AppError::Unauthenticated);
    }

    let access_token = response
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            tracing::warn!(provider = %provider.alias, "a token response carried no access token");
            AppError::Unauthenticated
        })?;

    // An ID token, where there is one, is the authoritative source: it is what
    // the provider signed for this particular sign-in, and it carries the
    // nonce that ties it to this one rather than another.
    let id_claims = match response.get("id_token").and_then(serde_json::Value::as_str) {
        Some(id_token) => Some(verify_id_token(id_token, provider, &pending.nonce)?),
        None => None,
    };

    let userinfo = match &provider.userinfo_endpoint {
        Some(endpoint) => Some(transport.get_json(endpoint, access_token).await?),
        None => None,
    };

    let mut claims = read_claims(provider.kind, id_claims.as_ref(), userinfo.as_ref())?;

    // GitHub's `/user` reports the *public profile* address, which the account
    // holder types in and GitHub does not check. The verified set lives behind
    // a second call, and without it a GitHub sign-in would assert an address
    // nobody proved — which is precisely the input `link_by_verified_email`
    // leans on.
    if provider.kind == Kind::GitHub {
        let emails = transport
            .get_json("https://api.github.com/user/emails", access_token)
            .await?;
        match primary_verified_email(&emails) {
            Some(email) => {
                claims.email = Some(email);
                claims.email_verified = true;
            }
            None => {
                claims.email_verified = false;
            }
        }
    }

    Ok(claims)
}

/// The claims inside an ID token, after the checks that are ours to make.
type IdClaims = HashMap<String, serde_json::Value>;

/// Decode an ID token and check what TLS does not cover.
///
/// See the module documentation for why the signature is not verified here.
fn verify_id_token(id_token: &str, provider: &Provider, nonce: &str) -> Result<IdClaims> {
    let payload = id_token
        .split('.')
        .nth(1)
        .ok_or_else(|| AppError::internal("an id_token was not a JWT"))?;

    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| AppError::internal("an id_token payload was not base64url"))?;

    let claims: IdClaims = serde_json::from_slice(&bytes)
        .map_err(|_| AppError::internal("an id_token payload was not JSON"))?;

    let refuse = |what: &str| {
        tracing::warn!(provider = %provider.alias, %what, "an id_token was refused");
        AppError::Unauthenticated
    };

    // `iss` must be the provider we configured, not merely *a* provider. This
    // is the check that stops a token from somebody else's tenant.
    if let Some(expected) = &provider.issuer {
        let issued_by = claims.get("iss").and_then(serde_json::Value::as_str);
        if issued_by != Some(expected.as_str()) {
            return Err(refuse("iss"));
        }
    }

    // `aud` must contain our client id. A token minted for a different client
    // of the same provider is not ours to accept.
    let audience_ok = match claims.get("aud") {
        Some(serde_json::Value::String(one)) => one == &provider.client_id,
        Some(serde_json::Value::Array(many)) => many
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|value| value == provider.client_id),
        _ => false,
    };
    if !audience_ok {
        return Err(refuse("aud"));
    }

    if let Some(expiry) = claims.get("exp").and_then(serde_json::Value::as_i64)
        && expiry <= OffsetDateTime::now_utc().unix_timestamp()
    {
        return Err(refuse("exp"));
    }

    // The nonce ties this token to this sign-in. Compared only when the
    // provider echoed one, and demanded whenever we sent one.
    if provider.kind != Kind::GitHub {
        let echoed = claims.get("nonce").and_then(serde_json::Value::as_str);
        if echoed != Some(nonce) {
            return Err(refuse("nonce"));
        }
    }

    Ok(claims)
}

/// Turn whatever this provider returned into one shape.
///
/// The endpoints are configuration; *this* is what genuinely differs between
/// providers, and it is why `Kind` exists.
fn read_claims(
    kind: Kind,
    id_claims: Option<&IdClaims>,
    userinfo: Option<&serde_json::Value>,
) -> Result<Claims> {
    let from_id = |name: &str| id_claims.and_then(|claims| claims.get(name)).cloned();
    let from_userinfo = |name: &str| userinfo.and_then(|value| value.get(name)).cloned();
    let either = |name: &str| from_id(name).or_else(|| from_userinfo(name));

    let string = |value: Option<serde_json::Value>| {
        value.and_then(|value| match value {
            serde_json::Value::String(text) => Some(text),
            // GitHub's user id is a number, and Facebook's is a string of
            // digits. Both are the subject; neither is negotiable.
            serde_json::Value::Number(number) => Some(number.to_string()),
            _ => None,
        })
    };

    let subject = match kind {
        // GitHub has no `sub`; its stable identifier is the numeric `id`.
        // `login` is not it — a user can rename themselves, and the name is
        // then available to somebody else.
        Kind::GitHub => string(from_userinfo("id")),
        _ => string(either("sub")).or_else(|| string(from_userinfo("id"))),
    }
    .ok_or_else(|| AppError::internal("a provider returned no subject"))?;

    let email = string(either("email"));

    let email_verified = match kind {
        // Overwritten by the `/user/emails` call in `complete`. Never trusted
        // from the profile.
        Kind::GitHub => false,
        // Facebook only returns an address it has confirmed.
        Kind::Facebook => email.is_some(),
        // Apple sends `email_verified` as a bool in some responses and the
        // string "true" in others. Both mean the same thing, and reading only
        // the bool would silently downgrade half of them.
        _ => match either("email_verified") {
            Some(serde_json::Value::Bool(value)) => value,
            Some(serde_json::Value::String(value)) => value == "true",
            _ => false,
        },
    };

    Ok(Claims {
        subject,
        email,
        email_verified,
        name: string(either("name")),
        preferred_username: string(either("preferred_username"))
            .or_else(|| string(from_userinfo("login"))),
    })
}

/// The primary, verified address from GitHub's `/user/emails`.
fn primary_verified_email(emails: &serde_json::Value) -> Option<String> {
    let list = emails.as_array()?;
    // Primary and verified, or failing that any verified one. An unverified
    // address is never returned, whatever its flags say.
    let verified = |entry: &&serde_json::Value| {
        entry.get("verified").and_then(serde_json::Value::as_bool) == Some(true)
    };
    list.iter()
        .filter(verified)
        .find(|entry| entry.get("primary").and_then(serde_json::Value::as_bool) == Some(true))
        .or_else(|| list.iter().find(verified))
        .and_then(|entry| entry.get("email").and_then(serde_json::Value::as_str))
        .map(ToOwned::to_owned)
}

// ---------------------------------------------------------------------------
// URL building
// ---------------------------------------------------------------------------

/// Percent-encode a query parameter value.
fn urlencode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// Append a query string, respecting an endpoint that already has one.
fn form_urlencoded_url(endpoint: &str, params: &[(&str, &str)]) -> String {
    let query: String = params
        .iter()
        .map(|(key, value)| format!("{key}={}", urlencode(value)))
        .collect::<Vec<_>>()
        .join("&");

    let separator = if endpoint.contains('?') { '&' } else { '?' };
    format!("{endpoint}{separator}{query}")
}

// ---------------------------------------------------------------------------
// The real transport
// ---------------------------------------------------------------------------

/// [`Transport`] over the network.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    client: reqwest::Client,
}

impl HttpTransport {
    /// Build one.
    ///
    /// # Errors
    ///
    /// Returns an internal error if the HTTP client cannot be constructed.
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            // A provider that hangs must not hold a request open indefinitely.
            .timeout(std::time::Duration::from_secs(15))
            .connect_timeout(std::time::Duration::from_secs(5))
            // Redirects are off: a token endpoint does not redirect, and
            // following one would send the client secret somewhere else.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("authenc/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| AppError::internal_from("building an HTTP client", e))?;

        Ok(Self { client })
    }
}

#[async_trait::async_trait]
impl Transport for HttpTransport {
    async fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> Result<serde_json::Value> {
        let mut request = self
            .client
            .post(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .form(form);

        if let Some((id, secret)) = basic {
            request = request.basic_auth(id, Some(secret));
        }

        let response = request.send().await.map_err(|e| {
            // The provider's URL can appear in this error; the client secret
            // never does, because it is in the body rather than the URL.
            AppError::internal_from("calling a provider's token endpoint", e)
        })?;

        response
            .json()
            .await
            .map_err(|e| AppError::internal_from("reading a provider's token response", e))
    }

    async fn get_json(&self, url: &str, bearer: &str) -> Result<serde_json::Value> {
        let response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .bearer_auth(bearer)
            .send()
            .await
            .map_err(|e| AppError::internal_from("calling a provider's userinfo endpoint", e))?;

        response
            .json()
            .await
            .map_err(|e| AppError::internal_from("reading a provider's userinfo response", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenc_identity::{
        MasterKey,
        federation::{self, NewProvider},
        realm,
    };
    use std::sync::Mutex;

    /// A URL and the form that was posted to it.
    type PostedForm = (String, Vec<(String, String)>);

    /// A [`Transport`] that returns what it was told to, and records what it
    /// was asked. Enough to exercise every rule that is ours; the network's
    /// own behaviour is not what these tests are about.
    struct Canned {
        token: serde_json::Value,
        userinfo: serde_json::Value,
        emails: serde_json::Value,
        posted: Mutex<Vec<PostedForm>>,
        fetched: Mutex<Vec<String>>,
    }

    impl Canned {
        fn new(token: serde_json::Value, userinfo: serde_json::Value) -> Self {
            Self {
                token,
                userinfo,
                emails: serde_json::json!([]),
                posted: Mutex::new(Vec::new()),
                fetched: Mutex::new(Vec::new()),
            }
        }

        fn with_emails(mut self, emails: serde_json::Value) -> Self {
            self.emails = emails;
            self
        }

        fn form_value(&self, key: &str) -> Option<String> {
            self.posted.lock().unwrap().first().and_then(|(_, form)| {
                form.iter()
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| value.clone())
            })
        }
    }

    #[async_trait::async_trait]
    impl Transport for Canned {
        async fn post_form(
            &self,
            url: &str,
            form: &[(&str, &str)],
            _basic: Option<(&str, &str)>,
        ) -> Result<serde_json::Value> {
            self.posted.lock().unwrap().push((
                url.to_owned(),
                form.iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
            ));
            Ok(self.token.clone())
        }

        async fn get_json(&self, url: &str, _bearer: &str) -> Result<serde_json::Value> {
            self.fetched.lock().unwrap().push(url.to_owned());
            if url.ends_with("/user/emails") {
                Ok(self.emails.clone())
            } else {
                Ok(self.userinfo.clone())
            }
        }
    }

    /// An unsigned JWT carrying these claims. The signature is not read — see
    /// the module documentation — so producing one is a base64 encode.
    fn id_token(claims: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        format!("{header}.{payload}.not-verified")
    }

    async fn provider_of(db: &Db, kind: Kind, issuer: Option<&str>) -> Provider {
        let realm = realm::create(db, "acme", "Acme").await.unwrap();
        federation::create(
            db,
            &MasterKey::generate().unwrap(),
            NewProvider {
                realm_id: realm.id,
                alias: "upstream",
                kind,
                display_name: "Upstream",
                client_id: "our-client-id",
                client_secret: "our-client-secret",
                authorization_endpoint: "https://provider.example/authorize",
                token_endpoint: "https://provider.example/token",
                userinfo_endpoint: Some("https://provider.example/userinfo"),
                issuer: issuer.map(ToOwned::to_owned).as_deref(),
                scopes: &["openid".to_owned(), "email".to_owned()],
                allow_provisioning: true,
                link_by_verified_email: false,
            },
        )
        .await
        .unwrap()
    }

    #[test]
    fn a_query_string_is_appended_to_an_endpoint_that_already_has_one() {
        assert_eq!(
            form_urlencoded_url("https://p.example/a?tenant=x", &[("state", "s")]),
            "https://p.example/a?tenant=x&state=s"
        );
        assert_eq!(
            form_urlencoded_url("https://p.example/a", &[("state", "s")]),
            "https://p.example/a?state=s"
        );
    }

    #[test]
    fn parameters_are_percent_encoded() {
        // A redirect URI contains `://` and `/`, and an unencoded one silently
        // truncates the query at the provider.
        let url = form_urlencoded_url(
            "https://p.example/a",
            &[("redirect_uri", "https://us.example/cb?x=1")],
        );
        assert!(
            url.contains("https%3A%2F%2Fus.example%2Fcb%3Fx%3D1"),
            "{url}"
        );
    }

    #[test]
    fn githubs_verified_address_is_the_primary_one() {
        let emails = serde_json::json!([
            { "email": "public@example.com", "primary": false, "verified": false },
            { "email": "real@example.com",   "primary": true,  "verified": true },
        ]);
        assert_eq!(
            primary_verified_email(&emails).as_deref(),
            Some("real@example.com")
        );
    }

    #[test]
    fn an_unverified_github_address_is_never_returned() {
        let emails = serde_json::json!([
            { "email": "typed-in@example.com", "primary": true, "verified": false },
        ]);
        assert_eq!(primary_verified_email(&emails), None);
    }

    #[test]
    fn apple_sends_email_verified_as_a_string_and_it_still_counts() {
        // Reading only the boolean would mark half of Apple's responses
        // unverified, which quietly disables adoption for those users.
        let claims = serde_json::from_str::<IdClaims>(
            r#"{"sub":"apple-1","email":"a@example.com","email_verified":"true"}"#,
        )
        .unwrap();

        let read = read_claims(Kind::Apple, Some(&claims), None).unwrap();
        assert!(read.email_verified);
    }

    #[test]
    fn a_boolean_email_verified_is_read_the_same_way() {
        let claims = serde_json::from_str::<IdClaims>(
            r#"{"sub":"g-1","email":"a@example.com","email_verified":true}"#,
        )
        .unwrap();
        assert!(
            read_claims(Kind::Google, Some(&claims), None)
                .unwrap()
                .email_verified
        );
    }

    #[test]
    fn a_missing_email_verified_means_unverified() {
        let claims =
            serde_json::from_str::<IdClaims>(r#"{"sub":"g-1","email":"a@example.com"}"#).unwrap();
        assert!(
            !read_claims(Kind::Google, Some(&claims), None)
                .unwrap()
                .email_verified
        );
    }

    #[test]
    fn githubs_numeric_id_is_the_subject_and_the_login_name_is_not() {
        // A GitHub user can rename themselves, and the old name becomes
        // available to somebody else. Keying on it would hand over the account.
        let userinfo = serde_json::json!({ "id": 4210, "login": "alice", "name": "Alice" });
        let claims = read_claims(Kind::GitHub, None, Some(&userinfo)).unwrap();

        assert_eq!(claims.subject, "4210");
        assert_eq!(claims.preferred_username.as_deref(), Some("alice"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_state_is_single_use(db: Db) {
        let provider = provider_of(&db, Kind::Google, None).await;
        let started = begin(&db, &provider, "https://us.example/cb", None)
            .await
            .unwrap();

        assert!(claim_state(&db, &started.state).await.is_ok());
        assert!(
            claim_state(&db, &started.state).await.is_err(),
            "a replayed state must not complete a second sign-in"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unknown_state_is_refused(db: Db) {
        provider_of(&db, Kind::Google, None).await;
        let invented = SecretToken::generate().unwrap();

        assert!(claim_state(&db, &invented).await.is_err());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_authorization_url_carries_pkce_and_a_nonce(db: Db) {
        let provider = provider_of(&db, Kind::Google, None).await;
        let started = begin(&db, &provider, "https://us.example/cb", None)
            .await
            .unwrap();
        let url = &started.authorization_url;

        assert!(
            url.starts_with("https://provider.example/authorize?"),
            "{url}"
        );
        assert!(url.contains("code_challenge_method=S256"), "{url}");
        assert!(url.contains("code_challenge="), "{url}");
        assert!(url.contains("nonce="), "{url}");
        assert!(url.contains("client_id=our-client-id"), "{url}");
        // The verifier itself must never reach the browser.
        let pending = claim_state(&db, &started.state).await.unwrap();
        assert!(
            !url.contains(&pending.verifier),
            "the verifier leaked into the URL"
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn github_is_not_sent_a_nonce_it_would_reject(db: Db) {
        let provider = provider_of(&db, Kind::GitHub, None).await;
        let started = begin(&db, &provider, "https://us.example/cb", None)
            .await
            .unwrap();

        assert!(!started.authorization_url.contains("nonce="));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_return_to_that_leaves_this_site_is_refused(db: Db) {
        let provider = provider_of(&db, Kind::Google, None).await;

        for hostile in [
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "/\t/evil.example",
            "evil",
        ] {
            let refused = begin(&db, &provider, "https://us.example/cb", Some(hostile)).await;
            assert!(refused.is_err(), "{hostile} was accepted as a return path");
        }

        assert!(
            begin(
                &db,
                &provider,
                "https://us.example/cb",
                Some("/admin/users")
            )
            .await
            .is_ok()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_complete_exchange_reads_the_claims(db: Db) {
        let provider = provider_of(&db, Kind::Google, Some("https://provider.example")).await;
        let started = begin(&db, &provider, "https://us.example/cb", None)
            .await
            .unwrap();
        let pending = claim_state(&db, &started.state).await.unwrap();

        let transport = Canned::new(
            serde_json::json!({
                "access_token": "at",
                "id_token": id_token(serde_json::json!({
                    "iss": "https://provider.example",
                    "aud": "our-client-id",
                    "sub": "upstream-1",
                    "nonce": pending.nonce,
                    "email": "alice@example.com",
                    "email_verified": true,
                    "name": "Alice Example",
                })),
            }),
            serde_json::json!({}),
        );

        let claims = complete(
            &transport,
            &provider,
            "our-client-secret",
            &pending,
            "the-code",
        )
        .await
        .unwrap();

        assert_eq!(claims.subject, "upstream-1");
        assert_eq!(claims.email.as_deref(), Some("alice@example.com"));
        assert!(claims.email_verified);

        // The verifier is proved, and the redirect URI replayed verbatim.
        assert_eq!(
            transport.form_value("code_verifier"),
            Some(pending.verifier)
        );
        assert_eq!(
            transport.form_value("redirect_uri").as_deref(),
            Some("https://us.example/cb")
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_id_token_for_another_client_is_refused(db: Db) {
        let provider = provider_of(&db, Kind::Google, Some("https://provider.example")).await;
        let started = begin(&db, &provider, "https://us.example/cb", None)
            .await
            .unwrap();
        let pending = claim_state(&db, &started.state).await.unwrap();

        let transport = Canned::new(
            serde_json::json!({
                "access_token": "at",
                "id_token": id_token(serde_json::json!({
                    "iss": "https://provider.example",
                    "aud": "somebody-elses-client",
                    "sub": "upstream-1",
                    "nonce": pending.nonce,
                })),
            }),
            serde_json::json!({}),
        );

        assert!(
            complete(&transport, &provider, "s", &pending, "code")
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_id_token_from_another_issuer_is_refused(db: Db) {
        let provider = provider_of(&db, Kind::Google, Some("https://provider.example")).await;
        let started = begin(&db, &provider, "https://us.example/cb", None)
            .await
            .unwrap();
        let pending = claim_state(&db, &started.state).await.unwrap();

        let transport = Canned::new(
            serde_json::json!({
                "access_token": "at",
                "id_token": id_token(serde_json::json!({
                    "iss": "https://attacker.example",
                    "aud": "our-client-id",
                    "sub": "upstream-1",
                    "nonce": pending.nonce,
                })),
            }),
            serde_json::json!({}),
        );

        assert!(
            complete(&transport, &provider, "s", &pending, "code")
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_id_token_with_the_wrong_nonce_is_refused(db: Db) {
        // The replay this defends against: a token the attacker obtained for
        // their own sign-in, presented into somebody else's callback.
        let provider = provider_of(&db, Kind::Google, Some("https://provider.example")).await;
        let started = begin(&db, &provider, "https://us.example/cb", None)
            .await
            .unwrap();
        let pending = claim_state(&db, &started.state).await.unwrap();

        let transport = Canned::new(
            serde_json::json!({
                "access_token": "at",
                "id_token": id_token(serde_json::json!({
                    "iss": "https://provider.example",
                    "aud": "our-client-id",
                    "sub": "upstream-1",
                    "nonce": "a nonce from another sign-in",
                })),
            }),
            serde_json::json!({}),
        );

        assert!(
            complete(&transport, &provider, "s", &pending, "code")
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_expired_id_token_is_refused(db: Db) {
        let provider = provider_of(&db, Kind::Google, Some("https://provider.example")).await;
        let started = begin(&db, &provider, "https://us.example/cb", None)
            .await
            .unwrap();
        let pending = claim_state(&db, &started.state).await.unwrap();

        let transport = Canned::new(
            serde_json::json!({
                "access_token": "at",
                "id_token": id_token(serde_json::json!({
                    "iss": "https://provider.example",
                    "aud": "our-client-id",
                    "sub": "upstream-1",
                    "nonce": pending.nonce,
                    "exp": 1_000_000_000,
                })),
            }),
            serde_json::json!({}),
        );

        assert!(
            complete(&transport, &provider, "s", &pending, "code")
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_refused_exchange_is_not_a_sign_in(db: Db) {
        let provider = provider_of(&db, Kind::Google, None).await;
        let started = begin(&db, &provider, "https://us.example/cb", None)
            .await
            .unwrap();
        let pending = claim_state(&db, &started.state).await.unwrap();

        let transport = Canned::new(
            serde_json::json!({ "error": "invalid_grant" }),
            serde_json::json!({}),
        );

        assert!(
            complete(&transport, &provider, "s", &pending, "code")
                .await
                .is_err()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn github_takes_its_address_from_the_verified_list(db: Db) {
        let provider = provider_of(&db, Kind::GitHub, None).await;
        let started = begin(&db, &provider, "https://us.example/cb", None)
            .await
            .unwrap();
        let pending = claim_state(&db, &started.state).await.unwrap();

        let transport = Canned::new(
            serde_json::json!({ "access_token": "at" }),
            // The profile address, which GitHub does not check.
            serde_json::json!({ "id": 4210, "login": "alice", "email": "typed-in@example.com" }),
        )
        .with_emails(serde_json::json!([
            { "email": "real@example.com", "primary": true, "verified": true },
        ]));

        let claims = complete(&transport, &provider, "s", &pending, "code")
            .await
            .unwrap();

        assert_eq!(claims.email.as_deref(), Some("real@example.com"));
        assert!(claims.email_verified);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_github_account_with_no_verified_address_is_not_verified(db: Db) {
        let provider = provider_of(&db, Kind::GitHub, None).await;
        let started = begin(&db, &provider, "https://us.example/cb", None)
            .await
            .unwrap();
        let pending = claim_state(&db, &started.state).await.unwrap();

        let transport = Canned::new(
            serde_json::json!({ "access_token": "at" }),
            serde_json::json!({ "id": 4210, "login": "alice", "email": "typed-in@example.com" }),
        )
        .with_emails(serde_json::json!([
            { "email": "typed-in@example.com", "primary": true, "verified": false },
        ]));

        let claims = complete(&transport, &provider, "s", &pending, "code")
            .await
            .unwrap();

        assert!(
            !claims.email_verified,
            "an address GitHub has not checked must not be reported as verified"
        );
    }
}
