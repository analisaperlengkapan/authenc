//! Registered clients: registration, lookup, and authentication.
//!
//! Three properties this module exists to hold, each of which the previous
//! implementation got wrong:
//!
//! * **Secrets are hashed.** The old store had a column called
//!   `client_secret_hash` and wrote the plaintext into it.
//! * **Redirect URIs are an exact-match allow-list.** The old authorize
//!   endpoint redirected to whatever the caller supplied. Prefix or wildcard
//!   matching is not offered here, because both are routinely bypassed —
//!   `https://good.example.com.attacker.test/` has the registered prefix.
//! * **A public client can never hold a secret**, and a confidential one can
//!   never be authenticated without presenting it. The database enforces the
//!   first half with a check constraint; [`authenticate`] enforces the second.

use authenc_contract::{AppError, RealmId, Result};
use authenc_identity::{Db, PasswordHasher, SecretToken};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::OAuthError;

/// The database identity of a registered client.
///
/// Distinct from `client_id`, which is the string the protocol carries. Both
/// are "the client's id" in conversation, which is precisely why they get
/// different types here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClientKey(pub Uuid);

/// Grant types a client may be registered for.
pub const GRANT_AUTHORIZATION_CODE: &str = "authorization_code";
/// Refresh-token grant.
pub const GRANT_REFRESH_TOKEN: &str = "refresh_token";

/// Every grant type this server implements.
pub const SUPPORTED_GRANTS: &[&str] = &[GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN];

/// A registered client, as every other module sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Client {
    /// Database identity.
    pub key: ClientKey,
    /// The realm it belongs to.
    pub realm_id: RealmId,
    /// The `client_id` carried in protocol messages.
    pub client_id: String,
    /// Display name, shown on the consent screen.
    pub name: String,
    /// Whether it is a public client (no secret, PKCE required).
    pub is_public: bool,
    /// Exact redirect URIs it may be sent to.
    pub redirect_uris: Vec<String>,
    /// Grant types it may use.
    pub grant_types: Vec<String>,
    /// The widest scope set it may request.
    pub scopes: Vec<String>,
    /// Whether the user must approve each new scope set.
    pub require_consent: bool,
}

impl Client {
    /// Whether a redirect URI is on this client's allow-list.
    ///
    /// Exact string comparison, deliberately. See the module docs.
    #[must_use]
    pub fn allows_redirect(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|allowed| allowed == uri)
    }

    /// Whether this client may use a grant type.
    #[must_use]
    pub fn allows_grant(&self, grant: &str) -> bool {
        self.grant_types.iter().any(|allowed| allowed == grant)
    }

    /// Whether PKCE is mandatory for this client.
    ///
    /// Always true for a public client, which has no other way to prove that
    /// the party redeeming the code is the party that requested it.
    #[must_use]
    pub const fn requires_pkce(&self) -> bool {
        self.is_public
    }
}

/// What a caller supplies to register a client.
#[derive(Debug, Clone)]
pub struct NewClient<'a> {
    /// Realm the client belongs to.
    pub realm_id: RealmId,
    /// Requested `client_id`. Generated when `None`.
    pub client_id: Option<&'a str>,
    /// Display name.
    pub name: &'a str,
    /// Whether it is a public client.
    pub is_public: bool,
    /// Redirect URIs. At least one is required.
    pub redirect_uris: &'a [String],
    /// Grant types. Defaults to code + refresh when empty.
    pub grant_types: &'a [String],
    /// Scopes it may request. Defaults to `openid profile email` when empty.
    pub scopes: &'a [String],
    /// Whether to ask the user before issuing.
    pub require_consent: bool,
}

/// A freshly registered client, with the one and only sight of its secret.
#[derive(Debug)]
pub struct Registered {
    /// The stored record.
    pub client: Client,
    /// The generated secret, `None` for a public client. Never recoverable
    /// afterwards — only its hash is stored.
    pub client_secret: Option<SecretToken>,
}

/// Register a client.
///
/// # Errors
///
/// Returns a protocol error if the metadata is unacceptable (RFC 7591 §3.2.2
/// calls this `invalid_client_metadata`), or a `server_error` if the write
/// fails.
pub async fn register(
    db: &Db,
    hasher: &PasswordHasher,
    new: NewClient<'_>,
) -> std::result::Result<Registered, OAuthError> {
    if new.name.trim().is_empty() {
        return Err(OAuthError::invalid_client_metadata(
            "client_name must not be empty",
        ));
    }
    if new.redirect_uris.is_empty() {
        return Err(OAuthError::invalid_client_metadata(
            "at least one redirect_uri is required",
        ));
    }
    for uri in new.redirect_uris {
        validate_redirect_uri(uri)?;
    }

    let grant_types: Vec<String> = if new.grant_types.is_empty() {
        SUPPORTED_GRANTS.iter().map(|g| (*g).to_owned()).collect()
    } else {
        for grant in new.grant_types {
            if !SUPPORTED_GRANTS.contains(&grant.as_str()) {
                return Err(OAuthError::invalid_client_metadata(format!(
                    "grant type '{grant}' is not supported"
                )));
            }
        }
        new.grant_types.to_vec()
    };

    let scopes: Vec<String> = if new.scopes.is_empty() {
        [
            crate::scope::OPENID,
            crate::scope::PROFILE,
            crate::scope::EMAIL,
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
    } else {
        new.scopes.to_vec()
    };

    let client_id = match new.client_id {
        Some(value) => {
            validate_client_id(value)?;
            value.to_owned()
        }
        None => Uuid::new_v4().to_string(),
    };

    // A public client is issued no secret at all. Issuing one and then
    // ignoring it — the shape the previous code had — leaves an unusable
    // credential in the operator's hands and in the database.
    let (secret, phc) = if new.is_public {
        (None, None)
    } else {
        let secret = SecretToken::generate()
            .map_err(|e| AppError::internal_from("generating client secret", e))?;
        // Argon2 at login parameters. The secret is 256 bits of our own
        // entropy, so the work factor is not what stops a guess — it is
        // defence for the case where an operator later imports a chosen
        // secret, and it keeps one hashing configuration in the system
        // instead of two.
        let phc = hasher.hash(secret.expose())?;
        (Some(secret), Some(phc))
    };

    let row = sqlx::query!(
        r#"
        INSERT INTO oauth_clients
            (realm_id, client_id, client_secret_phc, name, is_public,
             redirect_uris, grant_types, scopes, require_consent)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
        new.realm_id.0,
        client_id,
        phc.as_deref(),
        new.name,
        new.is_public,
        new.redirect_uris,
        &grant_types,
        &scopes,
        new.require_consent,
    )
    .fetch_one(db)
    .await
    .map_err(|e| match e {
        // RFC 7591 §3.2.2 has no "already registered" code; a `client_id` the
        // server cannot accept is metadata the server cannot accept.
        sqlx::Error::Database(ref db_error) if db_error.is_unique_violation() => {
            OAuthError::invalid_client_metadata(format!(
                "client_id '{client_id}' is already registered in this realm"
            ))
        }
        other => AppError::internal_from("registering client", other).into(),
    })?;

    Ok(Registered {
        client: Client {
            key: ClientKey(row.id),
            realm_id: new.realm_id,
            client_id,
            name: new.name.to_owned(),
            is_public: new.is_public,
            redirect_uris: new.redirect_uris.to_vec(),
            grant_types,
            scopes,
            require_consent: new.require_consent,
        },
        client_secret: secret,
    })
}

/// Look a client up by the `client_id` it presents.
///
/// # Errors
///
/// Returns [`AppError::NotFound`] if there is no such client in that realm.
pub async fn by_client_id(db: &Db, realm_id: RealmId, client_id: &str) -> Result<Client> {
    let row = sqlx::query!(
        r#"
        SELECT id, client_id, name, is_public, redirect_uris,
               grant_types, scopes, require_consent
        FROM oauth_clients
        WHERE realm_id = $1 AND client_id = $2
        "#,
        realm_id.0,
        client_id,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading client", e))?
    .ok_or(AppError::NotFound("client"))?;

    Ok(Client {
        key: ClientKey(row.id),
        realm_id,
        client_id: row.client_id,
        name: row.name,
        is_public: row.is_public,
        redirect_uris: row.redirect_uris,
        grant_types: row.grant_types,
        scopes: row.scopes,
        require_consent: row.require_consent,
    })
}

/// Every client registered in a realm.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn list(db: &Db, realm_id: RealmId) -> Result<Vec<Client>> {
    let rows = sqlx::query!(
        r#"
        SELECT id, client_id, name, is_public, redirect_uris,
               grant_types, scopes, require_consent
        FROM oauth_clients
        WHERE realm_id = $1
        ORDER BY name
        "#,
        realm_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("listing clients", e))?;

    Ok(rows
        .into_iter()
        .map(|row| Client {
            key: ClientKey(row.id),
            realm_id,
            client_id: row.client_id,
            name: row.name,
            is_public: row.is_public,
            redirect_uris: row.redirect_uris,
            grant_types: row.grant_types,
            scopes: row.scopes,
            require_consent: row.require_consent,
        })
        .collect())
}

/// What may be changed about a registered client.
///
/// `None` leaves a field alone; `Some` **replaces** it. Replacing rather than
/// merging is deliberate for `redirect_uris`: withdrawing one is the operation
/// an incident actually needs, and a merge would make it impossible here.
#[derive(Debug, Clone, Default)]
pub struct Changes<'a> {
    /// New exact redirect URIs.
    pub redirect_uris: Option<&'a [String]>,
    /// New scope allow-list.
    pub scopes: Option<&'a [String]>,
    /// Whether to ask the user before issuing.
    pub require_consent: Option<bool>,
}

/// Apply changes to a registered client.
///
/// # Errors
///
/// Returns `invalid_redirect_uri` for a URI this server will not register, or
/// `server_error` if the write fails.
pub async fn update(
    db: &Db,
    client: &Client,
    changes: Changes<'_>,
) -> std::result::Result<Client, OAuthError> {
    if let Some(uris) = changes.redirect_uris {
        if uris.is_empty() {
            return Err(OAuthError::invalid_client_metadata(
                "at least one redirect_uri is required",
            ));
        }
        for uri in uris {
            validate_redirect_uri(uri)?;
        }
    }

    let row = sqlx::query!(
        r#"
        UPDATE oauth_clients
        SET redirect_uris   = COALESCE($2, redirect_uris),
            scopes          = COALESCE($3, scopes),
            require_consent = COALESCE($4, require_consent)
        WHERE id = $1
        RETURNING client_id, name, is_public, redirect_uris,
                  grant_types, scopes, require_consent
        "#,
        client.key.0,
        changes.redirect_uris,
        changes.scopes,
        changes.require_consent,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("updating client", e))?
    .ok_or(AppError::NotFound("client"))?;

    Ok(Client {
        key: client.key,
        realm_id: client.realm_id,
        client_id: row.client_id,
        name: row.name,
        is_public: row.is_public,
        redirect_uris: row.redirect_uris,
        grant_types: row.grant_types,
        scopes: row.scopes,
        require_consent: row.require_consent,
    })
}

/// Replace a confidential client's secret, returning the new one.
///
/// Tokens the client already holds keep working; what stops working is
/// authenticating at the token endpoint with the old secret. That is the point:
/// a leaked secret is replaced without cutting off live sessions.
///
/// # Errors
///
/// Returns [`AppError::Validation`] for a public client, which has no secret to
/// rotate, and [`AppError::NotFound`] if the row has since been deleted.
pub async fn rotate_secret(
    db: &Db,
    hasher: &PasswordHasher,
    client: &Client,
) -> Result<SecretToken> {
    if client.is_public {
        return Err(AppError::validation(
            "a public client holds no secret; it authenticates with PKCE",
        ));
    }

    let secret = SecretToken::generate()
        .map_err(|e| AppError::internal_from("generating client secret", e))?;
    let phc = hasher.hash(secret.expose())?;

    let affected = sqlx::query!(
        "UPDATE oauth_clients SET client_secret_phc = $2 WHERE id = $1 AND NOT is_public",
        client.key.0,
        phc,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("rotating client secret", e))?
    .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound("client"));
    }

    Ok(secret)
}

/// Delete a client, and with it every code, token, and consent it holds.
///
/// # Errors
///
/// Returns [`AppError::NotFound`] if no such client exists.
pub async fn delete(db: &Db, realm_id: RealmId, client_id: &str) -> Result<()> {
    let affected = sqlx::query!(
        "DELETE FROM oauth_clients WHERE realm_id = $1 AND client_id = $2",
        realm_id.0,
        client_id,
    )
    .execute(db)
    .await
    .map_err(|e| AppError::internal_from("deleting client", e))?
    .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound("client"));
    }
    Ok(())
}

/// The credentials a client presented at the token endpoint.
#[derive(Debug, Clone)]
pub struct Credentials {
    /// The `client_id`, from `Authorization: Basic`, the body, or PKCE-only.
    pub client_id: String,
    /// The secret, absent for a public client.
    pub secret: Option<String>,
}

/// Authenticate a client.
///
/// # Errors
///
/// Returns `invalid_client` for an unknown client, a missing secret on a
/// confidential client, a wrong secret, or a secret presented by a public
/// client. All four produce the same code and the same status: distinguishing
/// them tells an attacker which client ids exist.
pub async fn authenticate(
    db: &Db,
    hasher: &PasswordHasher,
    realm_id: RealmId,
    presented: &Credentials,
) -> std::result::Result<Client, OAuthError> {
    let row = sqlx::query!(
        r#"
        SELECT id, client_id, client_secret_phc, name, is_public,
               redirect_uris, grant_types, scopes, require_consent
        FROM oauth_clients
        WHERE realm_id = $1 AND client_id = $2
        "#,
        realm_id.0,
        presented.client_id,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading client for authentication", e))?;

    let Some(row) = row else {
        return Err(OAuthError::invalid_client("client authentication failed"));
    };

    match (
        row.client_secret_phc.as_deref(),
        presented.secret.as_deref(),
    ) {
        // Public client, authenticating by PKCE alone.
        (None, None) => {}
        // A public client that sent a secret is either misconfigured or an
        // impersonation attempt. Either way it is not authenticated.
        (None, Some(_)) => {
            return Err(OAuthError::invalid_client("client authentication failed"));
        }
        (Some(_), None) => {
            return Err(OAuthError::invalid_client("client authentication failed"));
        }
        (Some(stored), Some(offered)) => {
            if !hasher.verify(offered, stored)? {
                return Err(OAuthError::invalid_client("client authentication failed"));
            }
        }
    }

    Ok(Client {
        key: ClientKey(row.id),
        realm_id,
        client_id: row.client_id,
        name: row.name,
        is_public: row.is_public,
        redirect_uris: row.redirect_uris,
        grant_types: row.grant_types,
        scopes: row.scopes,
        require_consent: row.require_consent,
    })
}

/// Reject a redirect URI this server will not register.
///
/// # Errors
///
/// Returns `invalid_redirect_uri` describing what is wrong.
pub fn validate_redirect_uri(uri: &str) -> std::result::Result<(), OAuthError> {
    if uri.trim() != uri || uri.is_empty() {
        return Err(OAuthError::invalid_redirect_uri(
            "redirect_uri must not be empty or padded with whitespace",
        ));
    }
    // RFC 6749 §3.1.2: absolute URI, no fragment. A relative URI would be
    // resolved against whatever page the browser happens to be on.
    let Some((scheme, rest)) = uri.split_once(':') else {
        return Err(OAuthError::invalid_redirect_uri(
            "redirect_uri must be an absolute URI",
        ));
    };
    if scheme.is_empty()
        || !scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return Err(OAuthError::invalid_redirect_uri(
            "redirect_uri must begin with a valid URI scheme",
        ));
    }
    if rest.is_empty() {
        return Err(OAuthError::invalid_redirect_uri(
            "redirect_uri must have a target after the scheme",
        ));
    }
    if uri.contains('#') {
        return Err(OAuthError::invalid_redirect_uri(
            "redirect_uri must not contain a fragment",
        ));
    }
    // A wildcard cannot be matched exactly, so registering one would only ever
    // produce a URI that never matches — better to say so at registration.
    if uri.contains('*') {
        return Err(OAuthError::invalid_redirect_uri(
            "redirect_uri must be exact; wildcards are not supported",
        ));
    }
    if scheme.eq_ignore_ascii_case("javascript") || scheme.eq_ignore_ascii_case("data") {
        return Err(OAuthError::invalid_redirect_uri(
            "redirect_uri scheme is not allowed",
        ));
    }
    Ok(())
}

fn validate_client_id(value: &str) -> std::result::Result<(), OAuthError> {
    if value.is_empty() || value.len() > 128 {
        return Err(OAuthError::invalid_client_metadata(
            "client_id must be between 1 and 128 characters",
        ));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    {
        return Err(OAuthError::invalid_client_metadata(
            "client_id may contain only letters, digits, and '-._:'",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "a failed setup step should fail the test"
)]
mod tests {
    use super::*;
    use authenc_identity::realm;

    fn owned(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).to_owned()).collect()
    }

    async fn a_realm(db: &Db) -> RealmId {
        realm::create(db, "master", "Master").await.unwrap().id
    }

    fn confidential<'a>(realm_id: RealmId, uris: &'a [String]) -> NewClient<'a> {
        NewClient {
            realm_id,
            client_id: Some("console"),
            name: "Console",
            is_public: false,
            redirect_uris: uris,
            grant_types: &[],
            scopes: &[],
            require_consent: true,
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_confidential_client_gets_a_secret_that_is_not_stored_in_the_clear(db: Db) {
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://app.example.com/callback"]);

        let registered = register(&db, &hasher, confidential(realm_id, &uris))
            .await
            .unwrap();
        let secret = registered.client_secret.unwrap();

        let stored: Option<String> = sqlx::query_scalar!(
            "SELECT client_secret_phc FROM oauth_clients WHERE id = $1",
            registered.client.key.0,
        )
        .fetch_one(&db)
        .await
        .unwrap();

        let stored = stored.unwrap();
        assert!(
            !stored.contains(secret.expose()),
            "the secret itself must never reach the database",
        );
        assert!(stored.starts_with("$argon2id$"), "got: {stored}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_registered_secret_authenticates_and_a_wrong_one_does_not(db: Db) {
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://app.example.com/callback"]);

        let registered = register(&db, &hasher, confidential(realm_id, &uris))
            .await
            .unwrap();
        let secret = registered.client_secret.unwrap();

        let ok = authenticate(
            &db,
            &hasher,
            realm_id,
            &Credentials {
                client_id: "console".to_owned(),
                secret: Some(secret.expose().to_owned()),
            },
        )
        .await;
        assert!(ok.is_ok(), "{:?}", ok.err());

        let wrong = authenticate(
            &db,
            &hasher,
            realm_id,
            &Credentials {
                client_id: "console".to_owned(),
                secret: Some("not the secret".to_owned()),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(wrong.code, crate::error::OAuthErrorCode::InvalidClient);
        assert_eq!(wrong.status(), 401);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_confidential_client_cannot_authenticate_without_its_secret(db: Db) {
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://app.example.com/callback"]);
        register(&db, &hasher, confidential(realm_id, &uris))
            .await
            .unwrap();

        let error = authenticate(
            &db,
            &hasher,
            realm_id,
            &Credentials {
                client_id: "console".to_owned(),
                secret: None,
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, crate::error::OAuthErrorCode::InvalidClient);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_public_client_is_issued_no_secret_and_requires_pkce(db: Db) {
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["http://127.0.0.1:8080/callback"]);

        let registered = register(
            &db,
            &hasher,
            NewClient {
                client_id: Some("spa"),
                is_public: true,
                ..confidential(realm_id, &uris)
            },
        )
        .await
        .unwrap();

        assert!(registered.client_secret.is_none());
        assert!(registered.client.requires_pkce());

        // And presenting a secret it was never issued must not authenticate it.
        let error = authenticate(
            &db,
            &hasher,
            realm_id,
            &Credentials {
                client_id: "spa".to_owned(),
                secret: Some("anything".to_owned()),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, crate::error::OAuthErrorCode::InvalidClient);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unknown_client_fails_exactly_like_a_wrong_secret(db: Db) {
        // Same code, same status, same description: otherwise the endpoint
        // enumerates which client ids exist.
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://app.example.com/callback"]);
        let registered = register(&db, &hasher, confidential(realm_id, &uris))
            .await
            .unwrap();

        let unknown = authenticate(
            &db,
            &hasher,
            realm_id,
            &Credentials {
                client_id: "no-such-client".to_owned(),
                secret: Some("whatever".to_owned()),
            },
        )
        .await
        .unwrap_err();

        let wrong_secret = authenticate(
            &db,
            &hasher,
            realm_id,
            &Credentials {
                client_id: registered.client.client_id.clone(),
                secret: Some("whatever".to_owned()),
            },
        )
        .await
        .unwrap_err();

        assert_eq!(unknown.code, wrong_secret.code);
        assert_eq!(unknown.description, wrong_secret.description);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn clients_in_one_realm_are_invisible_to_another(db: Db) {
        let master = a_realm(&db).await;
        let other = realm::create(&db, "other", "Other").await.unwrap().id;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://app.example.com/callback"]);

        let registered = register(&db, &hasher, confidential(master, &uris))
            .await
            .unwrap();
        let secret = registered.client_secret.unwrap();

        let error = authenticate(
            &db,
            &hasher,
            other,
            &Credentials {
                client_id: "console".to_owned(),
                secret: Some(secret.expose().to_owned()),
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, crate::error::OAuthErrorCode::InvalidClient);

        // And the same client_id may be registered independently in each.
        assert!(
            register(&db, &hasher, confidential(other, &uris))
                .await
                .is_ok()
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn registering_the_same_client_id_twice_in_one_realm_conflicts(db: Db) {
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://app.example.com/callback"]);

        register(&db, &hasher, confidential(realm_id, &uris))
            .await
            .unwrap();
        let error = register(&db, &hasher, confidential(realm_id, &uris))
            .await
            .unwrap_err();
        assert_eq!(
            error.code,
            crate::error::OAuthErrorCode::InvalidClientMetadata,
            "{error}",
        );
        assert!(error.description.contains("console"), "{error}");
    }

    #[test]
    fn a_redirect_uri_is_matched_exactly_and_never_by_prefix() {
        let client = Client {
            key: ClientKey(Uuid::nil()),
            realm_id: RealmId(Uuid::nil()),
            client_id: "c".to_owned(),
            name: "C".to_owned(),
            is_public: false,
            redirect_uris: owned(&["https://app.example.com/callback"]),
            grant_types: owned(&[GRANT_AUTHORIZATION_CODE]),
            scopes: owned(&["openid"]),
            require_consent: true,
        };

        assert!(client.allows_redirect("https://app.example.com/callback"));

        // Each of these passes a prefix check and is a real attack.
        for hostile in [
            "https://app.example.com/callback/../../evil",
            "https://app.example.com/callback?next=https://evil.test",
            "https://app.example.com.evil.test/callback",
            "https://app.example.com/callbackevil",
            "https://APP.example.com/callback",
        ] {
            assert!(!client.allows_redirect(hostile), "accepted: {hostile}");
        }
    }

    #[test]
    fn registration_refuses_redirect_uris_that_cannot_be_matched_safely() {
        for bad in [
            "",
            "  https://app.example.com/callback",
            "/callback",
            "https://app.example.com/callback#fragment",
            "https://app.example.com/*",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "https:",
        ] {
            assert!(
                validate_redirect_uri(bad).is_err(),
                "should have been refused: {bad:?}",
            );
        }

        for good in [
            "https://app.example.com/callback",
            "http://127.0.0.1:8080/callback",
            "http://localhost:3000/auth/callback",
            "com.example.app:/oauth2redirect",
        ] {
            assert!(validate_redirect_uri(good).is_ok(), "refused: {good}");
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_client_registered_with_no_redirect_uri_is_refused(db: Db) {
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let error = register(&db, &hasher, confidential(realm_id, &[]))
            .await
            .unwrap_err();
        assert_eq!(
            error.code,
            crate::error::OAuthErrorCode::InvalidClientMetadata,
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unsupported_grant_type_is_refused_rather_than_stored(db: Db) {
        // Storing it would make discovery and the token endpoint disagree.
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://app.example.com/callback"]);
        let grants = owned(&["implicit"]);

        let error = register(
            &db,
            &hasher,
            NewClient {
                grant_types: &grants,
                ..confidential(realm_id, &uris)
            },
        )
        .await
        .unwrap_err();
        assert!(error.description.contains("implicit"), "{error}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_generated_client_id_is_used_when_none_is_asked_for(db: Db) {
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://app.example.com/callback"]);

        let registered = register(
            &db,
            &hasher,
            NewClient {
                client_id: None,
                ..confidential(realm_id, &uris)
            },
        )
        .await
        .unwrap();

        assert!(!registered.client.client_id.is_empty());
        assert!(
            by_client_id(&db, realm_id, &registered.client.client_id)
                .await
                .is_ok(),
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn deleting_a_client_reports_whether_there_was_one(db: Db) {
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://app.example.com/callback"]);
        register(&db, &hasher, confidential(realm_id, &uris))
            .await
            .unwrap();

        assert_eq!(list(&db, realm_id).await.unwrap().len(), 1);
        delete(&db, realm_id, "console").await.unwrap();
        assert!(list(&db, realm_id).await.unwrap().is_empty());
        assert_eq!(
            delete(&db, realm_id, "console").await.unwrap_err().status(),
            404,
        );
    }
}
