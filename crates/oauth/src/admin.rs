//! Administering OAuth clients.
//!
//! The same shape as `authenc_identity::admin`: every function takes an
//! [`Actor`] and checks a typed permission before doing anything. Nothing here
//! knows about HTTP, so the console's server functions and the REST handlers
//! can be two thin surfaces over one set of rules rather than two
//! implementations that drift.
//!
//! Realm isolation is enforced the same way too: reaching for a client in
//! another realm is [`AppError::NotFound`], not `Forbidden`, because confirming
//! that something exists in another tenant is itself a disclosure.

use authenc_contract::{AppError, Permission, RealmId, Result, event::Action, model::Actor};
use authenc_identity::{
    Db, PasswordHasher, SecretToken,
    audit::{self, Entry},
};

use crate::client::{self, Client, NewClient};

/// List the clients registered in a realm.
///
/// # Errors
///
/// Returns [`AppError::Forbidden`] without `client:read`, or an internal error
/// if the query fails.
pub async fn list(db: &Db, actor: &Actor, realm_id: RealmId) -> Result<Vec<Client>> {
    actor.require(Permission::ClientRead)?;
    same_realm(actor, realm_id)?;
    client::list(db, realm_id).await
}

/// Fetch one client.
///
/// # Errors
///
/// Returns [`AppError::Forbidden`] without `client:read`, or
/// [`AppError::NotFound`] if there is no such client in the actor's realm.
pub async fn get(db: &Db, actor: &Actor, client_id: &str) -> Result<Client> {
    actor.require(Permission::ClientRead)?;
    client::by_client_id(db, actor.realm_id, client_id).await
}

/// What an administrator supplies to register a client.
#[derive(Debug, Clone)]
pub struct Registration<'a> {
    /// The `client_id` the client will present.
    pub client_id: &'a str,
    /// Display name, shown on the consent screen.
    pub name: &'a str,
    /// Whether it is a public client: no secret, PKCE required.
    pub is_public: bool,
    /// Exact redirect URIs. At least one is required.
    pub redirect_uris: &'a [String],
    /// Scopes it may request. Defaults to `openid profile email` when empty.
    pub scopes: &'a [String],
    /// Whether the user is asked before the first issuance.
    pub require_consent: bool,
}

/// A newly registered client and the one sight of its secret.
#[derive(Debug)]
pub struct Registered {
    /// The stored record.
    pub client: Client,
    /// The generated secret, `None` for a public client. Only its hash is
    /// stored, so this is the only time it can be read.
    pub client_secret: Option<SecretToken>,
}

/// Register a client in the actor's realm.
///
/// # Errors
///
/// Returns [`AppError::Forbidden`] without `client:write`, or a validation
/// error describing metadata the server will not accept.
pub async fn register(
    db: &Db,
    actor: &Actor,
    hasher: &PasswordHasher,
    new: Registration<'_>,
) -> Result<Registered> {
    actor.require(Permission::ClientWrite)?;

    let registered = client::register(
        db,
        hasher,
        NewClient {
            realm_id: actor.realm_id,
            client_id: Some(new.client_id),
            name: new.name,
            is_public: new.is_public,
            redirect_uris: new.redirect_uris,
            // Administrators do not choose grant types: the set this server
            // implements is the set a client may use, and discovery says so.
            grant_types: &[],
            scopes: new.scopes,
            require_consent: new.require_consent,
        },
    )
    .await
    // The protocol's error vocabulary is for protocol callers. An
    // administrator gets the ordinary one, so the console and the REST surface
    // report it like any other validation failure.
    .map_err(protocol_to_app)?;

    audit::observe(
        db,
        Entry::success(Action::ClientRegistered)
            .in_realm(actor.realm_id)
            .by(actor.user_id, &actor.username)
            .to("client", new.client_id)
            .detail(serde_json::json!({ "public": new.is_public })),
    )
    .await;

    Ok(Registered {
        client: registered.client,
        client_secret: registered.client_secret,
    })
}

/// Replace a client's secret, returning the new one.
///
/// Every token the client already holds keeps working; what stops working is
/// the client's ability to authenticate at the token endpoint with the old
/// secret. That is the point — a leaked secret is replaced without invalidating
/// live sessions.
///
/// # Errors
///
/// Returns [`AppError::Forbidden`] without `client:write`,
/// [`AppError::NotFound`] for an unknown client, or a validation error if the
/// client is public and therefore has no secret to rotate.
pub async fn rotate_secret(
    db: &Db,
    actor: &Actor,
    hasher: &PasswordHasher,
    client_id: &str,
) -> Result<SecretToken> {
    actor.require(Permission::ClientWrite)?;
    let client = client::by_client_id(db, actor.realm_id, client_id).await?;
    let secret = client::rotate_secret(db, hasher, &client).await?;

    // The event a rotation exists for: an operator reading the trail during an
    // incident needs to see when the old secret stopped working.
    audit::observe(
        db,
        Entry::success(Action::ClientSecretRotated)
            .in_realm(actor.realm_id)
            .by(actor.user_id, &actor.username)
            .to("client", client_id),
    )
    .await;

    Ok(secret)
}

/// Replace a client's redirect URIs and scopes.
///
/// # Errors
///
/// Returns [`AppError::Forbidden`] without `client:write`,
/// [`AppError::NotFound`] for an unknown client, or a validation error for a
/// redirect URI this server will not register.
pub async fn update(
    db: &Db,
    actor: &Actor,
    client_id: &str,
    changes: client::Changes<'_>,
) -> Result<Client> {
    actor.require(Permission::ClientWrite)?;
    let client = client::by_client_id(db, actor.realm_id, client_id).await?;

    // Captured before the move, so the record describes the request that was
    // made rather than whatever survived it.
    let touched = serde_json::json!({
        "redirect_uris": changes.redirect_uris.is_some(),
        "scopes": changes.scopes.is_some(),
        "require_consent": changes.require_consent.is_some(),
    });

    let updated = client::update(db, &client, changes)
        .await
        .map_err(protocol_to_app)?;

    audit::observe(
        db,
        Entry::success(Action::ClientUpdated)
            .in_realm(actor.realm_id)
            .by(actor.user_id, &actor.username)
            .to("client", client_id)
            // Which fields changed, never their values: a redirect URI list is
            // not a secret, but the habit of writing payloads into an audit log
            // is how one eventually contains something that is.
            .detail(touched),
    )
    .await;

    Ok(updated)
}

/// Delete a client, and with it every code, token, and consent it holds.
///
/// # Errors
///
/// Returns [`AppError::Forbidden`] without `client:write`, or
/// [`AppError::NotFound`] for an unknown client.
pub async fn delete(db: &Db, actor: &Actor, client_id: &str) -> Result<()> {
    actor.require(Permission::ClientWrite)?;
    client::delete(db, actor.realm_id, client_id).await?;

    audit::observe(
        db,
        Entry::success(Action::ClientDeleted)
            .in_realm(actor.realm_id)
            .by(actor.user_id, &actor.username)
            .to("client", client_id),
    )
    .await;

    Ok(())
}

/// Whether a client is one the actor may touch.
///
/// `NotFound` rather than `Forbidden`, deliberately.
fn same_realm(actor: &Actor, realm_id: RealmId) -> Result<()> {
    if actor.realm_id == realm_id {
        Ok(())
    } else {
        Err(AppError::NotFound("realm"))
    }
}

/// Turn a protocol error into the ordinary one an administrator should see.
fn protocol_to_app(error: crate::OAuthError) -> AppError {
    match error.code {
        crate::OAuthErrorCode::ServerError => AppError::internal(error.description),
        _ => AppError::validation(error.description),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "a failed setup step should fail the test"
)]
mod tests {
    use super::*;
    use authenc_contract::UserId;
    use authenc_identity::realm;

    fn owned(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).to_owned()).collect()
    }

    fn actor_with(realm_id: RealmId, permissions: &[Permission]) -> Actor {
        Actor {
            user_id: UserId::new(),
            realm_id,
            username: "admin".to_owned(),
            roles: Vec::new(),
            permissions: permissions.to_vec(),
        }
    }

    async fn a_realm(db: &Db) -> RealmId {
        realm::create(db, "master", "Master").await.unwrap().id
    }

    fn registration<'a>(uris: &'a [String], scopes: &'a [String]) -> Registration<'a> {
        Registration {
            client_id: "console",
            name: "Console",
            is_public: false,
            redirect_uris: uris,
            scopes,
            require_consent: true,
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn registering_needs_client_write(db: Db) {
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://app.example.com/callback"]);
        let scopes = owned(&["openid"]);

        // Read alone is not enough.
        let reader = actor_with(realm_id, &[Permission::ClientRead]);
        let error = register(&db, &reader, &hasher, registration(&uris, &scopes))
            .await
            .unwrap_err();
        assert_eq!(error.status(), 403);

        let writer = actor_with(realm_id, &[Permission::ClientWrite]);
        assert!(
            register(&db, &writer, &hasher, registration(&uris, &scopes))
                .await
                .is_ok(),
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn listing_needs_client_read_and_write_implies_it(db: Db) {
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://app.example.com/callback"]);
        let scopes = owned(&["openid"]);
        let writer = actor_with(realm_id, &[Permission::ClientWrite]);
        register(&db, &writer, &hasher, registration(&uris, &scopes))
            .await
            .unwrap();

        // A user holding nothing at all sees nothing.
        let nobody = actor_with(realm_id, &[]);
        assert_eq!(
            list(&db, &nobody, realm_id).await.unwrap_err().status(),
            403
        );

        // `client:write` implies `client:read`, so a writer can see the list
        // it is allowed to change.
        assert_eq!(list(&db, &writer, realm_id).await.unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_secret_can_be_rotated_and_the_old_one_stops_authenticating(db: Db) {
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://app.example.com/callback"]);
        let scopes = owned(&["openid"]);
        let actor = actor_with(realm_id, &[Permission::ClientWrite]);

        let first = register(&db, &actor, &hasher, registration(&uris, &scopes))
            .await
            .unwrap()
            .client_secret
            .unwrap();

        let second = rotate_secret(&db, &actor, &hasher, "console")
            .await
            .unwrap();
        assert_ne!(first.expose(), second.expose());

        let credentials = |secret: &SecretToken| client::Credentials {
            client_id: "console".to_owned(),
            secret: Some(secret.expose().to_owned()),
        };

        assert!(
            client::authenticate(&db, &hasher, realm_id, &credentials(&second))
                .await
                .is_ok(),
        );
        assert!(
            client::authenticate(&db, &hasher, realm_id, &credentials(&first))
                .await
                .is_err(),
            "the replaced secret must stop working",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_public_client_has_no_secret_to_rotate(db: Db) {
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://app.example.com/callback"]);
        let scopes = owned(&["openid"]);
        let actor = actor_with(realm_id, &[Permission::ClientWrite]);

        register(
            &db,
            &actor,
            &hasher,
            Registration {
                client_id: "spa",
                is_public: true,
                ..registration(&uris, &scopes)
            },
        )
        .await
        .unwrap();

        // Issuing one would create a credential the client can never present:
        // the token endpoint refuses a secret from a public client.
        let error = rotate_secret(&db, &actor, &hasher, "spa")
            .await
            .unwrap_err();
        assert_eq!(error.status(), 400, "{error}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn an_actor_cannot_reach_a_client_in_another_realm(db: Db) {
        let master = a_realm(&db).await;
        let other = realm::create(&db, "other", "Other").await.unwrap().id;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://app.example.com/callback"]);
        let scopes = owned(&["openid"]);

        let insider = actor_with(master, &[Permission::ClientWrite]);
        register(&db, &insider, &hasher, registration(&uris, &scopes))
            .await
            .unwrap();

        let outsider = actor_with(other, &[Permission::ClientWrite]);

        // 404, not 403: confirming the client exists elsewhere is itself a
        // disclosure.
        assert_eq!(
            get(&db, &outsider, "console").await.unwrap_err().status(),
            404
        );
        assert_eq!(
            delete(&db, &outsider, "console")
                .await
                .unwrap_err()
                .status(),
            404,
        );
        assert_eq!(
            rotate_secret(&db, &outsider, &hasher, "console")
                .await
                .unwrap_err()
                .status(),
            404,
        );
        assert_eq!(
            list(&db, &outsider, master).await.unwrap_err().status(),
            404,
        );

        // And the client is still there afterwards.
        assert_eq!(list(&db, &insider, master).await.unwrap().len(), 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_redirect_uri_that_cannot_be_matched_is_refused_at_registration(db: Db) {
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let scopes = owned(&["openid"]);
        let actor = actor_with(realm_id, &[Permission::ClientWrite]);

        for bad in [
            "https://app.example.com/*",
            "/callback",
            "javascript:alert(1)",
        ] {
            let uris = owned(&[bad]);
            let error = register(&db, &actor, &hasher, registration(&uris, &scopes))
                .await
                .unwrap_err();
            assert_eq!(error.status(), 400, "accepted {bad}: {error}");
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn updating_replaces_the_redirect_uris_rather_than_adding_to_them(db: Db) {
        // Adding would mean a URI can never be withdrawn through this surface,
        // which is the operation an incident actually needs.
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://old.example.com/callback"]);
        let scopes = owned(&["openid"]);
        let actor = actor_with(realm_id, &[Permission::ClientWrite]);
        register(&db, &actor, &hasher, registration(&uris, &scopes))
            .await
            .unwrap();

        let replacement = owned(&["https://new.example.com/callback"]);
        let updated = update(
            &db,
            &actor,
            "console",
            client::Changes {
                redirect_uris: Some(&replacement),
                scopes: None,
                require_consent: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.redirect_uris, replacement);
        assert!(!updated.allows_redirect("https://old.example.com/callback"));
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn deleting_a_client_needs_write_and_reports_an_unknown_one(db: Db) {
        let realm_id = a_realm(&db).await;
        let hasher = PasswordHasher::new();
        let uris = owned(&["https://app.example.com/callback"]);
        let scopes = owned(&["openid"]);
        let actor = actor_with(realm_id, &[Permission::ClientWrite]);
        register(&db, &actor, &hasher, registration(&uris, &scopes))
            .await
            .unwrap();

        let reader = actor_with(realm_id, &[Permission::ClientRead]);
        assert_eq!(
            delete(&db, &reader, "console").await.unwrap_err().status(),
            403
        );

        delete(&db, &actor, "console").await.unwrap();
        assert_eq!(
            delete(&db, &actor, "console").await.unwrap_err().status(),
            404
        );
    }
}
