//! Signing keys: persistent, rotatable, encrypted at rest.
//!
//! The previous build's entire root of trust was
//! `Lazy::new(|| SigningKey::generate(&mut OsRng))`, with a comment saying
//! "for demo purposes". Every restart invalidated every token it had ever
//! issued, no two instances could validate each other's, and the JWKS document
//! changed on every boot.
//!
//! Here a realm has exactly one **active** key that signs, and any number of
//! **retired** keys that still verify and still appear in JWKS until they
//! expire — which is what makes rotation possible without invalidating tokens
//! that are still in flight.
//!
//! Private keys are stored AES-GCM-encrypted under a key-encryption key that
//! comes from configuration and never reaches the database. A database
//! disclosure alone therefore does not yield a signing key.

use aes_gcm::{
    Aes256Gcm, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use authenc_contract::{AppError, RealmId, Result};
use authenc_identity::Db;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

/// Bytes in the key-encryption key.
pub const MASTER_KEY_BYTES: usize = 32;

/// The key-encryption key that protects stored private keys.
///
/// Kept as its own type so it cannot be confused with a signing key, and so
/// its `Debug` can be redacted.
#[derive(Clone)]
pub struct MasterKey([u8; MASTER_KEY_BYTES]);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey([redacted])")
    }
}

impl MasterKey {
    /// Parse a base64url-encoded 32-byte key.
    ///
    /// # Errors
    ///
    /// Returns a validation error if the value is not 32 bytes once decoded.
    /// Rejecting a short key here rather than padding it is the point: a
    /// truncated key would silently weaken every stored private key.
    pub fn from_base64(value: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value.trim())
            .map_err(|_| AppError::validation("master key is not valid base64url"))?;

        let bytes: [u8; MASTER_KEY_BYTES] = bytes.try_into().map_err(|_| {
            AppError::validation(format!(
                "master key must decode to exactly {MASTER_KEY_BYTES} bytes"
            ))
        })?;

        Ok(Self(bytes))
    }

    /// Generate a fresh key, for `authenc generate-master-key`.
    ///
    /// # Errors
    ///
    /// Returns an internal error if the OS entropy source fails.
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; MASTER_KEY_BYTES];
        getrandom::fill(&mut bytes)
            .map_err(|e| AppError::internal_from("generating master key", e))?;
        Ok(Self(bytes))
    }

    /// Render for configuration.
    #[must_use]
    pub fn to_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(&Key::<Aes256Gcm>::from(self.0))
    }
}

/// A key usable for signing and verification.
pub struct ActiveKey {
    /// The `kid` published in JWKS and carried in each token header.
    pub kid: String,
    /// The private half.
    pub signing: SigningKey,
}

impl std::fmt::Debug for ActiveKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// A public key as JWKS describes it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Jwk {
    /// Key type. Always `OKP` for Ed25519.
    pub kty: String,
    /// Curve. Always `Ed25519`.
    pub crv: String,
    /// The public key, base64url without padding.
    pub x: String,
    /// Key id.
    pub kid: String,
    /// Intended use. Always `sig`.
    #[serde(rename = "use")]
    pub use_: String,
    /// Algorithm. Always `EdDSA`.
    pub alg: String,
}

/// A JWKS document.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JwkSet {
    /// The keys a verifier may use.
    pub keys: Vec<Jwk>,
}

fn jwk_for(kid: &str, public: &VerifyingKey) -> Jwk {
    Jwk {
        kty: "OKP".to_owned(),
        crv: "Ed25519".to_owned(),
        x: URL_SAFE_NO_PAD.encode(public.as_bytes()),
        kid: kid.to_owned(),
        use_: "sig".to_owned(),
        alg: "EdDSA".to_owned(),
    }
}

/// Return the realm's active signing key, creating one if there is none.
///
/// # Errors
///
/// Returns an internal error if entropy, encryption, or the database fails.
pub async fn active(db: &Db, master: &MasterKey, realm_id: RealmId) -> Result<ActiveKey> {
    if let Some(key) = load_active(db, master, realm_id).await? {
        return Ok(key);
    }
    create(db, master, realm_id).await
}

async fn load_active(db: &Db, master: &MasterKey, realm_id: RealmId) -> Result<Option<ActiveKey>> {
    let row = sqlx::query!(
        r#"
        SELECT kid, private_key, private_nonce
        FROM signing_keys
        WHERE realm_id = $1 AND status = 'active'
        "#,
        realm_id.0,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading signing key", e))?;

    let Some(row) = row else {
        return Ok(None);
    };

    let signing = decrypt(master, &row.kid, &row.private_key, &row.private_nonce)?;
    Ok(Some(ActiveKey {
        kid: row.kid,
        signing,
    }))
}

/// Create a new active key, retiring whichever one was active.
///
/// The retired key keeps verifying — and keeps appearing in JWKS — until
/// `not_after`, so tokens signed a moment before rotation remain valid.
///
/// # Errors
///
/// Returns an internal error if entropy, encryption, or the database fails.
pub async fn rotate(
    db: &Db,
    master: &MasterKey,
    realm_id: RealmId,
    retire_after: time::Duration,
) -> Result<ActiveKey> {
    let mut tx = db
        .begin()
        .await
        .map_err(|e| AppError::internal_from("beginning transaction", e))?;

    sqlx::query!(
        r#"
        UPDATE signing_keys
        SET status = 'retired', not_after = now() + make_interval(secs => $2)
        WHERE realm_id = $1 AND status = 'active'
        "#,
        realm_id.0,
        retire_after.as_seconds_f64(),
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::internal_from("retiring signing key", e))?;

    let key = insert(&mut tx, master, realm_id).await?;

    tx.commit()
        .await
        .map_err(|e| AppError::internal_from("committing transaction", e))?;

    tracing::info!(kid = %key.kid, "rotated signing key");
    Ok(key)
}

async fn create(db: &Db, master: &MasterKey, realm_id: RealmId) -> Result<ActiveKey> {
    let mut tx = db
        .begin()
        .await
        .map_err(|e| AppError::internal_from("beginning transaction", e))?;

    let key = insert(&mut tx, master, realm_id).await?;

    tx.commit()
        .await
        .map_err(|e| AppError::internal_from("committing transaction", e))?;

    Ok(key)
}

async fn insert(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    master: &MasterKey,
    realm_id: RealmId,
) -> Result<ActiveKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| AppError::internal_from("generating signing key", e))?;
    let signing = SigningKey::from_bytes(&seed);
    let public = signing.verifying_key();

    // The kid is derived from the public key, so it is stable, unguessable in
    // advance, and cannot collide with another key's.
    let kid = URL_SAFE_NO_PAD.encode(&Sha256::digest(public.as_bytes())[..16]);
    let (ciphertext, nonce) = encrypt(master, &kid, &seed)?;

    sqlx::query!(
        r#"
        INSERT INTO signing_keys
            (realm_id, kid, public_key, private_key, private_nonce, status)
        VALUES ($1, $2, $3, $4, $5, 'active')
        "#,
        realm_id.0,
        kid,
        public.as_bytes().as_slice(),
        &ciphertext[..],
        &nonce[..],
    )
    .execute(&mut **tx)
    .await
    .map_err(|e| AppError::internal_from("storing signing key", e))?;

    Ok(ActiveKey { kid, signing })
}

/// Every key a verifier may currently use: the active one, plus retired keys
/// that have not passed `not_after`.
///
/// # Errors
///
/// Returns an internal error if the query fails, or if a stored public key is
/// not a valid Ed25519 point.
pub async fn jwks(db: &Db, realm_id: RealmId) -> Result<JwkSet> {
    let rows = sqlx::query!(
        r#"
        SELECT kid, public_key
        FROM signing_keys
        WHERE realm_id = $1
          AND (status = 'active' OR not_after > now())
        ORDER BY created_at DESC
        "#,
        realm_id.0,
    )
    .fetch_all(db)
    .await
    .map_err(|e| AppError::internal_from("loading JWKS", e))?;

    let mut keys = Vec::with_capacity(rows.len());
    for row in rows {
        let bytes: [u8; 32] = row
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| AppError::internal("stored public key has the wrong length"))?;
        let public = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| AppError::internal_from("parsing stored public key", e))?;
        keys.push(jwk_for(&row.kid, &public));
    }

    Ok(JwkSet { keys })
}

/// Find the verifying key for a `kid`, if it is still usable.
///
/// # Errors
///
/// Returns an internal error if the query fails.
pub async fn verifying_key(db: &Db, kid: &str) -> Result<Option<VerifyingKey>> {
    let row = sqlx::query!(
        r#"
        SELECT public_key
        FROM signing_keys
        WHERE kid = $1 AND (status = 'active' OR not_after > now())
        "#,
        kid,
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::internal_from("loading verifying key", e))?;

    let Some(row) = row else {
        return Ok(None);
    };

    let bytes: [u8; 32] = row
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| AppError::internal("stored public key has the wrong length"))?;

    VerifyingKey::from_bytes(&bytes)
        .map(Some)
        .map_err(|e| AppError::internal_from("parsing stored public key", e))
}

/// Delete retired keys whose `not_after` has passed.
///
/// # Errors
///
/// Returns an internal error if the delete fails.
pub async fn purge_retired(db: &Db) -> Result<u64> {
    let result =
        sqlx::query!("DELETE FROM signing_keys WHERE status = 'retired' AND not_after <= now()",)
            .execute(db)
            .await
            .map_err(|e| AppError::internal_from("purging retired keys", e))?;

    Ok(result.rows_affected())
}

/// Encrypt a private key seed, returning the ciphertext and its nonce.
///
/// The `kid` is bound in as associated data, so a ciphertext moved onto another
/// key's row fails to decrypt rather than silently signing as the wrong key.
fn encrypt(master: &MasterKey, kid: &str, seed: &[u8; 32]) -> Result<(Vec<u8>, [u8; 12])> {
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| AppError::internal_from("generating nonce", e))?;

    let ciphertext = master
        .cipher()
        .encrypt(
            &Nonce::from(nonce_bytes),
            Payload {
                msg: seed,
                aad: kid.as_bytes(),
            },
        )
        .map_err(|_| AppError::internal("encrypting signing key"))?;

    Ok((ciphertext, nonce_bytes))
}

fn decrypt(master: &MasterKey, kid: &str, ciphertext: &[u8], nonce: &[u8]) -> Result<SigningKey> {
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| AppError::internal("stored nonce has the wrong length"))?;

    let plaintext = master
        .cipher()
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: kid.as_bytes(),
            },
        )
        .map_err(|_| {
            // Almost always the wrong master key. Say so, because the
            // alternative reading — "the database is corrupt" — sends an
            // operator down the wrong path.
            AppError::internal(
                "could not decrypt the signing key; \
                 the configured master key does not match the stored key",
            )
        })?;

    let seed: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| AppError::internal("stored signing key has the wrong length"))?;

    Ok(SigningKey::from_bytes(&seed))
}

/// When a rotated key stops being accepted, by default.
pub const DEFAULT_RETIRE_AFTER: time::Duration = time::Duration::days(2);

/// The moment a token signed now should stop being valid, for a given lifetime.
#[must_use]
pub fn expiry(lifetime: time::Duration) -> OffsetDateTime {
    OffsetDateTime::now_utc() + lifetime
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenc_identity::realm;
    use ed25519_dalek::{Signer, Verifier};

    fn master() -> MasterKey {
        MasterKey::generate().unwrap()
    }

    async fn a_realm(db: &Db) -> RealmId {
        realm::create(db, "acme", "Acme").await.unwrap().id
    }

    #[test]
    fn a_master_key_round_trips_through_base64() {
        let key = master();
        let parsed = MasterKey::from_base64(&key.to_base64()).unwrap();
        assert_eq!(key.0, parsed.0);
    }

    #[test]
    fn a_short_or_malformed_master_key_is_refused() {
        // Padding a short key rather than refusing it would silently weaken
        // every private key it protects.
        assert!(MasterKey::from_base64("").is_err());
        assert!(MasterKey::from_base64("too-short").is_err());
        assert!(MasterKey::from_base64("!!! not base64 !!!").is_err());
    }

    #[test]
    fn the_master_key_is_redacted_in_debug_output() {
        let key = master();
        let rendered = format!("{key:?}");
        assert!(!rendered.contains(&key.to_base64()), "leaked: {rendered}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_same_key_comes_back_across_calls(db: Db) {
        // The property the previous build could not have: its key was
        // regenerated on every process start.
        let realm_id = a_realm(&db).await;
        let master = master();

        let first = active(&db, &master, realm_id).await.unwrap();
        let second = active(&db, &master, realm_id).await.unwrap();

        assert_eq!(first.kid, second.kid);
        assert_eq!(first.signing.to_bytes(), second.signing.to_bytes());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_signature_made_before_a_restart_still_verifies_after(db: Db) {
        let realm_id = a_realm(&db).await;
        let master = master();

        let before = active(&db, &master, realm_id).await.unwrap();
        let signature = before.signing.sign(b"a token payload");

        // A "restart" is simply loading the key again from storage.
        let after = active(&db, &master, realm_id).await.unwrap();
        assert!(
            after
                .signing
                .verifying_key()
                .verify(b"a token payload", &signature)
                .is_ok(),
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_private_key_is_not_stored_in_the_clear(db: Db) {
        let realm_id = a_realm(&db).await;
        let master = master();
        let key = active(&db, &master, realm_id).await.unwrap();

        let stored: Vec<u8> = sqlx::query_scalar("SELECT private_key FROM signing_keys")
            .fetch_one(&db)
            .await
            .unwrap();

        assert_ne!(stored, key.signing.to_bytes().to_vec());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn the_wrong_master_key_cannot_read_the_signing_key(db: Db) {
        let realm_id = a_realm(&db).await;
        active(&db, &master(), realm_id).await.unwrap();

        // A database disclosure alone must not yield a signing key.
        let error = active(&db, &master(), realm_id).await.unwrap_err();
        assert!(
            error.to_string().contains("master key"),
            "the message should point at the real cause, got: {error}",
        );
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn rotation_replaces_the_signer_but_keeps_verifying_old_tokens(db: Db) {
        let realm_id = a_realm(&db).await;
        let master = master();

        let old = active(&db, &master, realm_id).await.unwrap();
        let new = rotate(&db, &master, realm_id, DEFAULT_RETIRE_AFTER)
            .await
            .unwrap();

        assert_ne!(old.kid, new.kid, "rotation must produce a different key");
        assert_eq!(
            active(&db, &master, realm_id).await.unwrap().kid,
            new.kid,
            "new tokens must be signed by the new key",
        );

        // The retired key must still be resolvable, or every token issued a
        // moment before rotation would break.
        assert!(verifying_key(&db, &old.kid).await.unwrap().is_some());
        assert!(verifying_key(&db, &new.kid).await.unwrap().is_some());
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn jwks_publishes_the_active_and_retired_keys(db: Db) {
        let realm_id = a_realm(&db).await;
        let master = master();

        let old = active(&db, &master, realm_id).await.unwrap();
        let new = rotate(&db, &master, realm_id, DEFAULT_RETIRE_AFTER)
            .await
            .unwrap();

        let set = jwks(&db, realm_id).await.unwrap();
        let kids: Vec<_> = set.keys.iter().map(|k| k.kid.as_str()).collect();

        assert!(kids.contains(&old.kid.as_str()), "{kids:?}");
        assert!(kids.contains(&new.kid.as_str()), "{kids:?}");
        for jwk in &set.keys {
            assert_eq!(jwk.kty, "OKP");
            assert_eq!(jwk.crv, "Ed25519");
            assert_eq!(jwk.alg, "EdDSA");
        }
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn jwks_never_contains_a_private_key(db: Db) {
        let realm_id = a_realm(&db).await;
        let master = master();
        let key = active(&db, &master, realm_id).await.unwrap();

        let json = serde_json::to_string(&jwks(&db, realm_id).await.unwrap()).unwrap();
        let secret = URL_SAFE_NO_PAD.encode(key.signing.to_bytes());

        assert!(!json.contains(&secret), "the private key leaked into JWKS");
        // `d` is the JWK member that would carry it.
        assert!(!json.contains("\"d\""), "got: {json}");
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn a_key_retired_past_its_deadline_stops_verifying(db: Db) {
        let realm_id = a_realm(&db).await;
        let master = master();

        let old = active(&db, &master, realm_id).await.unwrap();
        rotate(&db, &master, realm_id, DEFAULT_RETIRE_AFTER)
            .await
            .unwrap();

        sqlx::query(
            "UPDATE signing_keys SET not_after = now() - interval '1 second' WHERE kid = $1",
        )
        .bind(&old.kid)
        .execute(&db)
        .await
        .unwrap();

        assert!(
            verifying_key(&db, &old.kid).await.unwrap().is_none(),
            "a key past its deadline must no longer verify",
        );
        assert_eq!(purge_retired(&db).await.unwrap(), 1);
    }

    #[sqlx::test(migrations = "../../migrations")]
    async fn realms_do_not_share_signing_keys(db: Db) {
        let master = master();
        let acme = a_realm(&db).await;
        let other = realm::create(&db, "other", "Other").await.unwrap().id;

        let a = active(&db, &master, acme).await.unwrap();
        let b = active(&db, &master, other).await.unwrap();

        assert_ne!(a.kid, b.kid);
        assert_ne!(a.signing.to_bytes(), b.signing.to_bytes());
    }
}
