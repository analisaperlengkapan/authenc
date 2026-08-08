//! Issuing and verifying JWTs.
//!
//! Verification checks **issuer, audience, expiry, not-before, and key id**.
//! The previous implementation checked the signature and `exp` and nothing
//! else — no `iss`, no `aud`, no `nbf`, no `kid`, no revocation — which meant a
//! token minted by its own unauthenticated mock endpoint for `demo_user`
//! authenticated against every admin endpoint in the system.
//!
//! The algorithm is fixed at EdDSA and is never read from the token header.
//! Trusting the header's `alg` is the classic JWT confusion attack.

use authenc_contract::{AppError, Result, UserId};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::keyring::ActiveKey;

/// How long an access token is valid by default.
pub const ACCESS_TOKEN_LIFETIME: Duration = Duration::minutes(15);
/// How long an ID token is valid by default.
pub const ID_TOKEN_LIFETIME: Duration = Duration::minutes(15);

/// The JOSE header we emit. `alg` is always `EdDSA`.
#[derive(Debug, Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

/// The claims carried by an access or ID token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// Issuer. Must equal the realm's issuer URL.
    pub iss: String,
    /// Subject: the user's id.
    pub sub: String,
    /// Audience: the client this token was minted for.
    pub aud: String,
    /// Expiry, as a Unix timestamp.
    pub exp: i64,
    /// Issued-at, as a Unix timestamp.
    pub iat: i64,
    /// Not-before, as a Unix timestamp.
    pub nbf: i64,
    /// Unique token id, so a token can be identified in a log or a denylist.
    pub jti: String,
    /// Granted scopes, space-separated, as RFC 8693 specifies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Nonce echoed from the authorization request, for ID tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Preferred username, for ID tokens carrying the `profile` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// Email, for ID tokens carrying the `email` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Whether that email has been proven.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

/// What a token is being minted for.
#[derive(Debug, Clone)]
pub struct Grant<'a> {
    /// The realm's issuer URL.
    pub issuer: &'a str,
    /// The user the token speaks for.
    pub subject: UserId,
    /// The client the token is addressed to.
    pub audience: &'a str,
    /// Granted scopes.
    pub scopes: &'a [String],
    /// Nonce from the authorization request, if any.
    pub nonce: Option<&'a str>,
    /// How long the token is valid.
    pub lifetime: Duration,
}

/// Sign a token.
///
/// # Errors
///
/// Returns an internal error if the claims cannot be serialised.
pub fn issue(key: &ActiveKey, grant: &Grant<'_>) -> Result<String> {
    let now = OffsetDateTime::now_utc();

    let claims = Claims {
        iss: grant.issuer.to_owned(),
        sub: grant.subject.to_string(),
        aud: grant.audience.to_owned(),
        exp: (now + grant.lifetime).unix_timestamp(),
        iat: now.unix_timestamp(),
        nbf: now.unix_timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        scope: (!grant.scopes.is_empty()).then(|| grant.scopes.join(" ")),
        nonce: grant.nonce.map(ToOwned::to_owned),
        preferred_username: None,
        email: None,
        email_verified: None,
    };

    sign(key, &claims)
}

/// Sign a prepared set of claims.
///
/// # Errors
///
/// Returns an internal error if the header or claims cannot be serialised.
pub fn sign(key: &ActiveKey, claims: &Claims) -> Result<String> {
    let header = Header {
        alg: "EdDSA".to_owned(),
        typ: "JWT".to_owned(),
        kid: key.kid.clone(),
    };

    let header = encode_part(&header)?;
    let payload = encode_part(claims)?;
    let signing_input = format!("{header}.{payload}");

    let signature = key.signing.sign(signing_input.as_bytes());

    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn encode_part<T: Serialize>(value: &T) -> Result<String> {
    let json = serde_json::to_vec(value)
        .map_err(|e| AppError::internal_from("serialising token part", e))?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

/// Read the `kid` from a token's header **without trusting anything else**.
///
/// The caller uses it to look up a key; the signature is then checked against
/// that key. Nothing from the header is used to decide *how* to verify — the
/// algorithm is fixed.
///
/// # Errors
///
/// Returns [`AppError::Unauthenticated`] if the token is not well formed.
pub fn kid_of(token: &str) -> Result<String> {
    let header = token.split('.').next().ok_or(AppError::Unauthenticated)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| AppError::Unauthenticated)?;
    let header: Header = serde_json::from_slice(&bytes).map_err(|_| AppError::Unauthenticated)?;

    Ok(header.kid)
}

/// What a verifier requires of a token.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// The issuer the token must name.
    pub issuer: &'a str,
    /// The audience the token must name.
    pub audience: &'a str,
}

/// Verify a token and return its claims.
///
/// # Errors
///
/// Returns [`AppError::Unauthenticated`] for a malformed token, a bad
/// signature, an expired or not-yet-valid token, or a mismatched issuer or
/// audience. One error for all of them: distinguishing them tells an attacker
/// which part of their forgery to fix.
pub fn verify(token: &str, public: &VerifyingKey, expected: Expected<'_>) -> Result<Claims> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(AppError::Unauthenticated);
    };

    let signature_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| AppError::Unauthenticated)?
        .try_into()
        .map_err(|_| AppError::Unauthenticated)?;

    let signing_input = format!("{header}.{payload}");
    public
        .verify(
            signing_input.as_bytes(),
            &Signature::from_bytes(&signature_bytes),
        )
        .map_err(|_| AppError::Unauthenticated)?;

    let claims: Claims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| AppError::Unauthenticated)?,
    )
    .map_err(|_| AppError::Unauthenticated)?;

    let now = OffsetDateTime::now_utc().unix_timestamp();

    // Each of these was missing from the previous verifier, which checked only
    // the signature and `exp`.
    if claims.iss != expected.issuer
        || claims.aud != expected.audience
        || claims.exp <= now
        || claims.nbf > now
    {
        return Err(AppError::Unauthenticated);
    }

    Ok(claims)
}

/// The issuer URL for a realm.
///
/// Derived from the configured public origin, never hardcoded. The previous
/// code baked in `http://localhost:8080/v1` and served that as the issuer in
/// its discovery document wherever it was deployed.
#[must_use]
pub fn issuer_for(public_url: &str, realm_name: &str) -> String {
    format!("{}/realms/{realm_name}", public_url.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ActiveKey {
        use ed25519_dalek::SigningKey;

        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).unwrap();
        ActiveKey {
            kid: "test-kid".to_owned(),
            signing: SigningKey::from_bytes(&seed),
        }
    }

    fn grant<'a>(issuer: &'a str, audience: &'a str, scopes: &'a [String]) -> Grant<'a> {
        Grant {
            issuer,
            subject: UserId::new(),
            audience,
            scopes,
            nonce: None,
            lifetime: ACCESS_TOKEN_LIFETIME,
        }
    }

    fn expected<'a>(issuer: &'a str, audience: &'a str) -> Expected<'a> {
        Expected { issuer, audience }
    }

    #[test]
    fn a_token_verifies_against_the_key_that_signed_it() {
        let key = key();
        let scopes = vec!["openid".to_owned()];
        let token = issue(&key, &grant("https://id.example", "app", &scopes)).unwrap();

        let claims = verify(
            &token,
            &key.signing.verifying_key(),
            expected("https://id.example", "app"),
        )
        .unwrap();

        assert_eq!(claims.iss, "https://id.example");
        assert_eq!(claims.aud, "app");
        assert_eq!(claims.scope.as_deref(), Some("openid"));
    }

    #[test]
    fn a_token_signed_by_another_key_is_refused() {
        let scopes = vec![];
        let token = issue(&key(), &grant("https://id.example", "app", &scopes)).unwrap();

        assert!(
            verify(
                &token,
                &key().signing.verifying_key(),
                expected("https://id.example", "app"),
            )
            .is_err(),
        );
    }

    #[test]
    fn the_issuer_must_match() {
        // Without this check a token from any issuer using the same key would
        // be accepted. The previous verifier did not look at `iss` at all.
        let key = key();
        let scopes = vec![];
        let token = issue(&key, &grant("https://elsewhere.example", "app", &scopes)).unwrap();

        assert!(
            verify(
                &token,
                &key.signing.verifying_key(),
                expected("https://id.example", "app"),
            )
            .is_err(),
        );
    }

    #[test]
    fn the_audience_must_match() {
        // Without this, a token minted for one client is usable at another —
        // a confused-deputy attack between two applications of the same realm.
        let key = key();
        let scopes = vec![];
        let token = issue(&key, &grant("https://id.example", "app-a", &scopes)).unwrap();

        assert!(
            verify(
                &token,
                &key.signing.verifying_key(),
                expected("https://id.example", "app-b"),
            )
            .is_err(),
        );
    }

    #[test]
    fn an_expired_token_is_refused() {
        let key = key();
        let scopes = vec![];
        let mut g = grant("https://id.example", "app", &scopes);
        g.lifetime = Duration::seconds(-1);
        let token = issue(&key, &g).unwrap();

        assert!(
            verify(
                &token,
                &key.signing.verifying_key(),
                expected("https://id.example", "app"),
            )
            .is_err(),
        );
    }

    #[test]
    fn a_not_yet_valid_token_is_refused() {
        let key = key();
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = Claims {
            iss: "https://id.example".to_owned(),
            sub: UserId::new().to_string(),
            aud: "app".to_owned(),
            exp: now + 3600,
            iat: now,
            nbf: now + 3600,
            jti: "x".to_owned(),
            scope: None,
            nonce: None,
            preferred_username: None,
            email: None,
            email_verified: None,
        };
        let token = sign(&key, &claims).unwrap();

        assert!(
            verify(
                &token,
                &key.signing.verifying_key(),
                expected("https://id.example", "app"),
            )
            .is_err(),
            "nbf must be enforced, not merely recorded",
        );
    }

    #[test]
    fn a_tampered_payload_is_refused() {
        let key = key();
        let scopes = vec!["openid".to_owned()];
        let token = issue(&key, &grant("https://id.example", "app", &scopes)).unwrap();

        // Swap the payload for one claiming a different subject.
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss": "https://id.example",
                "sub": "somebody-else",
                "aud": "app",
                "exp": OffsetDateTime::now_utc().unix_timestamp() + 3600,
                "iat": 0, "nbf": 0, "jti": "x",
            }))
            .unwrap(),
        );
        parts[1] = &forged;

        assert!(
            verify(
                &parts.join("."),
                &key.signing.verifying_key(),
                expected("https://id.example", "app"),
            )
            .is_err(),
        );
    }

    #[test]
    fn the_algorithm_is_never_taken_from_the_header() {
        // The classic JWT confusion attack: claim `alg: none` (or HS256 with
        // the public key as the secret) and hope the verifier obeys. Ours does
        // not read `alg` at all — the Ed25519 check is unconditional.
        let key = key();
        let scopes = vec![];
        let token = issue(&key, &grant("https://id.example", "app", &scopes)).unwrap();

        let mut parts: Vec<&str> = token.split('.').collect();
        let none_header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "alg": "none", "typ": "JWT", "kid": "test-kid",
            }))
            .unwrap(),
        );
        parts[0] = &none_header;

        assert!(
            verify(
                &parts.join("."),
                &key.signing.verifying_key(),
                expected("https://id.example", "app"),
            )
            .is_err(),
        );
    }

    #[test]
    fn a_malformed_token_is_refused_without_panicking() {
        let key = key().signing.verifying_key();
        for bad in ["", "a", "a.b", "a.b.c.d", "....", "not.a.token"] {
            assert!(
                verify(bad, &key, expected("https://id.example", "app")).is_err(),
                "accepted {bad:?}",
            );
        }
    }

    #[test]
    fn the_kid_is_readable_before_verification() {
        // The verifier needs it to choose a key; that is the only thing the
        // header is used for.
        let key = key();
        let scopes = vec![];
        let token = issue(&key, &grant("https://id.example", "app", &scopes)).unwrap();

        assert_eq!(kid_of(&token).unwrap(), "test-kid");
        assert!(kid_of("garbage").is_err());
    }

    #[test]
    fn every_token_has_a_distinct_id() {
        let key = key();
        let scopes = vec![];
        let a = issue(&key, &grant("https://id.example", "app", &scopes)).unwrap();
        let b = issue(&key, &grant("https://id.example", "app", &scopes)).unwrap();
        assert_ne!(a, b, "jti must make each token unique");
    }

    #[test]
    fn the_issuer_url_comes_from_configuration() {
        assert_eq!(
            issuer_for("https://id.example.com/", "master"),
            "https://id.example.com/realms/master",
        );
        assert_eq!(
            issuer_for("http://localhost:3000", "acme"),
            "http://localhost:3000/realms/acme",
        );
    }
}
