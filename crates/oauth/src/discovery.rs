//! The OpenID Provider metadata document.
//!
//! Two mistakes the previous build made, both of which make a conformant
//! client unable to use the server at all:
//!
//! * it registered the document at `/.well-known/openid_configuration` —
//!   **underscore** — which no standard client looks for;
//! * it hardcoded `http://localhost:8080/v1` as the issuer and served that
//!   wherever it was deployed, so `iss` never matched the host a client
//!   actually reached.
//!
//! Every URL here is derived from the configured public origin, and the
//! `supported` lists are built from the constants the code itself uses, so
//! discovery cannot drift away from what the endpoints implement.

use serde::{Deserialize, Serialize};

use crate::{
    client::SUPPORTED_GRANTS, code::CHALLENGE_METHOD, scope::SUPPORTED as SUPPORTED_SCOPES,
};

/// Client authentication methods the token endpoint accepts.
pub const AUTH_METHODS: &[&str] = &["client_secret_basic", "client_secret_post", "none"];

/// Where a realm's protocol endpoints live, all derived from one origin.
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// The issuer, which is also the `iss` claim in every token.
    pub issuer: String,
    /// Base path for the realm's protocol endpoints.
    base: String,
}

impl Endpoints {
    /// Build the endpoint set for a realm under a public origin.
    #[must_use]
    pub fn new(public_url: &str, realm: &str) -> Self {
        let origin = public_url.trim_end_matches('/');
        Self {
            issuer: crate::token::issuer_for(public_url, realm),
            base: format!("{origin}/realms/{realm}/protocol/openid-connect"),
        }
    }

    /// Where the browser is sent to authorise.
    #[must_use]
    pub fn authorization(&self) -> String {
        format!("{}/auth", self.base)
    }

    /// Where codes and refresh tokens are exchanged.
    #[must_use]
    pub fn token(&self) -> String {
        format!("{}/token", self.base)
    }

    /// Where claims about the subject are read.
    #[must_use]
    pub fn userinfo(&self) -> String {
        format!("{}/userinfo", self.base)
    }

    /// Where the public keys are published.
    #[must_use]
    pub fn jwks(&self) -> String {
        format!("{}/certs", self.base)
    }

    /// Where a token is introspected (RFC 7662).
    #[must_use]
    pub fn introspection(&self) -> String {
        format!("{}/token/introspect", self.base)
    }

    /// Where a token is revoked (RFC 7009).
    #[must_use]
    pub fn revocation(&self) -> String {
        format!("{}/revoke", self.base)
    }

    /// Where the session is ended.
    #[must_use]
    pub fn end_session(&self) -> String {
        format!("{}/logout", self.base)
    }

    /// Where a client registers itself (RFC 7591).
    #[must_use]
    pub fn registration(&self) -> String {
        format!("{}/register", self.base)
    }
}

/// The metadata document, as OpenID Connect Discovery 1.0 defines it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    /// Must equal the `iss` of every token this provider issues.
    pub issuer: String,
    /// Authorization endpoint.
    pub authorization_endpoint: String,
    /// Token endpoint.
    pub token_endpoint: String,
    /// UserInfo endpoint.
    pub userinfo_endpoint: String,
    /// JWKS endpoint.
    pub jwks_uri: String,
    /// Dynamic client registration endpoint (RFC 7591).
    pub registration_endpoint: String,
    /// Introspection endpoint (RFC 7662).
    pub introspection_endpoint: String,
    /// Revocation endpoint (RFC 7009).
    pub revocation_endpoint: String,
    /// RP-initiated logout endpoint.
    pub end_session_endpoint: String,
    /// Scopes a client may ask for.
    pub scopes_supported: Vec<String>,
    /// Response types. Only `code` — the implicit and hybrid flows return
    /// tokens through the browser's URL, and OAuth 2.1 drops them.
    pub response_types_supported: Vec<String>,
    /// Response modes.
    pub response_modes_supported: Vec<String>,
    /// Grant types.
    pub grant_types_supported: Vec<String>,
    /// Subject identifier types.
    pub subject_types_supported: Vec<String>,
    /// Signing algorithms for the ID token.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Client authentication methods at the token endpoint.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// PKCE methods. `plain` is deliberately absent.
    pub code_challenge_methods_supported: Vec<String>,
    /// Claims that may appear in an ID token or UserInfo response.
    pub claims_supported: Vec<String>,
    /// Whether a request may ask for claims by name.
    pub claims_parameter_supported: bool,
    /// Whether `request` objects are accepted.
    pub request_parameter_supported: bool,
    /// Whether `request_uri` is accepted.
    pub request_uri_parameter_supported: bool,
}

/// Build the metadata document for a realm.
#[must_use]
pub fn metadata(public_url: &str, realm: &str) -> Metadata {
    let endpoints = Endpoints::new(public_url, realm);
    let owned = |values: &[&str]| -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    };

    Metadata {
        issuer: endpoints.issuer.clone(),
        authorization_endpoint: endpoints.authorization(),
        token_endpoint: endpoints.token(),
        userinfo_endpoint: endpoints.userinfo(),
        jwks_uri: endpoints.jwks(),
        registration_endpoint: endpoints.registration(),
        introspection_endpoint: endpoints.introspection(),
        revocation_endpoint: endpoints.revocation(),
        end_session_endpoint: endpoints.end_session(),
        scopes_supported: owned(SUPPORTED_SCOPES),
        response_types_supported: owned(&["code"]),
        response_modes_supported: owned(&["query"]),
        grant_types_supported: owned(SUPPORTED_GRANTS),
        subject_types_supported: owned(&["public"]),
        id_token_signing_alg_values_supported: owned(&["EdDSA"]),
        token_endpoint_auth_methods_supported: owned(AUTH_METHODS),
        code_challenge_methods_supported: owned(&[CHALLENGE_METHOD]),
        claims_supported: owned(&[
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "nbf",
            "jti",
            "nonce",
            "preferred_username",
            "email",
            "email_verified",
        ]),
        claims_parameter_supported: false,
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_url_hangs_off_the_configured_origin() {
        // The previous document advertised http://localhost:8080/v1 wherever
        // it was deployed.
        let doc = metadata("https://id.example.com", "master");

        for url in [
            &doc.issuer,
            &doc.authorization_endpoint,
            &doc.token_endpoint,
            &doc.userinfo_endpoint,
            &doc.jwks_uri,
            &doc.registration_endpoint,
            &doc.introspection_endpoint,
            &doc.revocation_endpoint,
            &doc.end_session_endpoint,
        ] {
            assert!(
                url.starts_with("https://id.example.com/"),
                "not under the configured origin: {url}",
            );
        }
    }

    #[test]
    fn a_trailing_slash_on_the_origin_does_not_double_up() {
        let doc = metadata("https://id.example.com/", "master");
        assert!(
            !doc.token_endpoint.contains("//realms"),
            "{}",
            doc.token_endpoint
        );
    }

    #[test]
    fn the_issuer_matches_what_tokens_will_carry() {
        // If these two ever disagree, every client rejects every token.
        let doc = metadata("https://id.example.com", "master");
        assert_eq!(
            doc.issuer,
            crate::token::issuer_for("https://id.example.com", "master"),
        );
    }

    #[test]
    fn only_the_code_flow_and_only_s256_are_advertised() {
        let doc = metadata("https://id.example.com", "master");
        assert_eq!(doc.response_types_supported, vec!["code".to_owned()]);
        assert_eq!(
            doc.code_challenge_methods_supported,
            vec!["S256".to_owned()]
        );
        assert!(
            !doc.code_challenge_methods_supported
                .contains(&"plain".to_owned()),
            "plain PKCE defeats the purpose and must never be advertised",
        );
    }

    #[test]
    fn the_advertised_grants_are_the_ones_the_code_implements() {
        // Built from the same constant the token endpoint branches on, so
        // discovery cannot promise a grant that returns unsupported_grant_type.
        let doc = metadata("https://id.example.com", "master");
        assert_eq!(doc.grant_types_supported, SUPPORTED_GRANTS);
    }

    #[test]
    fn realms_get_distinct_issuers() {
        assert_ne!(
            metadata("https://id.example.com", "master").issuer,
            metadata("https://id.example.com", "staff").issuer,
        );
    }
}
