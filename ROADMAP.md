# Roadmap

What exists, what is coming, and what was removed. The point of this file is
that nothing is claimed to work until it does — the previous `TODO.md` listed
Docker, Helm charts, and an OpenAPI specification as complete when none of
those files existed in the repository.

## Delivered

### Stage 1 — Foundation

Workspace of four crates with CI-enforced layer boundaries. Leptos 0.8 SSR with
hydration via `cargo-leptos`. SQLx with migrations applied at startup and
compile-time-checked queries. Layered configuration, validated once, with
secrets redacted in logs. Axum middleware: request id, tracing, panic capture,
timeout, body limit, configured CORS, security headers. RFC 9457 error
responses. Health and readiness probes. Argon2id password hashing. Docker
image, compose stack, CI across format, lint (both targets), tests against a
real PostgreSQL, layer boundaries, wasm bundle, and MSRV.

## Planned

Each stage leaves the repository compiling, linted, and tested.

### Stage 2 — Authentication

Sessions as an opaque id in an `HttpOnly` cookie, CSRF bound to the session,
brute-force protection and account lockout, password reset and email
verification over SMTP, login and logout pages, a `CurrentUser` extractor.

### Stage 3 — Administration and RBAC

Realm, user, role, and permission management, with permission checks in the use
case rather than by URL prefix. Admin console pages backed by server functions,
plus a REST `/api/v1` surface with an OpenAPI document for automation.

### Stage 4 — OAuth 2.0 and OpenID Connect

Persistent, rotatable Ed25519 signing keys. Discovery at
`/.well-known/openid-configuration`. Authorization code with PKCE, refresh
token rotation with reuse detection, token introspection and revocation under
client authentication, UserInfo, JWKS, a consent screen, and dynamic client
registration (RFC 7591). Lands as `crates/oauth`.

### Stage 5 — Multi-factor authentication

TOTP with recovery codes, and WebAuthn passkeys through `webauthn-rs` with
genuine verification of the challenge, origin, RP ID, signature, and signature
counter.

### Stage 6 — Audit and events

Audit log in PostgreSQL with query and export, and a single event model.

### Stage 7 — Groups and organisations

Group hierarchies, multi-tenant organisations, membership, invitations.

### Stage 8 — Federation

Social login (Google, GitHub, Microsoft, Facebook, Apple) with account linking,
and LDAP/Active Directory bind plus synchronisation with just-in-time
provisioning.

Social login cannot be tested end to end without real provider credentials. The
OAuth client will be tested against a mock provider in CI, and the limitation
will be stated here and in the README rather than described as "tested".

## Removed, and why

These subsystems existed in the previous tree as code that returned invented
data. They were deleted rather than carried forward; each is a project in its
own right, and none is currently planned. All of it remains at the tag
`archive/pre-refactor`.

| Subsystem | What it actually did |
|---|---|
| SAML 2.0 | Three overlapping implementations; signature validation documented in its own comments as "simplified" |
| OID4VC / SD-JWT | Credential proofs were `format!("mock-proof-{}", uuid)` |
| Post-quantum cryptography | Key types present, never reachable from any request path |
| Clustering / Raft | Consensus was comments: `// we'd send vote requests to peers` |
| FIPS mode | A boolean field; attested to nothing |
| Kubernetes operator | Built against a Kubernetes version that is end-of-life |
| Compliance engine (GDPR/HIPAA/SOC 2) | Produced verdicts without reading any data source |
| Zero-trust risk scoring | Scored on `X-Forwarded-For`, trusted unconditionally |
| SPI plugin framework | Two competing versions; its username/password and OTP authenticators returned `success: true` for any input |
| Secret vault | The PKCS#12 backend's `set_secret()` logged a warning and returned `Ok` without storing anything |

If you need one of these, open an issue describing the use case. It will be
built properly or not at all.
