# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Four-crate workspace — `contract`, `identity`, `web`, `server` — with
  dependency directions enforced by a CI job rather than by convention.
- Leptos 0.8 server-side rendering with hydration, built by `cargo-leptos`. CI
  asserts the wasm bundle is actually produced.
- Server functions under `/api/sfn`, executing against PostgreSQL.
- SQLx with compile-time-checked queries, offline metadata in `.sqlx/`, and
  migrations applied at startup by `sqlx::migrate!()`.
- `migrations/0001_identity_core.sql`: realms, users, password credentials,
  roles, permissions, sessions, and login attempts.
- Argon2id password hashing at OWASP parameters, with per-user rehash detection.
- Layered configuration — defaults, TOML, `AUTHENC_` environment variables —
  validated once at startup, with secrets redacted in `Debug` output and zeroed
  on drop. The production profile refuses to start on development credentials,
  a non-HTTPS public URL, disabled HSTS, or wildcard CORS.
- Middleware stack in explicit outermost-first order: sensitive-header
  redaction, request id, tracing, panic capture, timeout, body limit,
  configured CORS, security headers, compression.
- RFC 9457 `application/problem+json` error responses from a single error type
  with a single status mapping.
- Liveness and readiness probes that answer different questions; readiness
  returns 503, not 500, when the database is unreachable.
- Tailwind v4 design tokens and the first design-system components.
- Multi-stage Dockerfile running as an unprivileged user, compose stack with
  PostgreSQL and MailHog, and a `justfile`.
- CI covering format, clippy on both targets, tests against a real PostgreSQL,
  layer boundaries, the Leptos build, and MSRV; plus scheduled `cargo-deny`,
  `cargo-audit`, and dependency review.
- `AGENTS.md`, `SECURITY.md`, `ROADMAP.md`, and `docs/`.
- `Cargo.lock` is now committed and builds use `--locked`.

### Removed

The tree before this release is preserved at the tag `archive/pre-refactor`. It
did not compile, its CI had failed 926 consecutive runs, and much of its
feature surface returned invented data. Removed rather than carried forward:

- SPI plugin framework, whose username/password and OTP authenticators returned
  `success: true` for any input, and whose WebAuthn verifier returned `Ok(true)`
  without checking anything.
- Unauthenticated test endpoints — `/oauth2/authorize/test`, `/oauth2/token/test`,
  `/oauth2/consent/test`, `/api/v1/auth/test-login` — that were registered in
  the production router.
- The mock OIDC provider that issued valid signed tokens for `demo_user`
  without credentials, alongside a second, unreachable OIDC implementation.
- SAML, OID4VC/SD-JWT, post-quantum cryptography, clustering, FIPS mode, the
  Kubernetes operator, the compliance engine, zero-trust scoring, and the
  secret vault whose `set_secret()` discarded what it was given.
- The Leptos 0.6 CSR console, which no automation ever built and which the
  server never served, and the empty `static/` shell it served instead.
- 129 test files, including 68 that reported success without asserting anything
  when no database was present, and 27 occurrences of `assert!(true)`.
- 869 lines of Playwright scripts driving selectors from a deleted UI.
- `ANALYSIS.md`, `PLAN.md`, `TODO.md`, `plan_client_ui.md`,
  `update_changelog.js`, and a 1,554-line `copilot-instructions.md` whose
  claims contradicted the tree.

[Unreleased]: https://github.com/analisaperlengkapan/authenc/compare/archive/pre-refactor...HEAD
