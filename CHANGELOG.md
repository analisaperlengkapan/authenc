# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — admin console

- Server-rendered `/admin` pages for the overview, users, and roles, backed by
  server functions.
- Session guard that redirects on the **server** before any console markup is
  produced. The previous console read `localStorage` in a route closure, so the
  page was delivered first and redirected afterwards.
- Actions are hidden when the viewer lacks the permission, using the same rule
  the server enforces — `LoginResponse::can` and `Actor::can` share one
  implementation, and a test asserts they agree for every permission. A further
  test asserts the hiding is only a hint: the server function still refuses.
- `DataTable` primitive with keyed `<For>`, replacing the table chrome the
  previous console copy-pasted across eight pages and rebuilt wholesale on
  every refetch.

### Changed

- Dev and test profiles use `debug = "line-tables-only"`. Full debug info cost
  26 GB of build artefacts on this workspace; line tables still give readable
  backtraces and panic locations.

### Added — administration and RBAC

- Typed `Permission` enum with `Actor::require`, checked inside each use case
  rather than by a URL-prefix middleware. Write implies read.
- Permissions resolved from `role_permissions` per request. Holding a role
  named `admin` grants nothing by itself; an unrecognised permission row is
  ignored with a warning rather than guessed.
- Tenant isolation checked separately from permissions: reaching into another
  realm returns 404, not 403.
- A disabled account fails authentication immediately, and disabling a user
  revokes their sessions. An actor cannot disable or delete itself.
- Listing is bounded server-side regardless of the requested limit.
- REST `/api/v1` for automation — users, roles, realm, whoami, permissions —
  with an OpenAPI document at `/api/v1/openapi.json` and `/api/v1/csrf` for
  cookie-authenticated clients.

### Added — credential recovery

- Password reset and email verification as single-use expiring links, with only
  the token hash stored and redemption as one atomic UPDATE.
- Completing a reset revokes every session for the user and clears their
  failure history; a policy-failing password is rejected before the token is
  spent.
- A verification link cannot confirm an address that changed after it was sent.
- Requesting a reset returns an identical response for known addresses, unknown
  addresses, and unknown realms.
- `Mailer` trait with SMTP (`lettre`), logging, and capturing implementations.
  The production profile refuses to start on the logging transport.
- `/forgot-password`, `/reset-password`, and `/verify-email` pages. The token is
  read from the **query** string — the previous console used `use_params`,
  which reads path parameters, on a route with no path segment, so email
  verification could never complete.

### Added — authentication

- Sessions: an opaque token in an `HttpOnly`, `SameSite=Lax` cookie, with only
  its SHA-256 hash stored. `Secure` and `__Host-` prefixed under the production
  profile. Expiry enforced on lookup; logout deletes the server-side row.
- CSRF: a token derived from a per-session secret, compared in constant time,
  so one session's token does not validate against another. Plus a
  `Sec-Fetch-Site`/`Origin` check.
- Brute-force lockout per identifier and per address over a rolling window. It
  holds even against the correct password, lifts on its own, and does not lock
  out unrelated accounts.
- User-enumeration resistance: a wrong password and an unknown user return the
  identical response, and the password is verified against a real Argon2 hash
  even when no such user exists so the timing matches. An unknown realm returns
  401, not 404.
- `log_in`, `log_out`, and `current_user` server functions, and a
  server-rendered login page with shared client/server validation.
- `CurrentUser` extractor; roles resolved from the database at the point of
  use rather than carried in a token.
- `authenc` CLI: `serve`, `migrate`, `seed`, `purge-sessions`. Seeding creates
  the first realm, administrator, and `admin` role — so no test endpoint needs
  to exist in the router.
- Server-function failures now carry the correct HTTP status instead of a
  blanket 500, so a wrong password is a 401 and a lockout is a 429.

### Added — foundation

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
