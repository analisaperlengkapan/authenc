# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — organisations

- A tenant boundary inside a realm, with three things a group does not have:
  it can be **suspended**, stopping its members signing in without touching a
  user row; people **join by invitation**; and membership carries a role inside
  the organisation — owner, admin, member — separate from realm RBAC.
- The suspension rule is deliberately careful. No organisation → unaffected.
  One, suspended → blocked. Two, one enabled → **not** blocked, because a
  consultant working with two customers must not lose their account when one is
  suspended.
- Invitations are single-use expiring links, hash-only at rest, claimed
  atomically. The accepting account is recorded separately from the invited
  address: a forwarded link cannot be prevented, but it is visible afterwards.
- An organisation must keep one owner, and an admin cannot act on an owner —
  otherwise an admin could evict every owner and take it.
- `/api/v1/organizations` with membership and invitations, and `/api/v1/groups`
  with membership and role grants. An invitation token is returned once, at
  creation, and never by the listing.
- Domain-based auto-join is **not** built. It is only safe once a domain has
  been proved, and DNS verification does not exist here, so a claimed domain
  would be a feature that looks like a control and is not.

### Added — groups

- A hierarchy of groups per realm, each carrying role grants, with membership.
  `user::permissions` and `user::role_names` resolve *through* the tree, so a
  member of `/engineering/backend` holds the roles granted to `backend` and to
  `engineering` above it. A group feature that stores a hierarchy and never
  consults it during authorisation is a diagram, not access control.
- Inheritance runs upward only. Adding a child group cannot widen what its
  parent's members can do, and a test asserts the downward direction stays
  closed.
- Cycles are refused by a database trigger. A cycle is not merely invalid data:
  every ancestry walk over it is a query that does not terminate, and one runs
  on every authorised request.
- `group:read` and `group:write`, and `/api/v1/groups` with membership and role
  grants. Granting a role to a group needs `role:write` as well, because doing
  so hands the role to every member and descendant at once.

### Fixed

- **A permission had two names on the wire.** `whoami` sent `user:read` — the
  stored name, the one `FromStr` parses — while anything serialising the enum
  sent `user_read`, which does not parse back. `Action` had the same split
  (`login.succeeded` versus `login_succeeded`), so the console and
  `/api/v1/audit` disagreed about what an event was called. Both now serialise
  as their stored name, defined once, and a test round-trips every variant.
- **`/api/v1` could create a role but never empower it.** There was no endpoint
  to attach permissions, so every role made through the API was inert. Added
  `PUT /api/v1/roles/{role_id}/permissions`, which replaces the whole set.
- **Unknown JSON fields were silently ignored.** A request sending
  `permissions` to `POST /api/v1/roles` — a field that endpoint does not have —
  received a 201 and a useless role. Every request body now sets
  `deny_unknown_fields`, so a typo or an invented field is refused rather than
  dropped.

### Added — the audit log

- One event model in `contract::event`. `Action::ALL` is the complete,
  reviewable list of what this system can record, and the stored names are
  namespaced (`mfa.totp_enrolled`) so a prefix filter selects a category
  without enumerating it. Names are stored rather than derived from the Rust
  variant, so renaming a variant cannot orphan rows already written. The
  previous tree had three competing event types in three crates and wrote none
  of them anywhere durable.
- Every authentication path records: password success and failure, lockout as
  its own action, both steps of an MFA login, a wrong second factor, and a
  recovery code being spent. Administrative changes record too — users, roles,
  and OAuth clients including secret rotation. So does refresh-token reuse,
  which until now went only to `tracing::warn!`.
- `audit:read`, its own permission. The trail names every account in the realm
  and where each of them signed in from; being allowed to list users is not the
  same as being allowed to read everyone's movements. There is no
  `audit:write` — the log is written by the system and nothing may edit it.
- An `/admin/audit` console page: filtered by namespace and by refusals, paged,
  with actions that are evidence of an attack marked using the same rule the
  contract defines.
- `/api/v1/audit` and `/api/v1/audit.csv` for automation. An unparseable filter
  is a 400 rather than a silently ignored parameter. The CSV prefixes a leading
  `=`, `+`, `-`, or `@` with a quote: an audit log holds attacker-supplied
  strings — a user agent is whatever the client sent — and the export exists to
  be opened in a spreadsheet, where such a cell is a formula.
- `authenc purge --audit-older-than DAYS`. Opt-in and never defaulted: a log
  that trims itself on a schedule nobody chose will be empty when it is needed.
- ID tokens now carry `amr` (RFC 8176), so a relying party can tell a
  password-only sign-in from one behind a second factor. The value is
  snapshotted onto the authorization code and then onto the refresh family
  rather than recomputed at issuance: by the time a refresh mints an ID token,
  the session may be gone and the account's enrolment may have changed, so
  recomputing would answer a different question. Access tokens carry none — an
  access token describes an authorisation, not an authentication — and an
  unknown `amr` is absent rather than an empty array, because an empty array
  asserts "no methods were used".

### Added — multi-factor authentication

- **The login flow no longer returns a session when a second factor is
  enrolled.** `login::authenticate` returns an `Outcome`; a correct password
  produces a `challenge::Pending` in its own table, with a five-minute life and
  a five-attempt budget, which no session lookup can resolve. Three HTTP tests
  assert this where a browser would see it: no session cookie in the response,
  and `/api/sfn/me` reporting nobody until the second step succeeds.
- **TOTP** (RFC 6238), verified against the RFC 6238 Appendix B test vectors.
  Codes are single-use — the matched time step is persisted, so an observed
  code is worth thirty seconds rather than the ninety the ±1-step drift window
  would otherwise allow. Secrets are AES-256-GCM sealed under the master key
  with the row's id as associated data.
- **Recovery codes**: ten per account, 80 bits each, hashed with SHA-256 and
  claimed by one atomic `UPDATE`. Issued at the moment an authenticator is
  confirmed, because turning on a second factor without a way past a lost phone
  is how an account becomes unrecoverable. They deliberately do not count as an
  enrolled factor.
- **WebAuthn passkeys** through `webauthn-rs`, with the ceremony challenge held
  server-side in `webauthn_ceremonies`, the signature counter written back
  after every assertion, and the credential re-checked against the user at the
  point of use. The previous tree's `verify_registration` and
  `verify_authentication` both returned `Ok(true)` without reading their
  arguments.
- A `/security` page for enrolment, recovery codes, and passkeys, and a second
  step on the login page. The passkey ceremony is driven by ~40 lines of
  self-hosted JavaScript, because `navigator.credentials` is a browser API.
- `authenc purge` now also clears expired MFA challenges and WebAuthn
  ceremonies.

### Changed

- `MasterKey` and the AES-GCM sealing it drives moved from `authenc-oauth` to
  `authenc-identity`, since signing keys are no longer the only secret that has
  to be recoverable rather than hashed. One implementation, used by both.
- `sessions` gained `authenticated_with`, recording how a login happened at the
  moment it happens. It is not yet carried into ID tokens; see `ROADMAP.md`.
- `server_ctx::require_session` and `require_actor` now return `ServerFnError`
  rather than `AppError`. Leptos reports every server-function failure as 500
  unless the status is set explicitly, and a bare `?` on an `AppError` skipped
  that — a new endpoint answered an anonymous caller with 500 instead of 401,
  and only a test asserting the status caught it. The obvious way is now the
  correct one.
- `deny.toml` admits OpenSSL through one narrow wrapper exception for
  `webauthn-rs-core`, with the reasoning and the exit condition recorded there.
  The Dockerfile installs `libssl-dev` in the builder and `libssl3` at runtime.

### Fixed

- The `leptos build` CI job failed twice with `No such file or directory` from
  `cargo-leptos`'s `sync.rs`, ten minutes after the Rust compile succeeded and
  with nothing in the log naming the file. The failing spawn was `tailwindcss`:
  `cargo-leptos` resolves it from `PATH` before it considers downloading a
  pinned copy, and the runner image carries an entry by that name that cannot
  be executed. CI and the Dockerfile now install v4.2.1 themselves, first on
  `PATH`, and run it once to prove it works. The bundle assertions were
  strengthened from "the CSS file is non-empty" to requiring Tailwind's own
  banner and one of our `@theme` tokens.

### Added — the OAuth 2.0 and OpenID Connect endpoints

- Discovery at `/.well-known/openid-configuration` and
  `/realms/{realm}/.well-known/openid-configuration`. Every URL in the document
  is derived from the configured public origin, and the `supported` lists are
  built from the same constants the endpoints branch on, so discovery cannot
  promise a flow the token endpoint refuses. The previous build registered
  `openid_configuration` — an underscore no standard client looks for — and
  hardcoded `http://localhost:8080/v1` as the issuer wherever it was deployed.
- Authorization endpoint with the code flow and PKCE `S256`, mandatory for
  public clients. The client and the `redirect_uri` are validated before
  anything else, and a failure in either is reported on the spot rather than by
  redirecting — the previous endpoint bounced the browser to whatever
  `redirect_uri` it was handed, which is an open redirect.
- Token endpoint with the `authorization_code` and `refresh_token` grants,
  `client_secret_basic` / `client_secret_post` / `none` client authentication,
  and `Cache-Control: no-store` on every response.
- Authorization codes that are single-use, one minute long, and claimed by one
  atomic `UPDATE … WHERE used_at IS NULL` scoped to the client, so another
  client presenting a stolen code neither redeems nor burns it.
- Refresh-token rotation with **reuse detection**: every token minted from one
  authorization shares the authorization code's id as its family, and
  presenting a spent code or token revokes the whole family.
- UserInfo, returning only the claims the granted scopes allow, and refusing a
  token whose account has since been disabled.
- Introspection (RFC 7662) and revocation (RFC 7009) under **client**
  authentication. The previous implementation gated introspection on a bearer
  JWT, so any token the server had issued could inspect any other. A client may
  only introspect its own tokens, and an unknown token is `active: false` with a
  200 rather than an error.
- A consent screen at `/consent`: a server-rendered Leptos page whose approval
  is a plain HTML form posting back to the authorization endpoint, so it works
  with JavaScript off. Consent records *which* scopes were approved, so a client
  cannot quietly widen them afterwards.
- Dynamic client registration (RFC 7591), off unless
  `oauth.allow_dynamic_registration` is set.
- RP-initiated logout, honouring `post_logout_redirect_uri` only when it is
  registered for the named client.
- `AUTHENC_OAUTH__MASTER_KEY`, `__DEFAULT_REALM`, and
  `__ALLOW_DYNAMIC_REGISTRATION`. The master key is parsed once at startup, so a
  malformed value stops the process instead of surfacing as a 500 on the first
  token request; the production profile refuses the development default.
- CLI: `generate-master-key`, `rotate-keys`, and `register-client`. The two that
  mint a credential write it to stdout and nowhere else.
- `crates/server/tests/oidc.rs`: 33 tests over the assembled router, including a
  full authorize → redeem → UserInfo → refresh → rotate exchange, and a test
  asserting that `/oauth2/authorize/test`, `/oauth2/token/test`,
  `/oauth2/consent/test`, `/api/v1/auth/test-login`, and `/oidc/token` do not
  exist.

### Added — OAuth client administration

- `client:read` and `client:write` permissions, and `authenc_oauth::admin`,
  which checks them per call from an `Actor` — the same shape as
  `authenc_identity::admin`, including reporting a client in another realm as
  404 rather than 403.
- `/api/v1/clients` with `GET`, `POST`, `PATCH`, `DELETE`, and
  `POST …/{client_id}/secret`, documented in the OpenAPI document. Responses
  carry a `ClientView` rather than the internal type, so the row's database id
  and realm id are not published; an internal identifier in a public response
  becomes a compatibility obligation as soon as someone stores it.
- `/admin/clients` console page: register, list, rotate a secret, delete. The
  controls are hidden without `client:write` and the server refuses regardless,
  with a test asserting the refusal rather than the hiding.
- Secret rotation, which is what this is for: replacing a leaked client secret
  previously needed shell access to the server. The new secret is shown once —
  the only moment it exists outside the caller — and tokens the client already
  holds keep working, so it is usable during an incident and not only at setup.
- `client::update`, replacing rather than merging `redirect_uris`, because
  withdrawing one is the operation an incident needs and a merge could not do it.

### Fixed

- `crates/web/public` — the `assets-dir` cargo-leptos is configured with — was
  empty, and git does not track empty directories. Every local build passed and
  a fresh checkout had no such path, so CI failed on it. It now holds a
  self-hosted `favicon.svg` (the previous console pulled Font Awesome from a CDN
  into an admin console, with no integrity hash) and a `robots.txt` that keeps
  sign-in and consent URLs, with the client ids and redirect URIs in their query
  strings, out of search indexes. CI asserts the directory is tracked.
- `dependency review`'s `continue-on-error` moved from the job to the step. On
  the job the check still reported red, and a check that is permanently red is
  one people learn to ignore.

### Fixed — the first CI run against this branch

CI had never executed here: the workflows trigger on `main` and on pull
requests, and until #186 there was no pull request. Four jobs failed, and each
was a real problem rather than a flake.

- **`authenc-web` did not compile for release wasm.** The consent page nested a
  `<Suspense>` around a `<Card>` around a form in one `view!`, and the trait
  solver overflowed its depth limit — in the release build only, so the debug
  clippy pass this branch was verified with stayed green. The page is now three
  small components and the crate sets `recursion_limit = "256"`. `AGENTS.md`
  records the gap: `just check` does not run the release wasm build, so a page
  change needs `just build` before pushing.
- **`cargo deny` failed all four checks.** The workspace's own path
  dependencies were being reported as unpinned wildcards, which
  `allow-wildcard-paths` does not cover for crates that could be published — so
  the crates are now marked `publish = false`, which is true and was worth
  saying anyway. `chrono` was banned outright but arrives only through
  `axum-test`, a dev-dependency, so the ban now names that wrapper instead of
  failing on a test harness we do not control. Three permissive licences in the
  tree (`0BSD`, `BSL-1.0`, `CDLA-Permissive-2.0`) were not on the allow-list;
  two entries that nothing uses were removed, because an allowance nothing
  matches is policy that has stopped being checked.
- **`cargo audit` failed on two unmaintained crates.** `paste` and
  `proc-macro-error2` are build-time proc-macros reached through Leptos, with
  no advisory against either. Both are ignored with an id, a reason, and a
  revisit date, in `deny.toml` and in the workflow, so the two tools cannot
  disagree.
- **`dependency review` cannot run on this repository.** It needs Dependency
  graph plus GitHub Advanced Security, which are repository settings rather
  than anything a branch can change. The job is advisory until they are
  enabled; `cargo-deny` and `cargo-audit` cover the same ground for Rust
  dependencies and do block the build.

### Removed

- `jsonwebtoken`, declared by `crates/oauth` and never used — the JWT encoding
  is written directly against `ed25519-dalek`, because the decision that matters
  (never reading `alg` from the header) belongs to the call site rather than to
  an encoder. It pulled in `aws-lc-rs`, a C and assembly crypto stack, for
  nothing. Nine fewer crates in the dependency graph.

### Changed

- `authenc purge-sessions` is now `authenc purge`, and clears expired sessions,
  recovery tokens, authorization codes, refresh tokens, and retired signing keys
  in one pass.
- `token::verify` is now built on `verify_any_audience`, which checks issuer,
  signature, `exp`, and `nbf` but not the audience. Only UserInfo uses the
  latter, and it does so under a name that makes the omission a decision rather
  than an oversight.
- The `boundaries` CI job now checks `authenc-oauth` as well as
  `authenc-contract` and `authenc-identity`.

### Added — OAuth signing keys and tokens

- `crates/oauth` with `keyring` and `token`.
- Persistent, rotatable Ed25519 signing keys, AES-GCM-encrypted at rest under a
  key-encryption key held in configuration. The `kid` is bound in as associated
  data, so a ciphertext moved onto another key's row fails to decrypt rather
  than signing as the wrong key. One active key per realm, enforced by a
  partial unique index; retired keys keep verifying until their deadline.
- Ed25519 JWTs whose verification checks issuer, audience, expiry, not-before,
  and key id — each of which the previous verifier omitted. The algorithm is
  fixed and never read from the token header.
- `migrations/0003_oauth.sql`: signing keys, clients (with Argon2-hashed
  secrets and an exact-match redirect-URI allow-list), single-use authorization
  codes with PKCE, refresh tokens with family ids for reuse detection, and
  recorded consent.

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
