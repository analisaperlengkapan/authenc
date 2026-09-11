# Authenc

Identity and access management, built as one Rust workspace: a Leptos
server-rendered frontend and an Axum backend over PostgreSQL.

> **Status: foundation, authentication, and the OAuth/OIDC provider.** This
> repository was rebuilt from
> scratch in August 2026. What is documented below is implemented and tested;
> everything else is in [ROADMAP.md](ROADMAP.md) and is not claimed to exist.
> It has not had an independent security review — see [SECURITY.md](SECURITY.md).

## Why it is built this way

One language across the whole stack means the type that a Leptos view renders
is the same type an Axum handler returns, checked by the compiler. Validation
rules in `crates/contract` run identically in the browser and on the server, so
they cannot drift. Server functions replace a hand-written API client entirely.

## Getting started

Requires Rust 1.94, Docker (for PostgreSQL), and
[`just`](https://github.com/casey/just).

```bash
git clone https://github.com/analisaperlengkapan/authenc.git
cd authenc
just setup    # toolchain, tools, database, migrations
just seed admin@example.com 'a long passphrase you will remember'
just dev      # http://localhost:3000/login, then /admin
```

`just setup` copies `.env.example` to `.env`. Every setting is documented
there.

Without `just`:

```bash
rustup target add wasm32-unknown-unknown
cargo install cargo-leptos sqlx-cli --locked
docker compose up -d postgres
cp .env.example .env
sqlx migrate run --source migrations
cargo leptos watch
```

## Layout

```
crates/contract   entities, DTOs, AppError, validation   — wasm + native
crates/identity   realms, users, roles, credentials      — native
crates/oauth      OAuth 2.0 / OpenID Connect provider    — native
crates/web        Leptos pages, components, server fns   — wasm + native
crates/server     composition root, HTTP stack, CLI      — native
migrations/       sqlx migrations, applied at startup
docs/             architecture, security model, deployment
```

Dependencies run one way: `contract ← identity ← oauth ← server` and
`contract ← web ← server`. Neither `identity` nor `oauth` may depend on `axum`
or `leptos`, which is what lets every protocol rule be tested without an HTTP
stack. CI fails the build if a crate reaches across a layer, so the structure
is enforced rather than merely intended.

## What works today

| | |
|---|---|
| Server-rendered pages with hydration | `cargo leptos build` produces the wasm bundle; CI asserts it exists |
| Server functions | `/api/sfn/*`, executing against PostgreSQL |
| Migrations | applied by `sqlx::migrate!()` at startup |
| Password hashing | Argon2id at OWASP parameters, with per-user rehash on policy change |
| Configuration | layered defaults → TOML → env, validated once, secrets redacted in logs |
| Health probes | `/health/live` and `/health/ready`, answering different questions |
| Middleware | request id, tracing, panic capture, timeout, body limit, CORS from config, security headers |
| Error responses | RFC 9457 `application/problem+json`, internal detail never leaked |
| Sessions | opaque token in an `HttpOnly`, `SameSite=Lax` cookie; only its hash is stored |
| Login and logout | server functions, with the login page rendered server-side |
| Brute-force protection | per-identifier and per-address lockout over a rolling window |
| User enumeration resistance | wrong password and unknown user return the identical response |
| CSRF | `/api/v1`: token bound to the session, compared in constant time. `/api/sfn`: `Sec-Fetch-Site`/`Origin`, because the Leptos client sends no header of ours |
| RBAC groundwork | roles resolved from the database at the point of use, never from a token |
| Password reset | single-use expiring link; completing it revokes every session and lifts the lockout |
| Email verification | single-use expiring link; a link cannot verify an address changed after it was sent |
| Mail | SMTP via lettre, or a logging transport for development that production refuses to start with |
| Admin console | server-rendered pages for users and roles, with a session guard that redirects on the server |
| RBAC | typed permissions checked in the use case, resolved from the database per request |
| REST API | `/api/v1` for automation, with an OpenAPI document at `/api/v1/openapi.json` |
| Tenant isolation | an actor cannot read or change anything in another realm, and gets 404 rather than 403 |
| OpenID Connect discovery | `/.well-known/openid-configuration` — with hyphens, so standard clients find it |
| Authorization code + PKCE | `S256` only, mandatory for public clients; a code is single-use and client-bound |
| Refresh token rotation | reuse is detected, not merely refused: a replayed token revokes its whole family |
| Signing keys | persistent, rotatable, AES-GCM-encrypted at rest; retired keys keep verifying until their deadline |
| Client registry | Argon2-hashed secrets, exact-match redirect URIs, `client_secret_basic`/`_post`/`none` |
| Introspection and revocation | RFC 7662 and RFC 7009, under client authentication, not a bearer token |
| UserInfo | claims filtered by granted scope; a disabled account stops working immediately |
| Consent | a server-rendered form that works without JavaScript, recording *which* scopes were approved |
| Dynamic client registration | RFC 7591, off unless switched on |
| Client administration | `/api/v1/clients` and a console page; secret rotation shows the new secret once |
| Two-step sign-in | a correct password returns a *challenge*, not a session, when a factor is enrolled — a different type, in a different table |
| TOTP | RFC 6238, checked against the RFC's own test vectors; a code is single-use, so an observed one expires in 30s rather than 90 |
| Recovery codes | ten per account, 80 bits each, single-use; issued the moment an authenticator is confirmed |
| Passkeys | WebAuthn via `webauthn-rs`; the challenge stays on the server and the signature counter is written back after every assertion |
| Audit log | one event model, `Action::ALL` is the complete list; every authentication path and every administrative change records |
| `amr` in ID tokens | snapshotted at sign-in and carried through code and refresh, so a relying party can tell a password from a passkey |
| Audit access | its own `audit:read` permission — listing users does not confer reading everyone's movements |
| Audit retention | opt-in via `authenc purge --audit-older-than DAYS`; nothing trims the log on a schedule nobody chose |
| Audit API | `/api/v1/audit` and `/api/v1/audit.csv`; a bad filter is refused, and the CSV neutralises spreadsheet formulas |
| Groups | a hierarchy per realm; permissions resolve through it, so a member of a child holds its ancestors' roles |
| Group safety | cycles refused by a database trigger; inheritance runs upward only, so nesting is never an escalation |
| Organisations | a tenant boundary inside a realm: suspendable, joined by invitation, with owner/admin/member roles |
| Suspension | disabling an organisation stops its members signing in — unless they belong to another that is still enabled |
| Invitations | single-use expiring links, hash-only at rest, recording who actually accepted rather than only who was invited |
| Group and org API | `/api/v1/groups` and `/api/v1/organizations`; an invitation token is returned once and never listed back |
| Social login | Google, GitHub, Microsoft, Facebook, Apple, or any OIDC provider; per realm, client secret sealed at rest |
| Account identity | the upstream `sub`, never the email — an address can be reassigned, and at several providers the holder can change it |
| Account adoption | off by default; needs the operator's opt-in *and* the upstream's own `email_verified` for that sign-in |
| Social login and MFA | a federated sign-in returns the same challenge a password does, so adding a provider is not a way around an enrolled factor |
| Login CSRF | `state` is bound to a `SameSite=Lax` cookie as well as the URL; the server-side row alone does not stop it |
| GitHub addresses | read from `/user/emails`, not the profile — the profile address is typed in by the account holder and never checked |
| API tokens | `Authorization: Bearer` for `/api/v1`, so automation does not have to hold somebody's password |
| Token authority | never more than its maker had, and narrowed at every request to what the bound account holds *now* |
| Token revocation | immediate; disabling the account kills its tokens without anybody remembering to revoke them |
| CLI | `authenc seed`, `migrate`, `purge`, `generate-master-key`, `rotate-keys`, `register-client` — no test endpoints in the router |

Social login is **tested against a mock provider, not a real one.** No
provider's credentials can run in CI, so `oauth::social::Transport` is a trait
and the tests exercise the rules that are ours: the state binding, PKCE, the
`nonce`/`iss`/`aud`/`exp` checks, and each provider's claim mapping. What has
not been exercised is a live Google or GitHub response.

## Development

```bash
just check     # fmt + clippy (both targets) + tests + layer boundaries
just test      # tests only
just build     # release build with the optimised wasm bundle
```

Two things to know before your first change:

- **Never use `--all-features`.** Leptos' `hydrate` and `ssr` features are
  mutually exclusive. Build native with `--features ssr`, wasm with
  `--features hydrate`.
- **After changing any SQL, run `just sqlx-prepare`** and commit `.sqlx/`. CI
  builds without a database and relies on that metadata.

Database tests use `#[sqlx::test]`, which gives each test its own throwaway
database. They need PostgreSQL running; they do not mock it.

## Documentation

- [AGENTS.md](AGENTS.md) — conventions and invariants, for humans and coding agents
- [docs/architecture.md](docs/architecture.md) — why the crates are cut this way
- [docs/security-model.md](docs/security-model.md) — sessions, CSRF, secrets
- [docs/deployment.md](docs/deployment.md) — Docker and configuration
- [ROADMAP.md](ROADMAP.md) — what is not built yet
- [SECURITY.md](SECURITY.md) — reporting a vulnerability
- [CONTRIBUTING.md](CONTRIBUTING.md)

## History

The tree before August 2026 is preserved at the tag `archive/pre-refactor`. It
did not compile, its CI had failed 926 consecutive runs, and several of its
authenticators returned success without verifying anything. It was replaced
rather than repaired. [ROADMAP.md](ROADMAP.md) records which of its advertised
features are genuinely planned.

## Licence

[Apache-2.0](LICENSE).
