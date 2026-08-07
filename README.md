# Authenc

Identity and access management, built as one Rust workspace: a Leptos
server-rendered frontend and an Axum backend over PostgreSQL.

> **Status: foundation.** This repository was rebuilt from scratch in August
> 2026. What is documented below is implemented and tested; everything else is
> in [ROADMAP.md](ROADMAP.md) and is not claimed to exist. Do not run this in
> production yet — the authentication slice lands in stage 2.

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
just dev      # http://localhost:3000
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
crates/web        Leptos pages, components, server fns   — wasm + native
crates/server     composition root, HTTP stack, CLI      — native
migrations/       sqlx migrations, applied at startup
docs/             architecture, security model, deployment
```

Dependencies run one way: `contract ← identity ← server` and
`contract ← web ← server`. CI fails the build if a crate reaches across a
layer, so the structure is enforced rather than merely intended.

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
