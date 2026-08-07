# Contributing

Thanks for taking an interest. This document is short because [AGENTS.md](AGENTS.md)
holds the conventions — it is written for coding agents but applies equally to
people.

## Setting up

Requires Rust 1.94, Docker, and [`just`](https://github.com/casey/just).

```bash
just setup   # toolchain targets, cargo-leptos, sqlx-cli, database, migrations
just dev     # http://localhost:3000
```

`just setup` copies `.env.example` to `.env`; every setting is documented in
that file.

## Before you open a pull request

```bash
just check
```

That runs format, clippy on both the native and wasm targets, the test suite
against a real PostgreSQL, and the layer-boundary check — the same things CI
runs, in the same order.

Two things catch people out:

- **`--all-features` does not work here** and never will. Leptos' `hydrate` and
  `ssr` features are mutually exclusive. Use `--features ssr` for native and
  `--features hydrate` for wasm.
- **Changing any SQL requires `just sqlx-prepare`**, and the resulting `.sqlx/`
  change must be committed. CI builds without a database and depends on it.

## What a good change looks like

**Tests prove behaviour, not coverage.** A test should fail if you delete the
implementation. Deleting it and re-running is a cheap way to check. Name the
test for the property it establishes — `readiness_reports_503_when_the_database_is_gone`
— rather than for the function it calls.

**Database tests use `#[sqlx::test]`**, which provisions a throwaway database
per test. Do not mock the repository layer; testing against real PostgreSQL is
what catches the constraint and case-sensitivity behaviour that matters.

**A test that cannot run must fail or be `#[ignore]`d.** Never return early
with a `println!`. The previous test suite had sixty-eight tests that reported
success while asserting nothing whenever the database was absent — which, in a
CI job that had no database, was always.

**Never add a function that returns success without doing the work.** If it is
not implemented, do not add it. `todo!()` is honest; `Ok(true)` is not.

**Comments explain why.** If the reason for a line is not obvious, say it. Do
not narrate what the code already says.

## Commits

Conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.

In the pull request, say what you did *not* do, and what you could not verify.
A partial change described accurately is useful; a partial change described as
complete is not.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies to every interaction here.
