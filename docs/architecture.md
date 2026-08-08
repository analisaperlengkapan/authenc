# Architecture

## The shape

Four crates, dependencies running one way:

```
                 ┌──────────────────┐
                 │ authenc-contract │  entities, DTOs, AppError, validation
                 │  wasm + native   │  no axum, no sqlx, no leptos
                 └────────┬─────────┘
                          │
         ┌────────────────┼────────────────┐
         │                                 │
┌────────▼─────────┐            ┌──────────▼───────┐
│ authenc-identity │            │   authenc-web    │  Leptos pages,
│      native      │            │  wasm + native   │  components,
│ realms, users,   │            │                  │  #[server] fns
│ roles, creds,    │◄───────────┤ (ssr feature)    │
│ sessions         │            └──────────┬───────┘
└────────┬─────────┘                       │
         │                                 │
         └────────────────┬────────────────┘
                          │
                 ┌────────▼─────────┐
                 │  authenc-server  │  composition root: config, HTTP
                 │      native      │  stack, leptos_axum, CLI
                 └──────────────────┘
```

CI fails the build if `authenc-contract` acquires `axum`, `sqlx`, or `leptos`,
or if `authenc-identity` acquires `axum` or `leptos`. The previous tree split
into eight crates and then let `services`, `crypto`, and `core` all depend on
`axum`, so the split enforced nothing at all. A boundary that is not checked is
a comment.

## Why these cuts

**`contract` exists because two targets must agree.** The Leptos view running
in the browser and the Axum handler running on the server exchange these types.
Putting them in one wasm-compatible crate makes agreement a compile error to
break, instead of something a hand-written API client has to keep up with.

**`identity` keeps rules and SQL together.** The obvious alternative is a
repository trait in one crate and its Postgres implementation in another, so
the rules can be tested against a mock. This project does not do that. It is
committed to PostgreSQL, and `#[sqlx::test]` gives every test a throwaway
database — which catches the constraint violations, the case-sensitivity
collisions, and the cascade behaviour that a mock repository is definitionally
blind to. Two crate boundaries is a high price for the ability to not test
against the real engine.

Traits are still used where substitution genuinely buys something: sending mail
and talking to an external identity provider, neither of which can run in CI.

**`web` is not a frontend.** Its `#[server]` function bodies compile and run on
the server, reaching straight into `identity`. Calling the crate `frontend`
would misdescribe half its contents; calling it `console` would undersell it,
since it also holds login, password reset, and the end-user account area. It is
compiled twice — to wasm with `hydrate`, natively with `ssr` — and the two
features are mutually exclusive, which is why `--all-features` must never be
used anywhere in this repository.

The wasm entry point lives in `web/src/lib.rs` rather than in a crate of its
own. The official Leptos workspace template separates it so that
`crate-type = ["cdylib"]` does not appear in the graph the server links; the
real cost of folding it back in is one unused `.so` produced during native
builds, which is a smaller price than a crate whose entire content is a
ten-line function.

**`server` is the only place that knows everything.** Configuration, the
database pool, the middleware stack, and the Leptos application meet here and
nowhere else.

## Request paths

There are two, deliberately.

**Server functions** (`/api/sfn/*`) back the web application. They are ordinary
Rust functions annotated `#[server]`; the argument and return types are the
contract, and there is no route string, no serialisation code, and no client
wrapper to get wrong. The previous console needed sixty lines of hand-written
`authenticated_request` plumbing, which silently rejected `PATCH` — so renaming
a passkey failed without ever reaching the network.

**HTTP endpoints** serve everything that is not the web application: health
probes, the OAuth 2.0 and OpenID Connect protocol endpoints under
`/realms/{realm}/protocol/openid-connect/`, and a REST `/api/v1` surface for
automation. These have to be real HTTP because their callers are
specifications and scripts, not our own browser code.

Both sit on the same use cases in `identity` and `oauth`. Neither is the
"real" one.

The consent screen is the one place the two meet: the authorization endpoint
redirects to a Leptos page, and that page posts a plain HTML form straight back
to the authorization endpoint. It is a form rather than a server function on
purpose — a hydration failure then degrades to a working page rather than a
dead button, and the endpoint re-validates every parameter instead of trusting
what the page decided.

## Authorisation

Decided in the use case, from an `Actor`, never by matching a URL prefix in
middleware. The previous code gated on path prefixes, which meant a route
registered on the wrong router silently lost its access control — and in fact
about thirty-eight account endpoints returned HTTP 500 because they expected an
extension that the middleware they were never wrapped in would have inserted.

## Errors

One `AppError` in `contract`, one status-code mapping, one conversion to an
HTTP response in `server/src/error.rs`. Responses are RFC 9457
`application/problem+json`. `AppError::Internal` collapses to a fixed message
for the client; the real one is logged. The previous codebase carried two
hand-maintained copies of the status mapping which had already drifted apart.

## Middleware order

`server/src/http.rs` builds the stack with `tower::ServiceBuilder`, which
applies layers in written order, so the code reads the way it executes. This is
not cosmetic: axum's `.layer()` makes the *last* call outermost, and the
previous server chained `.layer()` calls under a comment claiming rate limiting
ran "first (early rejection)" when it was in fact innermost — running only
after the body had been read and validated.

## Configuration

Layered: defaults, then `config/default.toml`, then `config/{profile}.toml`,
then `AUTHENC_`-prefixed environment variables. Read and validated once at
startup into an immutable value. Under the production profile the server
refuses to start on development credentials, a non-HTTPS public URL, HSTS
disabled, or a wildcard CORS origin — rather than falling back to a default, as
the previous build did with `default_jwt_secret_change_in_production`.
