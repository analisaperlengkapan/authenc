# Security model

What this system assumes, what it guarantees, and what it does not. Statements
here are backed by tests; where something is not yet built, this file says so
rather than describing an intention as a property.

## Status

Stages 1 and 2 of the rebuild. Passwords, sessions, CSRF, brute-force lockout,
configuration, transport headers, and error handling are in place and tested.
OAuth 2.0, OpenID Connect, and multi-factor authentication do not exist yet.

## Threat model

Assumed capable of:

- reading anything the browser can read, via injected script (XSS)
- making a browser issue authenticated cross-site requests (CSRF)
- reading the database, if it leaks
- reading logs, metrics, and crash dumps
- replaying a captured request

Out of scope: a compromised server host, a malicious administrator, and
side-channel attacks against the hardware.

## Credentials

**Passwords** are hashed with Argon2id at OWASP parameters — 19 MiB, 2
iterations, 1 lane — and stored as a full PHC string, so the parameters travel
with each hash. `PasswordHasher::needs_rehash` detects hashes made under weaker
settings so they can be upgraded on the user's next successful login without a
mass reset.

A malformed stored hash is an **error**, never a successful verification. This
has a test of its own (`a_malformed_stored_hash_is_an_error_not_a_successful_login`)
because the failure mode it guards against — a verifier returning success when
it could not actually check — is exactly what the previous tree shipped in
`verify_authentication()`, `UsernamePasswordAuthenticator`, and
`OTPAuthenticator`.

**Usernames and emails are unique per realm, compared case-insensitively**,
enforced by a functional unique index in the schema. Treating `Alice` and
`alice` as separate accounts is an account-takeover route during password
reset.

## Sessions

- The browser holds an **opaque token** in a cookie: `HttpOnly`,
  `SameSite=Lax`, `Path=/`. Nothing readable by JavaScript authenticates a
  request, so an injected script has nothing to steal. The previous console
  kept a JWT in `localStorage`. Under the production profile the cookie is
  additionally `Secure` and `__Host-` prefixed, binding it to exactly one
  origin so a sibling subdomain cannot overwrite it. Development uses a plain
  name because a browser will not store a `Secure` cookie over plain HTTP.
- The server stores only a **SHA-256 hash** of the token, so a database
  disclosure yields hashes rather than live sessions. A test asserts the
  plaintext never appears in the row.
- Expiry is enforced **on lookup**, not merely recorded, and logging out
  deletes the server-side row as well as the cookie — clearing only the cookie
  would leave a working session for anyone who captured the value.

## CSRF

The token is derived from a per-session secret and compared in **constant
time**; a token minted for one session does not validate against another, and a
test asserts exactly that. The previous implementation checked only that the
submitted value was at least 32 characters long, with no server-side state, no
HMAC, and no session binding, so any string of the right length worked
everywhere.

Safe methods are exempt. `Sec-Fetch-Site`/`Origin` is checked as well, since a
browser sets it and page script cannot forge it.

## Resisting brute force and enumeration

- **A wrong password and an unknown user produce the identical response** —
  same status, same body. The password is verified against a real Argon2 hash
  even when no such user exists, so response time does not distinguish the two
  either. An unknown *realm* returns 401 rather than 404, so realm names cannot
  be probed.
- **Lockout is checked before the password is**, so a locked account costs an
  attacker a database lookup rather than an Argon2 verification. It is scoped
  per identifier and per address over a rolling window, holds even against the
  correct password, lifts on its own once attempts stop, and does not lock out
  other accounts.
- **Every attempt is recorded**, successful or not — that record is both the
  lockout input and the answer to "was this account attacked?".
- The client address comes from the transport connection only.
  `X-Forwarded-For` is deliberately not consulted; the previous code trusted it
  unconditionally, letting any client choose the address it was judged by.

## Roles

Resolved from the database at the point of use, never carried in a token. The
previous system minted tokens with `roles: None` and then checked
`roles.contains("admin")`, so no token it issued could satisfy an admin check —
every role-gated endpoint was permanently 403 while everything else was
permanently open.

## Operational tasks

`authenc seed`, `migrate`, and `purge-sessions` are CLI subcommands. Nothing
equivalent exists as an HTTP endpoint. The previous router served
`/oauth2/token/test`, `/oauth2/consent/test`, and `/api/v1/auth/test-login`
unauthenticated in production, granting consent for a hardcoded user id.

## Secrets

Configuration secrets use the `Secret` newtype: `Debug` renders
`Secret([redacted])`, and the buffer is zeroed on drop. A test asserts that
formatting the whole `Config` does not reveal the database password, because a
config struct reaches logs and panic messages.

`Authorization` and `Cookie` request headers are marked sensitive before the
tracing layer sees them.

## Error disclosure

`AppError::Internal` carries context for the log and collapses to
`"An internal error occurred."` on the wire. Two tests assert that a connection
string embedded in an internal error does not appear in the response body.
Validation errors keep their detail, including the offending field name,
because the caller needs it and it reveals nothing.

## Transport

Every response carries `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`,
and `Cross-Origin-Opener-Policy: same-origin`.

HSTS is emitted **only when configured on**, and the production profile refuses
to start without it. The previous server emitted HSTS unconditionally while
serving plain HTTP and never implementing TLS at all.

CORS comes from configuration. An empty allow-list means same-origin only,
which is the default. `*` is rejected under the production profile. A test
asserts that an unlisted origin is not reflected.

## Availability

The release profile uses `panic = "unwind"` with `CatchPanicLayer`, so a panic
in one request becomes a 500 for that request. Under `panic = "abort"` — which
this project previously shipped — any panic in any handler killed the whole
process, turning a single malformed request into a denial of service.

Requests are bounded by a timeout and a body-size limit, both configured.

Readiness returns **503**, not 500, when the database is unreachable, so an
orchestrator removes the instance from rotation instead of restarting it.
Liveness deliberately touches no dependency.

## Not yet addressed

General per-endpoint rate limiting is not implemented; only the login path is
protected, by the lockout above. The previous implementation was a
process-local counter keyed per IP *and path*, so the effective budget was the
configured limit multiplied by the number of paths, and it coordinated across
no instances. A replacement will be shared-state and keyed on the identity
being attacked.

Password reset and email verification are not implemented — the token
primitive and schema exist, but nothing sends mail.

No independent security review has been performed.
