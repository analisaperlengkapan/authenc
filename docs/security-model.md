# Security model

What this system assumes, what it guarantees, and what it does not. Statements
here are backed by tests; where something is not yet built, this file says so
rather than describing an intention as a property.

## Status

Stage 1 of the rebuild. Passwords, configuration, transport headers, and error
handling are in place. **Sessions, CSRF, and login land in stage 2** — until
then there is no authentication to reason about, and the service must not be
exposed.

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

## Sessions (stage 2)

Design, recorded here so it is reviewable before it is written:

- The browser holds an **opaque identifier** in a cookie: `HttpOnly`, `Secure`,
  `SameSite=Lax`, `Path=/`, `__Host-` prefixed. Nothing readable by JavaScript
  authenticates a request, so an injected script has nothing to steal. The
  previous console kept a JWT in `localStorage`.
- The server stores only a **hash** of the session token, so a database
  disclosure does not hand over live sessions.
- **CSRF** uses double-submit with a token bound to the session — the
  `csrf_secret` column exists in `0001_identity_core.sql` for this. A token
  minted for one session must not validate against another. The previous
  implementation checked only that the submitted value was at least 32
  characters long, with no server-side state, no HMAC, and no session binding.

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

Rate limiting is not implemented. The previous implementation was a
process-local counter keyed per IP *and path*, so the effective budget was the
configured limit multiplied by the number of paths, and it coordinated across
no instances. A replacement will be shared-state and keyed on the identity
being attacked, and will arrive with the login flow in stage 2.

No independent security review has been performed.
