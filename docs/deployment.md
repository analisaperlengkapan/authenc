# Deployment

## Building

```bash
cargo leptos build --release
```

Produces two things:

- `target/release/authenc` — the server binary
- `target/site/` — the wasm bundle, JS shim, and compiled CSS

Both are needed. The binary locates the site directory through
`LEPTOS_SITE_ROOT`.

## Container

```bash
docker build -t authenc:local .
docker compose --profile full up
```

The image is multi-stage: a Rust builder that runs `cargo leptos build
--release` with `SQLX_OFFLINE=true` (no database is reachable at build time,
which is what the committed `.sqlx/` metadata is for), and a Debian slim
runtime carrying only the binary and the site directory, running as an
unprivileged user.

Its `HEALTHCHECK` calls `/health/ready`, not `/health/live`, so an instance
whose database is unreachable is reported unhealthy rather than being killed
and restarted.

## Configuration

Everything is set through `AUTHENC_`-prefixed environment variables, nested
with `__`. `.env.example` documents every setting. Configuration is read and
validated once at startup.

### Production profile

Set `AUTHENC_PROFILE=production`. The server then **refuses to start** if:

- the database URL still carries the `postgres:postgres` development credentials
- `AUTHENC_SERVER__PUBLIC_URL` is not `https://`
- `AUTHENC_SECURITY__HSTS` is not `true`
- `AUTHENC_SECURITY__CORS_ALLOWED_ORIGINS` contains `*`

This is deliberate. The previous build shipped a default JWT secret of
`default_jwt_secret_change_in_production` and only rejected it when an
unrelated environment variable happened to be set.

### Minimum production settings

```bash
AUTHENC_PROFILE=production
AUTHENC_SERVER__HOST=0.0.0.0
AUTHENC_SERVER__PORT=3000
AUTHENC_SERVER__PUBLIC_URL=https://id.example.com
AUTHENC_DATABASE__URL=postgres://authenc:<password>@db.internal:5432/authenc?sslmode=require
AUTHENC_SECURITY__HSTS=true
AUTHENC_SECURITY__CORS_ALLOWED_ORIGINS=https://app.example.com
AUTHENC_TELEMETRY__JSON=true
```

Use `sslmode=require` (or stronger) in the database URL. The previous data
layer hard-wired `NoTls` with no way to enable it.

## Migrations

Applied automatically at startup by `sqlx::migrate!()`. Set
`AUTHENC_DATABASE__MIGRATE_ON_START=false` and run `sqlx migrate run` as a
separate job if your deployment applies schema changes out of band — which is
the safer choice when running more than one instance.

Migrations are additive and never edited after merge.

## TLS

The server speaks plain HTTP and expects to sit behind a terminating proxy or
ingress. It does not terminate TLS itself. This is stated rather than implied:
the previous configuration had `tls_enabled`, `tls_cert_path`, and
`tls_key_path` settings that were validated at startup and then never read by
anything.

Because of that, `AUTHENC_SERVER__PUBLIC_URL` must reflect the **externally
visible** origin, not the address the process binds — it is what cookie
scoping and absolute URLs are derived from.

## Observability

- **Logs** — `tracing`, JSON when `AUTHENC_TELEMETRY__JSON=true`. `RUST_LOG`
  overrides the configured filter at runtime.
- **Correlation** — every response carries `x-request-id`; an incoming one is
  propagated.
- **Probes** — `/health/live` for liveness (touches nothing), `/health/ready`
  for readiness (503 when the database is down).

Wire the liveness probe to restarts and the readiness probe to load-balancer
membership. Conflating them turns a database blip into a restart loop.

## Scaling

The server is stateless; sessions live in PostgreSQL. Run as many instances as
you need behind a load balancer.

Set `AUTHENC_DATABASE__MAX_CONNECTIONS` with the total in mind: instances
multiplied by max connections must stay under the server's `max_connections`.
