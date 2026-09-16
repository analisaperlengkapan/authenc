-- Core identity schema.
--
-- This is migration 0001. The previous repository shipped two competing
-- migration trees -- `migrations/` starting at 008 (001-007 were simply
-- missing) and a second timestamped set inside the database crate -- neither
-- of which was ever executed, because `run_migrations()` only logged the byte
-- count of a schema file. This tree starts from nothing and is applied by
-- `sqlx::migrate!()` at startup.

-- gen_random_uuid() is built into PostgreSQL 13+; no extension needed.

-- ---------------------------------------------------------------------------
-- Realms: isolated tenants. Everything else is scoped to one.
-- ---------------------------------------------------------------------------
CREATE TABLE realms (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name          TEXT        NOT NULL,
    display_name  TEXT        NOT NULL,
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- The slug appears in OIDC issuer URLs, so constrain it at the database
    -- level too rather than trusting every write path to have validated it.
    CONSTRAINT realms_name_is_slug CHECK (name ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'),
    CONSTRAINT realms_name_unique UNIQUE (name)
);

-- ---------------------------------------------------------------------------
-- Users. Credentials deliberately live in a separate table (see below).
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id       UUID        NOT NULL REFERENCES realms (id) ON DELETE CASCADE,
    username       TEXT        NOT NULL,
    email          TEXT        NOT NULL,
    email_verified BOOLEAN     NOT NULL DEFAULT FALSE,
    first_name     TEXT,
    last_name      TEXT,
    enabled        BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Usernames and emails are unique per realm and compared case-insensitively:
-- treating `Alice` and `alice` as different accounts is an account-takeover
-- vector during password reset.
CREATE UNIQUE INDEX users_realm_username_key ON users (realm_id, lower(username));
CREATE UNIQUE INDEX users_realm_email_key    ON users (realm_id, lower(email));

-- ---------------------------------------------------------------------------
-- Password credentials.
--
-- Separate from `users` so that an accidental `SELECT *` on the user table --
-- or a new column added to a DTO -- cannot leak a hash. The previous codebase
-- had exactly this problem in reverse: it stored OAuth client secrets in a
-- column named `client_secret_hash` while writing the plaintext into it.
-- ---------------------------------------------------------------------------
CREATE TABLE user_passwords (
    user_id       UUID        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    -- Full PHC string ($argon2id$v=19$m=..,t=..,p=..$salt$hash), so parameters
    -- travel with the hash and can be upgraded per-user on next login.
    phc           TEXT        NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Roles and permissions.
-- ---------------------------------------------------------------------------
CREATE TABLE roles (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id    UUID        NOT NULL REFERENCES realms (id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT roles_realm_name_unique UNIQUE (realm_id, name)
);

CREATE TABLE permissions (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id    UUID        NOT NULL REFERENCES realms (id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT permissions_realm_name_unique UNIQUE (realm_id, name)
);

CREATE TABLE role_permissions (
    role_id       UUID NOT NULL REFERENCES roles (id)       ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,

    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id    UUID        NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX user_roles_role_id_idx ON user_roles (role_id);

-- ---------------------------------------------------------------------------
-- Sessions.
--
-- The browser holds an opaque id in an HttpOnly cookie; the server holds
-- everything else here. Nothing that reaches JavaScript is a bearer token, so
-- an injected script has nothing to exfiltrate. (The previous frontend kept a
-- JWT in localStorage.)
--
-- Only a hash of the session token is stored, so a database disclosure does
-- not hand over live sessions.
-- ---------------------------------------------------------------------------
CREATE TABLE sessions (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    realm_id      UUID        NOT NULL REFERENCES realms (id) ON DELETE CASCADE,
    token_hash    BYTEA       NOT NULL,
    -- Bound to the session and used for the CSRF double-submit comparison, so
    -- a token minted for one session cannot be replayed against another.
    csrf_secret   BYTEA       NOT NULL,
    user_agent    TEXT,
    ip_address    INET,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,

    CONSTRAINT sessions_token_hash_unique UNIQUE (token_hash)
);

CREATE INDEX sessions_user_id_idx    ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

-- ---------------------------------------------------------------------------
-- Login attempts, for lockout and for answering "was this account attacked?".
-- ---------------------------------------------------------------------------
CREATE TABLE login_attempts (
    id           BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    realm_id     UUID        NOT NULL REFERENCES realms (id) ON DELETE CASCADE,
    -- Recorded as typed, because a failed attempt often names an account that
    -- does not exist -- which is itself worth seeing.
    identifier   TEXT        NOT NULL,
    user_id      UUID        REFERENCES users (id) ON DELETE SET NULL,
    ip_address   INET,
    successful   BOOLEAN     NOT NULL,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX login_attempts_lookup_idx
    ON login_attempts (realm_id, lower(identifier), attempted_at DESC);
CREATE INDEX login_attempts_ip_idx
    ON login_attempts (ip_address, attempted_at DESC);
