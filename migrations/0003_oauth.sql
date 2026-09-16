-- OAuth 2.0 and OpenID Connect.

-- ---------------------------------------------------------------------------
-- Signing keys.
--
-- The previous build generated its Ed25519 keypair with
-- `Lazy::new(|| SigningKey::generate(&mut OsRng))` and a comment saying "for
-- demo purposes". Every restart invalidated every token, no two instances
-- could validate each other's, and the JWKS document changed on every boot.
--
-- Keys live here instead: persistent, rotatable, and encrypted at rest with a
-- key-encryption key that never touches the database.
-- ---------------------------------------------------------------------------
CREATE TABLE signing_keys (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id       UUID        NOT NULL REFERENCES realms (id) ON DELETE CASCADE,
    -- The `kid` published in JWKS and carried in every token header, so a
    -- verifier knows which key to use rather than guessing.
    kid            TEXT        NOT NULL,
    algorithm      TEXT        NOT NULL DEFAULT 'EdDSA',
    public_key     BYTEA       NOT NULL,
    -- AES-GCM ciphertext of the private key. The nonce is stored beside it;
    -- the key that decrypts it comes from configuration.
    private_key    BYTEA       NOT NULL,
    private_nonce  BYTEA       NOT NULL,
    -- active: signs new tokens. Exactly one per realm.
    -- retired: no longer signs, but still verifies and still appears in JWKS
    --          until `not_after`, so tokens issued before rotation stay valid.
    status         TEXT        NOT NULL CHECK (status IN ('active', 'retired')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    not_after      TIMESTAMPTZ,

    CONSTRAINT signing_keys_kid_unique UNIQUE (kid)
);

-- At most one active key per realm: two would make "which key signs" ambiguous.
CREATE UNIQUE INDEX signing_keys_one_active_per_realm
    ON signing_keys (realm_id) WHERE status = 'active';
CREATE INDEX signing_keys_realm_idx ON signing_keys (realm_id);

-- ---------------------------------------------------------------------------
-- Registered clients.
-- ---------------------------------------------------------------------------
CREATE TABLE oauth_clients (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id            UUID        NOT NULL REFERENCES realms (id) ON DELETE CASCADE,
    client_id           TEXT        NOT NULL,
    -- Argon2 PHC string, or NULL for a public client. The previous code had a
    -- column named `client_secret_hash` and wrote the plaintext into it.
    client_secret_phc   TEXT,
    name                TEXT        NOT NULL,
    -- Public clients (SPAs, native apps) cannot keep a secret, so they must
    -- use PKCE and are never issued one.
    is_public           BOOLEAN     NOT NULL,
    -- Exact-match allow-list. The previous authorize endpoint redirected to
    -- whatever `redirect_uri` the caller supplied, with no check at all.
    redirect_uris       TEXT[]      NOT NULL DEFAULT '{}',
    grant_types         TEXT[]      NOT NULL DEFAULT '{authorization_code,refresh_token}',
    scopes              TEXT[]      NOT NULL DEFAULT '{openid,profile,email}',
    require_consent     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT oauth_clients_realm_client_id_unique UNIQUE (realm_id, client_id),
    -- A public client with a secret is a contradiction; a confidential client
    -- without one cannot authenticate.
    CONSTRAINT oauth_clients_secret_matches_kind
        CHECK ((is_public AND client_secret_phc IS NULL)
            OR (NOT is_public AND client_secret_phc IS NOT NULL))
);

-- ---------------------------------------------------------------------------
-- Authorization codes.
--
-- Single-use and short-lived, redeemed by one atomic UPDATE, exactly like the
-- recovery tokens.
-- ---------------------------------------------------------------------------
CREATE TABLE authorization_codes (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id             UUID        NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    user_id               UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    realm_id              UUID        NOT NULL REFERENCES realms (id) ON DELETE CASCADE,
    code_hash             BYTEA       NOT NULL,
    redirect_uri          TEXT        NOT NULL,
    scopes                TEXT[]      NOT NULL,
    nonce                 TEXT,
    -- PKCE. Required for public clients; the challenge is bound to the code so
    -- an intercepted code is useless without the verifier.
    code_challenge        TEXT,
    code_challenge_method TEXT CHECK (code_challenge_method IN ('S256')),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at            TIMESTAMPTZ NOT NULL,
    used_at               TIMESTAMPTZ,

    CONSTRAINT authorization_codes_hash_unique UNIQUE (code_hash)
);

CREATE INDEX authorization_codes_expires_at_idx ON authorization_codes (expires_at);

-- ---------------------------------------------------------------------------
-- Refresh tokens.
--
-- Rotated on every use. A token is never simply deleted: it is marked used and
-- points at its successor, so presenting a spent token is *detectable* and can
-- be treated as theft — the whole chain is then revoked.
-- ---------------------------------------------------------------------------
CREATE TABLE refresh_tokens (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id     UUID        NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    user_id       UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    realm_id      UUID        NOT NULL REFERENCES realms (id) ON DELETE CASCADE,
    token_hash    BYTEA       NOT NULL,
    scopes        TEXT[]      NOT NULL,
    -- Every token minted from one authorization shares a family id. Detecting
    -- reuse revokes the family, not just the one token.
    family_id     UUID        NOT NULL,
    replaced_by   UUID        REFERENCES refresh_tokens (id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ NOT NULL,
    used_at       TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,

    CONSTRAINT refresh_tokens_hash_unique UNIQUE (token_hash)
);

CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_expires_at_idx ON refresh_tokens (expires_at);

-- ---------------------------------------------------------------------------
-- Recorded consent, so a user is asked once per client and scope set.
-- ---------------------------------------------------------------------------
CREATE TABLE oauth_consents (
    user_id    UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    client_id  UUID        NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    scopes     TEXT[]      NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (user_id, client_id)
);
