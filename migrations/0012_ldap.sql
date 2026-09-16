-- LDAP and Active Directory as a source of users.
--
-- Two tables, mirroring social login: what is configured, and which local
-- account each external identity maps to.
--
-- # The distinguished name is the identity
--
-- `ldap_identities.external_dn` is the key, not the login name. A `uid` can be
-- reassigned when somebody leaves, and a directory that hands `jsmith` to a
-- new starter would otherwise hand them the previous holder's local account,
-- its roles included. The DN is what the directory itself treats as the
-- identity.
--
-- Stored case-normalised, because a DN is case-insensitive in the parts that
-- matter and two spellings of one identity would become two accounts.
--
-- # Why the filter is a template and not free text
--
-- `user_filter` carries `{login}` where the submitted name goes, and
-- `identity::directory` escapes that value per RFC 4515 before substituting.
-- Without the escape, a login of `*)(uid=*` turns "find this user" into "find
-- any user", and the first result is whoever the directory happens to return.

CREATE TABLE ldap_directories (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id      uuid NOT NULL REFERENCES realms (id) ON DELETE CASCADE,

    alias         text NOT NULL CHECK (alias ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    display_name  text NOT NULL CHECK (length(trim(display_name)) > 0),

    -- `ldaps://host:636` or `ldap://host:389`. Plaintext is refused outside
    -- development by `Config::validate`, because the user's password crosses
    -- this connection.
    url           text NOT NULL,
    -- Upgrade a plaintext connection before binding.
    start_tls     boolean NOT NULL DEFAULT false,

    -- The service account used to search. Empty means an anonymous search,
    -- which some directories allow.
    bind_dn       text NOT NULL DEFAULT '',
    -- AES-256-GCM under the master key, with the directory id as associated
    -- data. Null when binding anonymously.
    bind_password_ciphertext bytea,
    bind_password_nonce      bytea,

    user_base_dn  text NOT NULL,
    -- Must contain `{login}`; checked in Rust, because a CHECK constraint
    -- cannot give the error message an operator needs.
    user_filter   text NOT NULL,

    -- Which attributes carry what. Defaults suit OpenLDAP; Active Directory
    -- wants `sAMAccountName` and `givenName`/`sn`.
    attr_username   text NOT NULL DEFAULT 'uid',
    attr_email      text NOT NULL DEFAULT 'mail',
    attr_first_name text NOT NULL DEFAULT 'givenName',
    attr_last_name  text NOT NULL DEFAULT 'sn',

    -- Whether a directory account nobody here has seen may create a local one.
    allow_provisioning boolean NOT NULL DEFAULT true,
    enabled       boolean NOT NULL DEFAULT true,

    created_at    timestamptz NOT NULL DEFAULT now(),

    UNIQUE (realm_id, alias)
);

CREATE TABLE ldap_identities (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    directory_id  uuid NOT NULL REFERENCES ldap_directories (id) ON DELETE CASCADE,
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- Case-normalised; see the note above.
    external_dn   text NOT NULL,

    linked_at     timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,

    UNIQUE (directory_id, external_dn),
    UNIQUE (directory_id, user_id)
);

CREATE INDEX ldap_identities_user ON ldap_identities (user_id);
