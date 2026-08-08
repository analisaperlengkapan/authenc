-- The audit log.
--
-- One table, append-only by convention and by the absence of any UPDATE or
-- DELETE path in `identity::audit` other than the explicit retention sweep.
-- The previous tree had three competing event types in three crates and wrote
-- none of them anywhere durable, so "what happened to this account?" had no
-- answer.
--
-- Two decisions are worth stating, because both look like redundancy:
--
--   * `actor_name` and `target` are **denormalised strings**, not joins. An
--     audit record has to outlive the rows it names — a foreign key that nulls
--     on delete answers "somebody did something to something", which is
--     precisely the question the record exists to answer. The ids are kept too,
--     for as long as they resolve.
--   * `realm_id` is nullable. A failed login against a realm that does not
--     exist still happened, and refusing to record it because there is no realm
--     to attach it to would blind the log to exactly the probing worth seeing.

CREATE TABLE audit_events (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    realm_id    uuid REFERENCES realms (id) ON DELETE CASCADE,

    -- The stable name from `contract::Action::as_str`, never the Rust variant
    -- name: renaming a variant must not orphan rows already written.
    action      text NOT NULL,
    outcome     text NOT NULL CHECK (outcome IN ('success', 'failure')),

    -- Who. The id goes null if the account is deleted; the name does not.
    actor_id    uuid REFERENCES users (id) ON DELETE SET NULL,
    actor_name  text,

    -- To what.
    target_type text,
    target      text,

    -- From where.
    ip_address  inet,
    user_agent  text,

    -- Anything action-specific. Deliberately not a place for credentials:
    -- `identity::audit` has no path that writes one, and review is the check.
    detail      jsonb NOT NULL DEFAULT '{}'::jsonb,

    occurred_at timestamptz NOT NULL DEFAULT now()
);

-- The console's default view: one realm, newest first.
CREATE INDEX audit_events_realm_time ON audit_events (realm_id, occurred_at DESC);

-- "What has this account been doing?" — the question asked during an incident.
CREATE INDEX audit_events_actor_time ON audit_events (actor_id, occurred_at DESC)
    WHERE actor_id IS NOT NULL;

-- "Show me every lockout this week." Filtering by action is the other half of
-- every query the console offers.
CREATE INDEX audit_events_action_time ON audit_events (action, occurred_at DESC);

-- Retention sweeps delete by age across all realms.
CREATE INDEX audit_events_time ON audit_events (occurred_at);
