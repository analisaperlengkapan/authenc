-- Audit log table for Authenc
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event TEXT NOT NULL,
    user_id TEXT,
    client_id TEXT,
    status TEXT NOT NULL,
    detail TEXT
);
