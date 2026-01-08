-- Add realm_id to user_sessions table
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS realm_id UUID;

-- Since we can't easily backfill realm_id for existing sessions without more logic,
-- we'll make it nullable for now, but in future it should be NOT NULL.
-- For new sessions, it will be populated.

-- Create index on realm_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_user_sessions_realm_id ON user_sessions(realm_id);
