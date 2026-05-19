-- Add session_id to oauth2_access_tokens
ALTER TABLE oauth2_access_tokens
ADD COLUMN IF NOT EXISTS session_id VARCHAR(255);

-- Create index on session_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_oauth2_access_tokens_session_id ON oauth2_access_tokens(session_id);
