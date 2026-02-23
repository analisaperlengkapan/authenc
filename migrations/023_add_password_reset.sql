-- Add password reset columns to users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_hash TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires_at TIMESTAMPTZ;

-- Add index on reset_token_hash for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_reset_token_hash ON users(reset_token_hash) WHERE reset_token_hash IS NOT NULL;
