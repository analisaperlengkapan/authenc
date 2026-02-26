-- Add email verification token fields to users table
ALTER TABLE users
ADD COLUMN verification_token_hash TEXT,
ADD COLUMN verification_token_expires_at TIMESTAMPTZ;

-- Add index on verification_token_hash for faster lookups
CREATE INDEX idx_users_verification_token_hash ON users(verification_token_hash);
