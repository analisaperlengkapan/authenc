-- Add email verification token fields to users table
ALTER TABLE users
ADD COLUMN verification_token_hash TEXT,
ADD COLUMN verification_token_expires_at TIMESTAMPTZ;
