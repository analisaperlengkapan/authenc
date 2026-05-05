-- Add name column to webauthn_credentials
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS name TEXT;
