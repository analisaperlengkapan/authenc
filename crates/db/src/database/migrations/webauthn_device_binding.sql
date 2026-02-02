-- Add device_id column to webauthn_credentials table to support device binding
ALTER TABLE webauthn_credentials ADD COLUMN IF NOT EXISTS device_id UUID REFERENCES devices(id) ON DELETE SET NULL;
