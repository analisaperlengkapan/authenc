-- Organization settings for multi-tenancy
CREATE TABLE IF NOT EXISTS organization_settings (
    organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    allow_public_signup BOOLEAN NOT NULL DEFAULT false,
    require_email_verification BOOLEAN NOT NULL DEFAULT true,
    enable_two_factor BOOLEAN NOT NULL DEFAULT false,
    password_policy TEXT NOT NULL DEFAULT 'default',
    session_timeout BIGINT NOT NULL DEFAULT 3600,
    max_users INTEGER,
    features TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Trigger for updated_at
CREATE TRIGGER update_organization_settings_updated_at
BEFORE UPDATE ON organization_settings
FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
