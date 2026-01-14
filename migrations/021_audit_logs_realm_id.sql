-- Add realm_id column to audit_logs table
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS realm_id UUID;
CREATE INDEX IF NOT EXISTS idx_audit_logs_realm_id ON audit_logs(realm_id);
