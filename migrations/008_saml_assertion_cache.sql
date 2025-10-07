-- Migration: Create SAML assertion cache table for replay attack prevention
-- Description: Stores used SAML assertion IDs to prevent replay attacks
-- Date: October 2, 2025

-- Create SAML assertion cache table
CREATE TABLE IF NOT EXISTS saml_assertion_cache (
    assertion_id VARCHAR(255) PRIMARY KEY,
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- Create index for efficient cleanup of expired assertions
CREATE INDEX IF NOT EXISTS idx_saml_assertion_expires 
ON saml_assertion_cache(expires_at);

-- Comments for documentation
COMMENT ON TABLE saml_assertion_cache IS 'Cache of used SAML assertion IDs to prevent replay attacks';
COMMENT ON COLUMN saml_assertion_cache.assertion_id IS 'Unique SAML assertion ID from the AssertionID attribute';
COMMENT ON COLUMN saml_assertion_cache.used_at IS 'Timestamp when the assertion was first used';
COMMENT ON COLUMN saml_assertion_cache.expires_at IS 'Timestamp when the cache entry expires (typically 5 minutes after use)';
