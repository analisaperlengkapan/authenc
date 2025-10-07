-- SAML message storage for request/response tracking and replay prevention
CREATE TABLE IF NOT EXISTS saml_messages (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    saml_id VARCHAR(255) NOT NULL UNIQUE, -- SAML message ID from XML
    message_type VARCHAR(50) NOT NULL, -- AuthnRequest, Response, LogoutRequest, LogoutResponse
    issuer VARCHAR(500) NOT NULL, -- Entity ID of the issuer
    destination VARCHAR(500) NOT NULL, -- Destination URL
    xml_content TEXT NOT NULL, -- Full SAML XML message
    signature TEXT, -- Digital signature if present
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL, -- TTL for replay prevention
    session_id VARCHAR(255), -- Associated session
    relay_state TEXT -- OAuth relay state parameter
);

-- Index for fast lookup by SAML ID
CREATE INDEX idx_saml_messages_saml_id ON saml_messages(saml_id);

-- Index for cleanup of expired messages
CREATE INDEX idx_saml_messages_expires_at ON saml_messages(expires_at);

-- Index for session association
CREATE INDEX idx_saml_messages_session_id ON saml_messages(session_id) WHERE session_id IS NOT NULL;
