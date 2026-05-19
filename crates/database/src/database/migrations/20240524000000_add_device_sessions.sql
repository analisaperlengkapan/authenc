-- Add device_sessions table
CREATE TABLE IF NOT EXISTS device_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_session_id UUID REFERENCES user_sessions(id) ON DELETE SET NULL,
    session_identifier VARCHAR(255) NOT NULL,
    ip_address INET,
    location JSONB,
    risk_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    risk_factors JSONB,
    is_active BOOLEAN NOT NULL DEFAULT true,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_sessions_device_id ON device_sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_device_sessions_user_id ON device_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_device_sessions_active ON device_sessions(is_active);

CREATE TRIGGER update_device_sessions_updated_at BEFORE UPDATE ON device_sessions FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
