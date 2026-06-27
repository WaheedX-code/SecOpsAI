CREATE TABLE IF NOT EXISTS secopsai.audit_logs (
    audit_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event       TEXT NOT NULL,
    username    TEXT,
    ip_address  INET,
    details     JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp
    ON secopsai.audit_logs (timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_event
    ON secopsai.audit_logs (event);

CREATE INDEX IF NOT EXISTS idx_audit_logs_username
    ON secopsai.audit_logs (username);
