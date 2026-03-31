-- Table: sources
CREATE TABLE IF NOT EXISTS sources (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    type VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    last_success_at TIMESTAMP WITH TIME ZONE,
    last_failure_at TIMESTAMP WITH TIME ZONE,
    last_error TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Table: source_fetch_runs
CREATE TABLE IF NOT EXISTS source_fetch_runs (
    id SERIAL PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    finished_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL,
    items_fetched INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Table: advisories
CREATE TABLE IF NOT EXISTS advisories (
    id SERIAL PRIMARY KEY,
    source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    external_id VARCHAR(500) NOT NULL,
    title TEXT NOT NULL,
    summary TEXT,
    severity VARCHAR(50) NOT NULL,
    vendor VARCHAR(255),
    published_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE,
    exploit_status VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    raw_hash VARCHAR(64) NOT NULL,
    raw_payload JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    modified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(source_id, external_id)
);

-- Table: advisory_identifiers
CREATE TABLE IF NOT EXISTS advisory_identifiers (
    id SERIAL PRIMARY KEY,
    advisory_id INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    identifier_type VARCHAR(50) NOT NULL,
    identifier_value VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    UNIQUE(advisory_id, identifier_type, identifier_value)
);

-- Table: advisory_references
CREATE TABLE IF NOT EXISTS advisory_references (
    id SERIAL PRIMARY KEY,
    advisory_id INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    label TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Table: notification_events
CREATE TABLE IF NOT EXISTS notification_events (
    id SERIAL PRIMARY KEY,
    advisory_id INTEGER NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    notification_type VARCHAR(50) NOT NULL,
    channel VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL,
    slack_message_ref VARCHAR(255),
    sent_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Table: digest_runs
CREATE TABLE IF NOT EXISTS digest_runs (
    id SERIAL PRIMARY KEY,
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    finished_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(50) NOT NULL,
    items_included INTEGER DEFAULT 0,
    slack_message_ref VARCHAR(255),
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_advisories_source_external ON advisories(source_id, external_id);
CREATE INDEX IF NOT EXISTS idx_advisories_published_at ON advisories(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_advisories_severity ON advisories(severity);
CREATE INDEX IF NOT EXISTS idx_advisory_identifiers_type_value ON advisory_identifiers(identifier_type, identifier_value);
CREATE INDEX IF NOT EXISTS idx_notification_events_advisory ON notification_events(advisory_id);
CREATE INDEX IF NOT EXISTS idx_notification_events_type ON notification_events(notification_type);
CREATE INDEX IF NOT EXISTS idx_source_fetch_runs_source ON source_fetch_runs(source_id, started_at DESC);
