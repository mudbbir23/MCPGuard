-- ============================================
-- MCPGuard Database Schema
-- Supabase-compatible PostgreSQL
-- ============================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ─── ENUM TYPES ─────────────────────────────────────────────

CREATE TYPE plan_type AS ENUM ('free', 'pro', 'team');
CREATE TYPE target_type AS ENUM ('github', 'npm', 'local');
CREATE TYPE scan_status AS ENUM ('pending', 'running', 'complete', 'failed');
CREATE TYPE severity_score AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE');
CREATE TYPE server_category AS ENUM ('filesystem', 'communication', 'development', 'database', 'other');
CREATE TYPE advisory_severity AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW');

-- ─── USERS TABLE ────────────────────────────────────────────

CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email       TEXT NOT NULL,
    plan        plan_type NOT NULL DEFAULT 'free',
    api_key     TEXT UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE users IS 'MCPGuard user accounts, linked to Clerk auth';

-- ─── SCANS TABLE ────────────────────────────────────────────

CREATE TABLE scans (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id           UUID REFERENCES users(id) ON DELETE SET NULL,
    target_url        TEXT NOT NULL,
    target_type       target_type NOT NULL,
    status            scan_status NOT NULL DEFAULT 'pending',
    overall_score     severity_score,
    result_json       JSONB,
    scan_duration_ms  INTEGER,
    error_message     TEXT
);

COMMENT ON TABLE scans IS 'Individual security scan records';

-- ─── REGISTRY SERVERS TABLE ─────────────────────────────────

CREATE TABLE registry_servers (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    github_url      TEXT NOT NULL,
    npm_package     TEXT,
    language        TEXT NOT NULL DEFAULT 'unknown',
    category        server_category NOT NULL DEFAULT 'other',
    latest_score    severity_score,
    latest_scan_id  UUID REFERENCES scans(id) ON DELETE SET NULL,
    scan_count      INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE registry_servers IS 'Registry of known MCP servers with security scores';

-- ─── REGISTRY ADVISORIES TABLE ──────────────────────────────

CREATE TABLE registry_advisories (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    server_id       UUID NOT NULL REFERENCES registry_servers(id) ON DELETE CASCADE,
    cve_id          TEXT,
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    severity        advisory_severity NOT NULL,
    disclosed_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    reporter_email  TEXT,
    verified        BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE registry_advisories IS 'Community-submitted security advisories for MCP servers';

-- ─── WATCHLIST TABLE ────────────────────────────────────────

CREATE TABLE watchlist (
    user_id                 UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    server_id               UUID NOT NULL REFERENCES registry_servers(id) ON DELETE CASCADE,
    notify_on_score_change  BOOLEAN NOT NULL DEFAULT true,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),

    PRIMARY KEY (user_id, server_id)
);

COMMENT ON TABLE watchlist IS 'User watchlist for MCP server score change notifications';

-- ─── INDEXES ────────────────────────────────────────────────

CREATE INDEX idx_scans_user_id ON scans(user_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX idx_scans_target_url ON scans(target_url);

CREATE INDEX idx_registry_servers_category ON registry_servers(category);
CREATE INDEX idx_registry_servers_latest_score ON registry_servers(latest_score);
CREATE INDEX idx_registry_servers_name ON registry_servers(name);
CREATE INDEX idx_registry_servers_updated_at ON registry_servers(updated_at DESC);

CREATE INDEX idx_registry_advisories_server_id ON registry_advisories(server_id);
CREATE INDEX idx_registry_advisories_severity ON registry_advisories(severity);

CREATE INDEX idx_watchlist_server_id ON watchlist(server_id);

-- ─── ROW LEVEL SECURITY ────────────────────────────────────

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry_advisories ENABLE ROW LEVEL SECURITY;
ALTER TABLE watchlist ENABLE ROW LEVEL SECURITY;

-- Users can only read/write their own rows
CREATE POLICY users_own_row ON users
    FOR ALL
    USING (id = auth.uid())
    WITH CHECK (id = auth.uid());

-- Users can read their own scans; public scans (user_id IS NULL) are readable by all
CREATE POLICY scans_own_read ON scans
    FOR SELECT
    USING (user_id = auth.uid() OR user_id IS NULL);

CREATE POLICY scans_own_insert ON scans
    FOR INSERT
    WITH CHECK (user_id = auth.uid() OR user_id IS NULL);

CREATE POLICY scans_own_update ON scans
    FOR UPDATE
    USING (user_id = auth.uid() OR user_id IS NULL);

-- Registry servers are public read
CREATE POLICY registry_servers_public_read ON registry_servers
    FOR SELECT
    USING (true);

-- Registry advisories are public read
CREATE POLICY registry_advisories_public_read ON registry_advisories
    FOR SELECT
    USING (true);

-- Watchlist: users can only manage their own entries
CREATE POLICY watchlist_own_row ON watchlist
    FOR ALL
    USING (user_id = auth.uid())
    WITH CHECK (user_id = auth.uid());

-- ─── TRIGGERS ───────────────────────────────────────────────

-- Auto-update registry_servers when a scan completes
CREATE OR REPLACE FUNCTION update_registry_on_scan_complete()
RETURNS TRIGGER AS $$
BEGIN
    -- Only act on scans that just completed
    IF NEW.status = 'complete' AND OLD.status != 'complete' THEN
        UPDATE registry_servers
        SET
            latest_score = NEW.overall_score,
            latest_scan_id = NEW.id,
            scan_count = scan_count + 1,
            updated_at = now()
        WHERE github_url = NEW.target_url
           OR npm_package = NEW.target_url;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_registry_on_scan
    AFTER UPDATE ON scans
    FOR EACH ROW
    EXECUTE FUNCTION update_registry_on_scan_complete();

-- Auto-update updated_at on registry_servers modification
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_registry_servers_updated_at
    BEFORE UPDATE ON registry_servers
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at();
