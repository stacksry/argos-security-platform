-- ARGOS PostgreSQL + TimescaleDB initialization
-- Runs once on first container start.

CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── Episodic memory (time-series) ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS scans (
    time         TIMESTAMPTZ     NOT NULL,
    scan_id      TEXT            NOT NULL,
    repo         TEXT            NOT NULL,
    agent        TEXT            NOT NULL,
    findings_count INTEGER       DEFAULT 0,
    duration_ms  INTEGER         DEFAULT 0,
    trigger      TEXT            DEFAULT 'push',
    platform     TEXT            DEFAULT 'bitbucket'
);
SELECT create_hypertable('scans', 'time', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS scans_repo_idx ON scans (repo, time DESC);

CREATE TABLE IF NOT EXISTS findings_timeline (
    time         TIMESTAMPTZ     NOT NULL,
    repo         TEXT            NOT NULL,
    finding_id   TEXT            NOT NULL,
    vuln_class   TEXT            NOT NULL,
    severity     TEXT            NOT NULL,
    status       TEXT            NOT NULL,
    agent        TEXT            NOT NULL,
    cvss_score   FLOAT           DEFAULT 0.0
);
SELECT create_hypertable('findings_timeline', 'time', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS findings_repo_idx ON findings_timeline (repo, time DESC);

CREATE TABLE IF NOT EXISTS agent_metrics (
    time         TIMESTAMPTZ     NOT NULL,
    agent        TEXT            NOT NULL,
    metric_name  TEXT            NOT NULL,
    value        FLOAT           NOT NULL,
    repo         TEXT            DEFAULT ''
);
SELECT create_hypertable('agent_metrics', 'time', if_not_exists => TRUE);

-- ── Procedural memory (self-learning) ──────────────────────────────────────

CREATE TABLE IF NOT EXISTS fix_patterns (
    id                  SERIAL PRIMARY KEY,
    vuln_class          TEXT        NOT NULL,
    language            TEXT        NOT NULL,
    file_extension      TEXT        NOT NULL,
    vulnerable_snippet  TEXT        NOT NULL,
    fix_snippet         TEXT        NOT NULL,
    repo                TEXT        NOT NULL,
    confirmed_by        TEXT        NOT NULL DEFAULT 'tester_agent',
    confidence          INTEGER     NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS fp_vuln_lang_idx ON fix_patterns (vuln_class, language);

CREATE TABLE IF NOT EXISTS false_positive_signals (
    id               SERIAL PRIMARY KEY,
    vuln_class       TEXT        NOT NULL,
    file_pattern     TEXT        NOT NULL,
    rejection_reason TEXT        NOT NULL,
    signal           TEXT        NOT NULL,
    count            INTEGER     NOT NULL DEFAULT 1,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS fps_vuln_idx ON false_positive_signals (vuln_class);

CREATE TABLE IF NOT EXISTS cvss_corrections (
    id               SERIAL PRIMARY KEY,
    vuln_class       TEXT        NOT NULL,
    original_score   FLOAT       NOT NULL,
    corrected_score  FLOAT       NOT NULL,
    original_vector  TEXT        NOT NULL,
    corrected_vector TEXT        NOT NULL,
    reason           TEXT        NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ranker_calibrations (
    id                SERIAL PRIMARY KEY,
    file_path_pattern TEXT        NOT NULL,
    file_extension    TEXT        NOT NULL,
    ranked_score      INTEGER     NOT NULL,
    actual_severity   TEXT        NOT NULL,
    vuln_class        TEXT        NOT NULL,
    lesson            TEXT        NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS confirmed_scan_patterns (
    id               SERIAL PRIMARY KEY,
    vuln_class       TEXT        NOT NULL,
    pattern          TEXT        NOT NULL,
    language         TEXT        NOT NULL,
    crash_indicator  TEXT        NOT NULL,
    confirmed_by     TEXT        NOT NULL DEFAULT 'sandbox',
    count            INTEGER     NOT NULL DEFAULT 1,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS csp_vuln_pattern_idx ON confirmed_scan_patterns (vuln_class, pattern);

CREATE TABLE IF NOT EXISTS agent_performance_log (
    id           SERIAL PRIMARY KEY,
    agent_name   TEXT        NOT NULL,
    precision    FLOAT       NOT NULL,
    recall       FLOAT       NOT NULL,
    fp_rate      FLOAT       NOT NULL,
    fn_rate      FLOAT       NOT NULL,
    scan_count   INTEGER     NOT NULL DEFAULT 0,
    recorded_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS apl_agent_idx ON agent_performance_log (agent_name, recorded_at DESC);

-- ── Triage records ──────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS triage_records (
    finding_id          TEXT        PRIMARY KEY,
    vuln_class          TEXT        NOT NULL,
    title               TEXT        NOT NULL,
    repo                TEXT        NOT NULL,
    file                TEXT        NOT NULL,
    severity            TEXT        NOT NULL,
    cvss_score          FLOAT       NOT NULL DEFAULT 0.0,
    cvss_vector         TEXT        NOT NULL DEFAULT '',
    route               TEXT        NOT NULL,
    status              TEXT        NOT NULL DEFAULT 'open',
    discovery_ts        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    disclosure_deadline TIMESTAMPTZ,
    exploitation_path   TEXT        NOT NULL DEFAULT '',
    population_impact   TEXT        NOT NULL DEFAULT '',
    affected_library    TEXT        NOT NULL DEFAULT '',
    commitment_hash     TEXT        NOT NULL DEFAULT '',
    blast_radius        INTEGER     NOT NULL DEFAULT 0,
    cisa_kev            BOOLEAN     NOT NULL DEFAULT FALSE,
    cve_ids             TEXT[]      NOT NULL DEFAULT '{}',
    notes               TEXT        NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS tr_repo_idx   ON triage_records (repo);
CREATE INDEX IF NOT EXISTS tr_status_idx ON triage_records (status);
CREATE INDEX IF NOT EXISTS tr_severity_idx ON triage_records (severity, cvss_score DESC);

-- ── Disclosure docs ─────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS disclosure_docs (
    id           SERIAL PRIMARY KEY,
    finding_id   TEXT        NOT NULL REFERENCES triage_records(finding_id),
    doc_type     TEXT        NOT NULL,  -- vendor_notification | escalation | public_disclosure
    content      TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
