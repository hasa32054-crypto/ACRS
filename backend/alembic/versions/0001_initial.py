"""ACRS core schema (Phase A).

Explicit SQL on purpose: security-critical DDL (append-only triggers, WORM
evidence) is easier to review as SQL than as ORM metadata.
Each statement is executed separately because asyncpg rejects multi-statement strings.

Revision ID: 0001_initial
"""
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

UPGRADE = [
    "CREATE EXTENSION IF NOT EXISTS pgcrypto",
    """CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('viewer','analyst','engineer','admin')),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
    """CREATE TABLE assets (
        id SERIAL PRIMARY KEY,
        hostname TEXT NOT NULL UNIQUE,
        ip INET NOT NULL UNIQUE,
        tier SMALLINT NOT NULL CHECK (tier BETWEEN 0 AND 2),
        role TEXT NOT NULL,
        segment TEXT NOT NULL,
        owner TEXT NOT NULL,
        isolatable BOOLEAN NOT NULL DEFAULT TRUE,
        criticality TEXT NOT NULL DEFAULT 'medium' CHECK (criticality IN ('critical','high','medium','low')),
        os TEXT NOT NULL DEFAULT '',
        pool TEXT,
        pool_size INT NOT NULL DEFAULT 1,
        environment TEXT NOT NULL DEFAULT 'on-prem' CHECK (environment IN ('on-prem','aws','azure','gcp','k8s')),
        cloud_instance_id TEXT,
        edr_device_id TEXT,
        in_change_window BOOLEAN NOT NULL DEFAULT FALSE,
        dependents TEXT[] NOT NULL DEFAULT '{}',
        status TEXT NOT NULL DEFAULT 'healthy'
            CHECK (status IN ('healthy','restricted','quarantined','isolated','remediating','reentry')),
        network_stage SMALLINT CHECK (network_stage BETWEEN 0 AND 3),
        current_risk INT NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
    """CREATE TABLE events (
        id BIGSERIAL PRIMARY KEY,
        ts TIMESTAMPTZ NOT NULL,
        source TEXT NOT NULL,
        type TEXT NOT NULL,
        severity SMALLINT,
        asset_id INT REFERENCES assets(id),
        src_ip INET NOT NULL,
        hostname TEXT,
        "user" TEXT,
        process_hash TEXT,
        c2_domain TEXT,
        raw_payload JSONB NOT NULL DEFAULT '{}',
        ingested_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
    "CREATE INDEX idx_events_asset_ingested ON events (asset_id, ingested_at)",
    "CREATE INDEX idx_events_src_ip_ts ON events (src_ip, ts DESC)",
    """CREATE TABLE incidents (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        state TEXT NOT NULL,
        tier SMALLINT,
        asset_id INT REFERENCES assets(id),
        src_ip INET NOT NULL,
        segment TEXT,
        title TEXT NOT NULL,
        attack_type TEXT,
        entry_path TEXT,
        attack_source JSONB,
        risk_score SMALLINT,
        confidence SMALLINT,
        level TEXT,
        pending_level TEXT,
        approvals_required SMALLINT NOT NULL DEFAULT 0,
        hold_reason TEXT,
        escalation_reason TEXT,
        escalated_from TEXT,
        fast_path BOOLEAN NOT NULL DEFAULT FALSE,
        auto_executed BOOLEAN NOT NULL DEFAULT FALSE,
        false_positive BOOLEAN NOT NULL DEFAULT FALSE,
        sla_breached BOOLEAN NOT NULL DEFAULT FALSE,
        cycle SMALLINT NOT NULL DEFAULT 1,
        remediation_attempts SMALLINT NOT NULL DEFAULT 0,
        network_stage SMALLINT,
        mttc_ms INT,
        correlation_keys TEXT[] NOT NULL DEFAULT '{}',
        context JSONB NOT NULL DEFAULT '{}',
        started_at TIMESTAMPTZ NOT NULL,
        detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
        decided_at TIMESTAMPTZ,
        deadline_at TIMESTAMPTZ,
        observe_until TIMESTAMPTZ,
        contained_at TIMESTAMPTZ,
        closed_at TIMESTAMPTZ,
        version INT NOT NULL DEFAULT 1,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
    "CREATE INDEX idx_incidents_state_tier ON incidents (state, tier)",
    "CREATE INDEX idx_incidents_started ON incidents (started_at)",
    "CREATE INDEX idx_incidents_detected ON incidents (detected_at DESC)",
    "CREATE INDEX idx_incidents_deadline ON incidents (deadline_at) WHERE state IN ('CONTAIN','VERIFY')",
    """CREATE TABLE incident_transitions (
        id BIGSERIAL PRIMARY KEY,
        incident_id UUID NOT NULL REFERENCES incidents(id),
        from_state TEXT,
        to_state TEXT NOT NULL,
        actor TEXT NOT NULL,
        detail JSONB NOT NULL DEFAULT '{}',
        at TIMESTAMPTZ NOT NULL DEFAULT now())""",
    "CREATE INDEX idx_transitions_incident ON incident_transitions (incident_id, id)",
    """CREATE TABLE incident_events (
        incident_id UUID NOT NULL REFERENCES incidents(id),
        event_id BIGINT NOT NULL REFERENCES events(id),
        correlation_weight REAL NOT NULL DEFAULT 1.0,
        PRIMARY KEY (incident_id, event_id))""",
    """CREATE TABLE response_actions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        incident_id UUID NOT NULL REFERENCES incidents(id),
        cycle SMALLINT NOT NULL DEFAULT 1,
        level TEXT NOT NULL,
        action_type TEXT NOT NULL,
        layer TEXT NOT NULL,
        target TEXT NOT NULL,
        params JSONB NOT NULL DEFAULT '{}',
        provider TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('succeeded','failed','released','rolled_back')),
        attempts SMALLINT NOT NULL DEFAULT 1,
        manual BOOLEAN NOT NULL DEFAULT FALSE,
        result JSONB NOT NULL DEFAULT '{}',
        undo JSONB NOT NULL DEFAULT '{}',
        duration_ms INT NOT NULL DEFAULT 0,
        idempotency_key TEXT NOT NULL UNIQUE,
        started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        finished_at TIMESTAMPTZ)""",
    "CREATE INDEX idx_actions_incident ON response_actions (incident_id)",
    """CREATE TABLE verification_checks (
        id BIGSERIAL PRIMARY KEY,
        incident_id UUID NOT NULL REFERENCES incidents(id),
        cycle SMALLINT NOT NULL DEFAULT 1,
        check_name TEXT NOT NULL,
        passed BOOLEAN NOT NULL,
        details JSONB NOT NULL DEFAULT '{}',
        checked_at TIMESTAMPTZ NOT NULL DEFAULT now())""",
    "CREATE INDEX idx_checks_incident ON verification_checks (incident_id, id)",
    """CREATE TABLE approvals (
        id SERIAL PRIMARY KEY,
        incident_id UUID NOT NULL REFERENCES incidents(id),
        approver TEXT NOT NULL,
        level TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (incident_id, level, approver))""",
    """CREATE TABLE evidence (
        id SERIAL PRIMARY KEY,
        incident_id UUID NOT NULL REFERENCES incidents(id),
        kind TEXT NOT NULL,
        uri TEXT NOT NULL,
        sha256 CHAR(64) NOT NULL,
        size_bytes BIGINT NOT NULL,
        collector TEXT NOT NULL,
        actor TEXT NOT NULL,
        collected_at TEXT NOT NULL,
        prev_hash CHAR(64) NOT NULL,
        chain_hash CHAR(64) NOT NULL UNIQUE,
        retention_days INT NOT NULL,
        retention_until DATE NOT NULL,
        legal_hold BOOLEAN NOT NULL DEFAULT FALSE)""",
    "CREATE INDEX idx_evidence_incident ON evidence (incident_id, id)",
    """CREATE TABLE audit_logs (
        id BIGSERIAL PRIMARY KEY,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT,
        reason TEXT,
        timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
        incident_id UUID,
        metadata JSONB NOT NULL DEFAULT '{}')""",
    "CREATE INDEX idx_audit_incident ON audit_logs (incident_id, id)",
    "CREATE INDEX idx_audit_timestamp ON audit_logs (timestamp DESC)",
    """CREATE TABLE risk_history (
        id BIGSERIAL PRIMARY KEY,
        asset_id INT NOT NULL REFERENCES assets(id),
        ts TIMESTAMPTZ NOT NULL DEFAULT now(),
        score SMALLINT NOT NULL)""",
    "CREATE INDEX idx_risk_asset_ts ON risk_history (asset_id, ts)",
    # updated_at maintenance
    """CREATE OR REPLACE FUNCTION acrs_touch_updated_at() RETURNS trigger AS $$
    BEGIN NEW.updated_at = now(); RETURN NEW; END; $$ LANGUAGE plpgsql""",
    "CREATE TRIGGER assets_touch BEFORE UPDATE ON assets FOR EACH ROW EXECUTE FUNCTION acrs_touch_updated_at()",
    "CREATE TRIGGER incidents_touch BEFORE UPDATE ON incidents FOR EACH ROW EXECUTE FUNCTION acrs_touch_updated_at()",
    # append-only guards (TRUNCATE for demo reset is a separate, admin-only path)
    """CREATE OR REPLACE FUNCTION acrs_forbid_mutation() RETURNS trigger AS $$
    BEGIN
        IF TG_TABLE_NAME = 'evidence' AND TG_OP = 'UPDATE'
           AND NEW.sha256 = OLD.sha256 AND NEW.chain_hash = OLD.chain_hash AND NEW.prev_hash = OLD.prev_hash
           AND NEW.uri = OLD.uri AND NEW.legal_hold >= OLD.legal_hold THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'ACRS: % on % is forbidden (append-only)', TG_OP, TG_TABLE_NAME;
    END; $$ LANGUAGE plpgsql""",
    "CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE ON audit_logs FOR EACH ROW EXECUTE FUNCTION acrs_forbid_mutation()",
    "CREATE TRIGGER transitions_append_only BEFORE UPDATE OR DELETE ON incident_transitions FOR EACH ROW EXECUTE FUNCTION acrs_forbid_mutation()",
    "CREATE TRIGGER evidence_worm BEFORE UPDATE OR DELETE ON evidence FOR EACH ROW EXECUTE FUNCTION acrs_forbid_mutation()",
]

DOWNGRADE = [
    "DROP TABLE IF EXISTS risk_history, audit_logs, evidence, approvals, verification_checks, response_actions, "
    "incident_events, incident_transitions, incidents, events, assets, users CASCADE",
    "DROP FUNCTION IF EXISTS acrs_forbid_mutation()",
    "DROP FUNCTION IF EXISTS acrs_touch_updated_at()",
]


def upgrade() -> None:
    for stmt in UPGRADE:
        op.execute(stmt)


def downgrade() -> None:
    for stmt in DOWNGRADE:
        op.execute(stmt)
