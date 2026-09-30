"""Phase B: Response Memory and hourly reports.

Revision ID: 0002_memory_reports
"""
from alembic import op

revision = "0002_memory_reports"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

UPGRADE = [
    """CREATE TABLE response_patterns (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        fingerprint JSONB NOT NULL,
        level TEXT NOT NULL,
        commands TEXT[] NOT NULL DEFAULT '{}',
        status TEXT NOT NULL DEFAULT 'PENDING_VALIDATION'
            CHECK (status IN ('PENDING_VALIDATION','APPROVED','REJECTED')),
        hits INT NOT NULL DEFAULT 0,
        occurrences INT NOT NULL DEFAULT 1,
        source_incident UUID,
        notes TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        approved_by TEXT,
        approved_at TIMESTAMPTZ,
        last_used_at TIMESTAMPTZ)""",
    "CREATE INDEX idx_patterns_status ON response_patterns (status)",
    """CREATE TABLE hourly_reports (
        id BIGSERIAL PRIMARY KEY,
        window_start TIMESTAMPTZ NOT NULL,
        window_end TIMESTAMPTZ NOT NULL,
        generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        kpis JSONB NOT NULL,
        body JSONB NOT NULL)""",
    "CREATE INDEX idx_reports_generated ON hourly_reports (generated_at DESC)",
    "CREATE TRIGGER reports_append_only BEFORE UPDATE OR DELETE ON hourly_reports "
    "FOR EACH ROW EXECUTE FUNCTION acrs_forbid_mutation()",
]
DOWNGRADE = ["DROP TABLE IF EXISTS hourly_reports, response_patterns"]


def upgrade() -> None:
    for stmt in UPGRADE:
        op.execute(stmt)


def downgrade() -> None:
    for stmt in DOWNGRADE:
        op.execute(stmt)
