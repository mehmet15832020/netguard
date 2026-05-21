"""Add composite index on alerts(tenant_id, triggered_at) for analytics performance.

Revision ID: 007
Revises: 006
Create Date: 2026-05-21

CIS Controls v8 Safeguard 13.6 — analytics time-window queries require
composite index with tenant equality predicate as leading column.
"""

from alembic import op

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
    CREATE INDEX IF NOT EXISTS idx_alerts_tenant_time
    ON alerts (tenant_id, triggered_at DESC)
    """)


def downgrade():
    op.execute("DROP INDEX IF EXISTS idx_alerts_tenant_time")
