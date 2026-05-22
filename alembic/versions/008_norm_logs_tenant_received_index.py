"""Add composite index on normalized_logs(tenant_id, received_at) for analytics performance.

Revision ID: 008
Revises: 007
Create Date: 2026-05-22

CIS Controls v8 Safeguard 13.6 — analytics time-window queries on normalized_logs
(top-talkers, protocol-distribution, traffic-volume) filter by tenant_id equality
and received_at range. A composite index with tenant_id as leading column enables
index range scans instead of full chunk scans on the TimescaleDB hypertable.
TimescaleDB propagates this index to all existing and future chunks automatically.
"""

from alembic import op

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
    CREATE INDEX IF NOT EXISTS idx_norm_tenant_received
    ON normalized_logs (tenant_id, received_at DESC)
    """)


def downgrade():
    op.execute("DROP INDEX IF EXISTS idx_norm_tenant_received")
