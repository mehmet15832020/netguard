"""Add network_bytes to normalized_logs.

Revision ID: 009
Revises: 008
Create Date: 2026-05-22

network_bytes enables bandwidth-aware analytics (top talkers by volume,
traffic volume in bytes). NetFlow and Zeek conn logs carry byte counts
which are stored in extra JSON today; promoting to a native column allows
efficient ORDER BY/SUM queries without JSON extraction.
"""

from alembic import op

revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        "ALTER TABLE normalized_logs ADD COLUMN IF NOT EXISTS network_bytes BIGINT"
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_norm_bytes
        ON normalized_logs (tenant_id, network_bytes DESC)
        WHERE network_bytes IS NOT NULL
        """
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS idx_norm_bytes")
