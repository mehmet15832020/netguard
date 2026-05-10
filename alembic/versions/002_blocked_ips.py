"""blocked_ips tablosu — V1-9 Aktif Yanıt

Revision ID: 002
Revises: 001
Create Date: 2026-05-10
"""
from alembic import op

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        block_id          TEXT PRIMARY KEY,
        ip                TEXT NOT NULL,
        reason            TEXT NOT NULL DEFAULT '',
        blocked_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        blocked_by        TEXT NOT NULL,
        is_active         SMALLINT NOT NULL DEFAULT 1,
        source_incident_id TEXT,
        provider          TEXT NOT NULL DEFAULT 'opnsense',
        unblocked_at      TIMESTAMPTZ,
        unblocked_by      TEXT,
        tenant_id         TEXT NOT NULL DEFAULT 'default'
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_blocked_ip       ON blocked_ips(ip)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_blocked_active   ON blocked_ips(is_active)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_blocked_tenant   ON blocked_ips(tenant_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_blocked_incident ON blocked_ips(source_incident_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS blocked_ips")
