"""saved_hunts tablosu — F5 Threat Hunt Workbench.

Analist filtre kombinasyonlarını kaydeder, yeniden çalıştırır.
filter_params JSON sütununda tüm sorgu parametreleri saklanır.

Revision ID: 015
Revises: 014
"""

from alembic import op

revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS saved_hunts (
            hunt_id      TEXT PRIMARY KEY,
            tenant_id    TEXT NOT NULL,
            created_by   TEXT NOT NULL,
            name         TEXT NOT NULL,
            description  TEXT NOT NULL DEFAULT '',
            filter_params TEXT NOT NULL DEFAULT '{}',
            tags         TEXT NOT NULL DEFAULT '[]',
            is_favorite  BOOLEAN NOT NULL DEFAULT FALSE,
            run_count    INTEGER NOT NULL DEFAULT 0,
            last_run_at  TIMESTAMPTZ,
            last_run_count INTEGER,
            created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_saved_hunts_tenant "
        "ON saved_hunts (tenant_id, created_at DESC)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_saved_hunts_favorite "
        "ON saved_hunts (tenant_id, is_favorite) WHERE is_favorite = TRUE"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS saved_hunts")
