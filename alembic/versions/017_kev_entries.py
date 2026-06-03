"""kev_entries tablosu — N7 CISA KEV Monitor.

CISA Known Exploited Vulnerabilities feed'inden gelen CVE kayıtları.
Günlük fetch ile güncellenir; yeni CVE'ler bildirim tetikler.

Revision ID: 017
Revises: 016
"""

from alembic import op

revision = "017"
down_revision = "016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS kev_entries (
            cve_id             TEXT PRIMARY KEY,
            vendor_project     TEXT NOT NULL DEFAULT '',
            product            TEXT NOT NULL DEFAULT '',
            vulnerability_name TEXT NOT NULL DEFAULT '',
            date_added         DATE NOT NULL,
            due_date           DATE,
            description        TEXT NOT NULL DEFAULT '',
            required_action    TEXT NOT NULL DEFAULT '',
            seen_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev_entries (date_added DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_kev_vendor    ON kev_entries (vendor_project)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS kev_entries")
