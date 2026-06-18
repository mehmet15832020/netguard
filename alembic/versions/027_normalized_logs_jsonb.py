"""normalized_logs extra+tags TEXT → JSONB + GIN index.

Revision ID: 027
Revises: 026
Create Date: 2026-06-18

extra ve tags kolonları TEXT'ten JSONB'e çevriliyor.
GIN indexleri ile @> operatörü ve array sorguları etkinleşiyor.
Kaynak: PostgreSQL JSONB Best Practices; TimescaleDB ile uyumlu;
OWASP A3 — format() ile string concat kaldırılıyor, tip güvenli.
"""

from alembic import op

revision = "027"
down_revision = "026"


def upgrade():
    # DEFAULT kısıtını önce kaldır, tip değiştir, yeni DEFAULT ekle
    op.execute("ALTER TABLE normalized_logs ALTER COLUMN extra DROP DEFAULT")
    op.execute(
        "ALTER TABLE normalized_logs "
        "ALTER COLUMN extra TYPE JSONB USING extra::jsonb"
    )
    op.execute("ALTER TABLE normalized_logs ALTER COLUMN extra SET DEFAULT '{}'::jsonb")

    op.execute("ALTER TABLE normalized_logs ALTER COLUMN tags DROP DEFAULT")
    op.execute(
        "ALTER TABLE normalized_logs "
        "ALTER COLUMN tags TYPE JSONB USING tags::jsonb"
    )
    op.execute("ALTER TABLE normalized_logs ALTER COLUMN tags SET DEFAULT '[]'::jsonb")

    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_normalized_logs_extra_gin "
        "ON normalized_logs USING GIN (extra jsonb_path_ops)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_normalized_logs_tags_gin "
        "ON normalized_logs USING GIN (tags)"
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS idx_normalized_logs_extra_gin")
    op.execute("DROP INDEX IF EXISTS idx_normalized_logs_tags_gin")
    op.execute("ALTER TABLE normalized_logs ALTER COLUMN extra DROP DEFAULT")
    op.execute(
        "ALTER TABLE normalized_logs "
        "ALTER COLUMN extra TYPE TEXT USING extra::text"
    )
    op.execute("ALTER TABLE normalized_logs ALTER COLUMN extra SET DEFAULT '{}'")
    op.execute("ALTER TABLE normalized_logs ALTER COLUMN tags DROP DEFAULT")
    op.execute(
        "ALTER TABLE normalized_logs "
        "ALTER COLUMN tags TYPE TEXT USING tags::text"
    )
    op.execute("ALTER TABLE normalized_logs ALTER COLUMN tags SET DEFAULT '[]'")
