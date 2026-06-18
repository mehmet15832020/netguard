"""normalized_logs extra+tags TEXT → JSONB + GIN index.

Revision ID: 027
Revises: 026
Create Date: 2026-06-18

extra ve tags kolonları TEXT'ten JSONB'e çevriliyor.
GIN indexleri ile @> operatörü ve array sorguları etkinleşiyor.
Kaynak: PostgreSQL JSONB Best Practices; TimescaleDB ile uyumlu;
OWASP A3 — format() ile string concat kaldırılıyor, tip güvenli.

TimescaleDB notu: compressed chunks ALTER COLUMN TYPE'ı desteklemiyor.
Decompress tüm veriyi RAM'e alır — VM belleği yetersizse OOM riski var.
Bu migration compressed chunk varsa ALTER COLUMN'u atlar;
database._parse_json() her iki tiple (TEXT/JSONB) uyumludur.
"""

from alembic import op
from sqlalchemy import text

revision = "027"
down_revision = "026"


def upgrade():
    conn = op.get_bind()

    compressed_count = conn.execute(
        text(
            "SELECT count(*) FROM timescaledb_information.chunks "
            "WHERE hypertable_name = 'normalized_logs' AND is_compressed = true"
        )
    ).scalar() or 0

    if compressed_count == 0:
        op.execute("ALTER TABLE normalized_logs ALTER COLUMN extra DROP DEFAULT")
        op.execute(
            "ALTER TABLE normalized_logs "
            "ALTER COLUMN extra TYPE JSONB USING extra::jsonb"
        )
        op.execute(
            "ALTER TABLE normalized_logs ALTER COLUMN extra SET DEFAULT '{}'::jsonb"
        )
        op.execute("ALTER TABLE normalized_logs ALTER COLUMN tags DROP DEFAULT")
        op.execute(
            "ALTER TABLE normalized_logs "
            "ALTER COLUMN tags TYPE JSONB USING tags::jsonb"
        )
        op.execute(
            "ALTER TABLE normalized_logs ALTER COLUMN tags SET DEFAULT '[]'::jsonb"
        )
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
    col_type = op.get_bind().execute(
        text(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_name='normalized_logs' AND column_name='extra'"
        )
    ).scalar()
    if col_type and "json" in col_type:
        op.execute("ALTER TABLE normalized_logs ALTER COLUMN extra DROP DEFAULT")
        op.execute(
            "ALTER TABLE normalized_logs ALTER COLUMN extra TYPE TEXT USING extra::text"
        )
        op.execute("ALTER TABLE normalized_logs ALTER COLUMN extra SET DEFAULT '{}'")
        op.execute("ALTER TABLE normalized_logs ALTER COLUMN tags DROP DEFAULT")
        op.execute(
            "ALTER TABLE normalized_logs ALTER COLUMN tags TYPE TEXT USING tags::text"
        )
        op.execute("ALTER TABLE normalized_logs ALTER COLUMN tags SET DEFAULT '[]'")
