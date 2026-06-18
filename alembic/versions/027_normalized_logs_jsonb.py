"""normalized_logs extra+tags TEXT → JSONB + GIN index.

Revision ID: 027
Revises: 026
Create Date: 2026-06-18

extra ve tags kolonları TEXT'ten JSONB'e çevriliyor.
GIN indexleri ile @> operatörü ve array sorguları etkinleşiyor.
Kaynak: PostgreSQL JSONB Best Practices; TimescaleDB ile uyumlu;
OWASP A3 — format() ile string concat kaldırılıyor, tip güvenli.

TimescaleDB notu: compressed chunks ALTER COLUMN TYPE'ı desteklemiyor.
Migration sırası: policy kaldır → decompress → alter → policy yeniden ekle.
Sıkıştırma ayarları Migration 013'teki değerler korunarak yeniden uygulanıyor.
"""

from alembic import op
from sqlalchemy import text

revision = "027"
down_revision = "026"


def upgrade():
    conn = op.get_bind()

    is_hypertable = conn.execute(
        text(
            "SELECT count(*) FROM timescaledb_information.hypertables "
            "WHERE hypertable_name = 'normalized_logs'"
        )
    ).scalar()

    is_compressed = False
    if is_hypertable:
        is_compressed = bool(
            conn.execute(
                text(
                    "SELECT compression_enabled FROM timescaledb_information.hypertables "
                    "WHERE hypertable_name = 'normalized_logs'"
                )
            ).scalar()
        )

    if is_compressed:
        conn.execute(
            text("SELECT remove_compression_policy('normalized_logs', if_exists => true)")
        )
        conn.execute(
            text(
                "SELECT decompress_chunk(c, if_compressed => true) "
                "FROM show_chunks('normalized_logs') c"
            )
        )

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

    if is_compressed:
        # Migration 013'teki sıkıştırma ayarlarını yeniden uygula
        conn.execute(
            text(
                "ALTER TABLE normalized_logs SET ("
                "timescaledb.compress, "
                "timescaledb.compress_segmentby = 'source_type', "
                "timescaledb.compress_orderby = 'received_at DESC'"
                ")"
            )
        )
        conn.execute(
            text(
                "SELECT add_compression_policy("
                "'normalized_logs', INTERVAL '7 days', if_not_exists => true"
                ")"
            )
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
