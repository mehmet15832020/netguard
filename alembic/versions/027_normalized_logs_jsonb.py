"""normalized_logs extra+tags TEXT → JSONB + GIN index.

Revision ID: 027
Revises: 026
Create Date: 2026-06-18

extra ve tags kolonları TEXT'ten JSONB'e çevriliyor.
GIN indexleri ile @> operatörü ve array sorguları etkinleşiyor.
Kaynak: PostgreSQL JSONB Best Practices; TimescaleDB ile uyumlu;
OWASP A3 — format() ile string concat kaldırılıyor, tip güvenli.

TimescaleDB notu: compressed chunks ALTER COLUMN TYPE'ı desteklemiyor.
Migration sırası: compression policy kaldır → decompress → alter → policy yeniden ekle.
"""

from alembic import op
from sqlalchemy import text

revision = "027"
down_revision = "026"


def upgrade():
    conn = op.get_bind()

    is_compressed = conn.execute(
        text(
            "SELECT compression_enabled FROM timescaledb_information.hypertables "
            "WHERE hypertable_name = 'normalized_logs'"
        )
    ).scalar()

    compress_segmentby = None
    compress_orderby = None
    compress_policy_interval = None

    if is_compressed:
        row = conn.execute(
            text(
                "SELECT segmentby, orderby "
                "FROM timescaledb_information.compression_settings "
                "WHERE hypertable_name = 'normalized_logs'"
            )
        ).fetchone()
        if row:
            compress_segmentby = row[0]
            compress_orderby = row[1]

        pol = conn.execute(
            text(
                "SELECT compress_after FROM timescaledb_information.jobs j "
                "JOIN timescaledb_information.job_stats js ON j.job_id = js.job_id "
                "WHERE j.application_name LIKE '%Compress%' "
                "AND j.hypertable_name = 'normalized_logs'"
            )
        ).fetchone()
        if pol:
            compress_policy_interval = pol[0]

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
        compress_opts = "timescaledb.compress"
        if compress_segmentby:
            compress_opts += f", timescaledb.compress_segmentby = '{compress_segmentby}'"
        if compress_orderby:
            compress_opts += f", timescaledb.compress_orderby = '{compress_orderby}'"
        conn.execute(text(f"ALTER TABLE normalized_logs SET ({compress_opts})"))

        interval = compress_policy_interval or "7 days"
        conn.execute(
            text(
                f"SELECT add_compression_policy('normalized_logs', INTERVAL '{interval}', if_not_exists => true)"
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
