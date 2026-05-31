"""TimescaleDB hypertable dönüşümü — normalized_logs.

Bu migration çalışmadan önce production VM'de kurulum zorunlu:
    scripts/setup_timescaledb.sh

Yapılan değişiklikler:
  1. timescaledb extension aktif edilir; kurulu + yüklü değilse ValueError
  2. log_id üzerindeki partition-uyumsuz UNIQUE kısıtlar kaldırılır
  3. (log_id, received_at) partition-uyumlu UNIQUE INDEX eklenir
  4. normalized_logs → hypertable (received_at, 1 günlük chunk)
  5. 7 günden eski chunk'lar sıkıştırılır (tenant_id segmentby)

Bu migration idempotent'tir: iki kez çalıştırılsa da güvenlidir.
Downgrade: veri kaybı riski nedeniyle manuel prosedür gerektirir (loglanır).

Kaynak: TimescaleDB docs §"Unique constraints on hypertables";
        TimescaleDB Best Practices for Time-Series Data (2024);
        CIS Controls v8.1 Safeguard 13.8 — log retention performance

Revision ID: 013
Revises: 012
Create Date: 2026-05-31
"""

import logging

from alembic import op
from sqlalchemy import text

revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)


def _extension_active(conn) -> bool:
    """timescaledb pg_extension'da (runtime yüklü) mı?"""
    row = conn.execute(
        text("SELECT COUNT(*) FROM pg_extension WHERE extname = 'timescaledb'")
    ).fetchone()
    return (row[0] if row else 0) > 0


def _is_hypertable(conn) -> bool:
    try:
        row = conn.execute(
            text("""
            SELECT COUNT(*) FROM timescaledb_information.hypertables
            WHERE hypertable_schema = 'public' AND hypertable_name = 'normalized_logs'
            """)
        ).fetchone()
        return (row[0] if row else 0) > 0
    except Exception:
        return False


def _log_id_index_is_compat(conn) -> bool:
    """idx_norm_log_id zaten (log_id, received_at) içeriyor mu?"""
    try:
        row = conn.execute(
            text("""
            SELECT indexdef FROM pg_indexes
            WHERE tablename = 'normalized_logs' AND indexname = 'idx_norm_log_id'
            """)
        ).fetchone()
        return row is not None and "received_at" in row[0].lower()
    except Exception:
        return False


def upgrade() -> None:
    conn = op.get_bind()

    # 1. Extension etkinleştir; shared_preload_libraries eksikse clear error
    if not _extension_active(conn):
        try:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE"))
        except Exception as ext_exc:
            raise ValueError(
                "TimescaleDB extension yüklenemedi. Olası nedenler:\n"
                "  a) Paket kurulmamış → scripts/setup_timescaledb.sh çalıştırın\n"
                "  b) shared_preload_libraries eksik → timescaledb-tune + PostgreSQL restart\n"
                f"Orijinal hata: {ext_exc}"
            ) from ext_exc

        if not _extension_active(conn):
            raise ValueError(
                "timescaledb extension CREATE EXTENSION sonrası pg_extension'da görünmüyor.\n"
                "shared_preload_libraries = 'timescaledb' olduğundan emin olun ve "
                "PostgreSQL'i yeniden başlatın, ardından 'alembic upgrade head' tekrar çalıştırın."
            )

    # 2. Partition-uyumsuz UNIQUE kısıtları kaldır (idempotent — IF NOT EXISTS/IF EXISTS)
    #    Her zaman çalışır; hypertable öncesi veya sonrası durumdan bağımsız.
    if not _log_id_index_is_compat(conn):
        # Otomatik adlandırılmış constraint (normalized_logs_log_id_key) + ek index
        conn.execute(text("""
        ALTER TABLE normalized_logs
            DROP CONSTRAINT IF EXISTS normalized_logs_log_id_key
        """))
        conn.execute(text("DROP INDEX IF EXISTS idx_norm_log_id"))

        # Partition-uyumlu UNIQUE index: log_id + received_at
        conn.execute(text("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_norm_log_id
            ON normalized_logs(log_id, received_at)
        """))

    # 3. Hypertable dönüşümü (mevcut veri migrate_data=TRUE ile korunur)
    if not _is_hypertable(conn):
        conn.execute(text("""
        SELECT create_hypertable(
            'normalized_logs', 'received_at',
            if_not_exists       => TRUE,
            migrate_data        => TRUE,
            chunk_time_interval => INTERVAL '1 day'
        )
        """))

        # Sıkıştırma yapılandırması
        conn.execute(text("""
        ALTER TABLE normalized_logs SET (
            timescaledb.compress,
            timescaledb.compress_segmentby = 'tenant_id',
            timescaledb.compress_orderby   = 'received_at DESC'
        )
        """))

    # 4. Compression policy (idempotent — if_not_exists => TRUE)
    conn.execute(text("""
    SELECT add_compression_policy('normalized_logs',
        INTERVAL '7 days', if_not_exists => TRUE)
    """))


def downgrade() -> None:
    """Hypertable → plain table otomatik geri alınamaz.

    Manuel prosedür:
      1. pg_dump ile veriyi yedekle
      2. normalized_logs tablosunu drop et (CASCADE)
      3. Migration 001'deki plain tablo şemasını yeniden oluştur
      4. Veriyi COPY ile geri yükle

    Downgrade bu nedenle no-op + uyarı loglar; Alembic pipeline kırılmaz.
    """
    logger.warning(
        "Migration 013 downgrade: hypertable → plain table dönüşümü otomatik yapılmıyor. "
        "Veri kaybı riski nedeniyle manuel prosedür gereklidir. "
        "Şema 013 seviyesinde kalmaya devam ediyor."
    )
