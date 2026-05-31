"""
O1 — TimescaleDB hypertable migration testleri.

Kapsam:
  - Migration 013 sonrası normalized_logs hypertable olmalı
  - Compression policy aktif olmalı
  - Yeni UNIQUE index (log_id, received_at) partition-uyumlu olmalı
  - INSERT/SELECT hypertable üzerinde doğru çalışmalı
  - Chunk pruning — zaman aralığı sorguları doğru sonuç vermeli
  - Migration idempotency (013'ü iki kez çalıştır — hata olmamalı)
  - Downgrade no-op (NotImplementedError yerine uyarı loglanır)

Kaynaklar:
  TimescaleDB docs §"Unique constraints on hypertables" (2024)
  CIS Controls v8.1 Safeguard 13.8 — performanslı log saklama
  NIST SP 800-94 Rev.1 §4.2 — log verisi bütünlüğü
"""

import uuid
import pytest
from datetime import datetime, timezone, timedelta


def _insert_norm_log(conn, *, source_ip="10.0.0.1", event_action="ssh_failure",
                     tenant_id="default", minutes_ago=0, log_id=None):
    ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    conn.execute(
        """
        INSERT INTO normalized_logs
          (log_id, raw_id, source_type, observer_hostname, timestamp,
           received_at, severity, event_category, event_action,
           source_ip, message, tenant_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            log_id or str(uuid.uuid4()), str(uuid.uuid4()), "netguard", "test-host",
            ts, ts,  # received_at = same offset so range queries work
            "warning", "network", event_action, source_ip,
            "test message", tenant_id,
        ),
    )
    conn.commit()


# ------------------------------------------------------------------ #
#  TimescaleDB extension varlığı
# ------------------------------------------------------------------ #

class TestTimescaleDBExtension:
    def test_extension_is_active(self, tmp_db):
        """timescaledb extension pg_extension tablosunda görünmeli."""
        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT extname FROM pg_extension WHERE extname = 'timescaledb'"
            ).fetchone()
        assert row is not None, "timescaledb extension aktif değil"

    def test_extension_version_is_2x(self, tmp_db):
        """TimescaleDB 2.x kullanılmalı (1.x API uyumsuz)."""
        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'"
            ).fetchone()
        assert row is not None
        major = int(row["extversion"].split(".")[0])
        assert major >= 2, f"TimescaleDB 2.x bekleniyor, bulunan: {row['extversion']}"


# ------------------------------------------------------------------ #
#  Hypertable durumu
# ------------------------------------------------------------------ #

class TestHypertableStatus:
    def test_normalized_logs_is_hypertable(self, tmp_db):
        """normalized_logs timescaledb_information.hypertables'da görünmeli."""
        with tmp_db._connect() as conn:
            row = conn.execute(
                """
                SELECT hypertable_name
                FROM timescaledb_information.hypertables
                WHERE hypertable_schema = 'public'
                  AND hypertable_name   = 'normalized_logs'
                """
            ).fetchone()
        assert row is not None, "normalized_logs hypertable değil"

    def test_partition_key_is_received_at(self, tmp_db):
        """Partition key 'received_at' olmalı (primary_dimension sütunu)."""
        with tmp_db._connect() as conn:
            row = conn.execute(
                """
                SELECT primary_dimension
                FROM timescaledb_information.hypertables
                WHERE hypertable_name = 'normalized_logs'
                """
            ).fetchone()
        assert row is not None
        assert row["primary_dimension"] == "received_at", (
            f"Beklenen primary_dimension: 'received_at', bulunan: {row['primary_dimension']}"
        )

    def test_chunk_interval_is_one_day(self, tmp_db):
        """Chunk aralığı 1 gün olmalı (TIMESTAMPTZ → time_interval, timedelta)."""
        with tmp_db._connect() as conn:
            row = conn.execute(
                """
                SELECT time_interval
                FROM timescaledb_information.dimensions
                WHERE hypertable_name = 'normalized_logs'
                  AND dimension_type  = 'Time'
                """
            ).fetchone()
        assert row is not None
        assert row["time_interval"] == timedelta(days=1), (
            f"Beklenen chunk: 1 gün, bulunan: {row['time_interval']}"
        )


# ------------------------------------------------------------------ #
#  Compression policy
# ------------------------------------------------------------------ #

class TestCompressionPolicy:
    def test_compression_enabled_on_hypertable(self, tmp_db):
        """hypertables.compression_enabled = True olmalı."""
        with tmp_db._connect() as conn:
            row = conn.execute(
                """
                SELECT compression_enabled
                FROM timescaledb_information.hypertables
                WHERE hypertable_name = 'normalized_logs'
                """
            ).fetchone()
        assert row is not None
        assert row["compression_enabled"] is True

    def test_compression_job_exists(self, tmp_db):
        """Compression policy job tanımlanmış olmalı."""
        with tmp_db._connect() as conn:
            row = conn.execute(
                """
                SELECT config->>'compress_after' AS compress_after
                FROM timescaledb_information.jobs
                WHERE hypertable_name = 'normalized_logs'
                  AND proc_name       = 'policy_compression'
                """
            ).fetchone()
        assert row is not None, "Compression policy job bulunamadı"

    def test_compression_after_7_days(self, tmp_db):
        """Compression threshold 7 gün olmalı."""
        with tmp_db._connect() as conn:
            row = conn.execute(
                """
                SELECT config->>'compress_after' AS compress_after
                FROM timescaledb_information.jobs
                WHERE hypertable_name = 'normalized_logs'
                  AND proc_name       = 'policy_compression'
                """
            ).fetchone()
        assert row is not None
        assert "7 day" in (row["compress_after"] or ""), (
            f"compress_after '7 days' bekleniyor, bulunan: {row['compress_after']}"
        )

    def test_compression_segmentby_is_tenant_id(self, tmp_db):
        """Sıkıştırma tenant_id segmentby ile yapılandırılmış olmalı."""
        with tmp_db._connect() as conn:
            row = conn.execute(
                """
                SELECT attname
                FROM timescaledb_information.compression_settings
                WHERE hypertable_name         = 'normalized_logs'
                  AND segmentby_column_index IS NOT NULL
                """
            ).fetchone()
        assert row is not None, "segmentby kolonu bulunamadı"
        assert row["attname"] == "tenant_id", (
            f"segmentby 'tenant_id' bekleniyor, bulunan: {row['attname']}"
        )


# ------------------------------------------------------------------ #
#  UNIQUE index partition uyumu
# ------------------------------------------------------------------ #

class TestUniqueIndexCompatibility:
    def test_log_id_unique_index_includes_received_at(self, tmp_db):
        """idx_norm_log_id, partition key (received_at) içermeli."""
        with tmp_db._connect() as conn:
            rows = conn.execute(
                """
                SELECT indexdef FROM pg_indexes
                WHERE tablename = 'normalized_logs'
                  AND indexname  = 'idx_norm_log_id'
                """
            ).fetchall()
        assert rows, "idx_norm_log_id bulunamadı"
        indexdef = rows[0]["indexdef"].lower()
        assert "received_at" in indexdef, (
            f"idx_norm_log_id 'received_at' içermeli. Tanım: {indexdef}"
        )
        assert "log_id" in indexdef

    def test_no_standalone_log_id_unique_constraint(self, tmp_db):
        """Partition-uyumsuz 'normalized_logs_log_id_key' kısıtı kaldırılmış olmalı."""
        with tmp_db._connect() as conn:
            row = conn.execute(
                """
                SELECT conname FROM pg_constraint
                WHERE conrelid = 'normalized_logs'::regclass
                  AND conname  = 'normalized_logs_log_id_key'
                """
            ).fetchone()
        assert row is None, (
            "normalized_logs_log_id_key kısıtı hâlâ mevcut — "
            "TimescaleDB ile uyumsuz unique constraint"
        )

    def test_duplicate_log_id_different_received_at_allowed(self, tmp_db):
        """Aynı log_id farklı received_at değerleriyle iki kez eklenebilmeli."""
        fixed_log_id = str(uuid.uuid4())
        t1 = datetime.now(timezone.utc) - timedelta(hours=2)
        t2 = datetime.now(timezone.utc) - timedelta(hours=1)
        with tmp_db._connect() as conn:
            for ts in (t1, t2):
                conn.execute(
                    """
                    INSERT INTO normalized_logs
                      (log_id, raw_id, source_type, observer_hostname, timestamp,
                       received_at, severity, event_category, event_action,
                       source_ip, message, tenant_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        fixed_log_id, str(uuid.uuid4()), "netguard", "test-host",
                        ts.isoformat(), ts.isoformat(),
                        "warning", "network", "ssh_failure",
                        "10.0.0.1", "dup test", "default",
                    ),
                )
            conn.commit()

        with tmp_db._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) AS cnt FROM normalized_logs WHERE log_id = %s",
                (fixed_log_id,),
            ).fetchone()["cnt"]
        assert count == 2


# ------------------------------------------------------------------ #
#  INSERT / SELECT — hypertable üzerinde temel işlemler
# ------------------------------------------------------------------ #

class TestHypertableOperations:
    def test_insert_and_query(self, tmp_db):
        """Hypertable'a veri yazılıp okunabiliyor."""
        with tmp_db._connect() as conn:
            _insert_norm_log(conn, source_ip="192.168.1.10", event_action="port_scan_ht")

        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT source_ip FROM normalized_logs WHERE event_action = 'port_scan_ht'"
            ).fetchone()
        assert row is not None
        assert row["source_ip"] == "192.168.1.10"

    def test_time_range_query_returns_correct_rows(self, tmp_db):
        """Zaman aralığı sorgusunun received_at chunk pruning ile doğru sonuç döndürdüğü."""
        with tmp_db._connect() as conn:
            _insert_norm_log(conn, source_ip="10.0.0.50", minutes_ago=10)
            _insert_norm_log(conn, source_ip="10.0.0.51", minutes_ago=120)

        since = datetime.now(timezone.utc) - timedelta(minutes=30)
        with tmp_db._connect() as conn:
            rows = conn.execute(
                "SELECT source_ip FROM normalized_logs WHERE received_at >= %s",
                (since,),
            ).fetchall()

        ips = {r["source_ip"] for r in rows}
        assert "10.0.0.50" in ips
        assert "10.0.0.51" not in ips

    def test_tenant_isolation_in_hypertable(self, tmp_db):
        """Tenant izolasyonu hypertable üzerinde de çalışmalı."""
        with tmp_db._connect() as conn:
            _insert_norm_log(conn, source_ip="10.1.0.1", tenant_id="tenant_a")
            _insert_norm_log(conn, source_ip="10.1.0.2", tenant_id="tenant_b")

        with tmp_db._connect() as conn:
            rows = conn.execute(
                "SELECT source_ip FROM normalized_logs WHERE tenant_id = 'tenant_a'"
            ).fetchall()

        ips = {r["source_ip"] for r in rows}
        assert "10.1.0.1" in ips
        assert "10.1.0.2" not in ips

    def test_num_chunks_increases_after_insert(self, tmp_db):
        """Veri eklendikçe chunk sayısı 1'in üzerinde veya eşit olmalı."""
        with tmp_db._connect() as conn:
            _insert_norm_log(conn)

        with tmp_db._connect() as conn:
            row = conn.execute(
                """
                SELECT num_chunks FROM timescaledb_information.hypertables
                WHERE hypertable_name = 'normalized_logs'
                """
            ).fetchone()
        assert row is not None
        assert row["num_chunks"] >= 1


# ------------------------------------------------------------------ #
#  Migration güvenilirliği
# ------------------------------------------------------------------ #

class TestMigrationReliability:
    def test_sql_idempotency_create_unique_index_if_not_exists(self, tmp_db):
        """CREATE UNIQUE INDEX IF NOT EXISTS iki kez çalıştırılsa hata üretmemeli."""
        with tmp_db._connect() as conn:
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_norm_log_id "
                "ON normalized_logs(log_id, received_at)"
            )
            conn.commit()

        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_norm_log_id'"
            ).fetchone()
        assert row is not None
        assert "received_at" in row["indexdef"].lower()

    def test_sql_idempotency_add_compression_policy_if_not_exists(self, tmp_db):
        """add_compression_policy if_not_exists=TRUE iki kez çalıştırılsa hata üretmemeli."""
        with tmp_db._connect() as conn:
            conn.execute(
                "SELECT add_compression_policy('normalized_logs', "
                "INTERVAL '7 days', if_not_exists => TRUE)"
            )
            conn.commit()

        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM timescaledb_information.jobs "
                "WHERE hypertable_name='normalized_logs' AND proc_name='policy_compression'"
            ).fetchone()
        assert row["cnt"] == 1, "Compression policy çift oluşmamalı"

    def test_downgrade_logs_warning_and_does_not_raise(self, caplog):
        """Downgrade NotImplementedError değil uyarı loglamalı (CI/CD pipeline kırılmaz)."""
        import logging
        import importlib.util
        import pathlib

        migration_path = (
            pathlib.Path(__file__).parents[1]
            / "alembic/versions/013_timescaledb_hypertable.py"
        )
        spec = importlib.util.spec_from_file_location("m013", migration_path)
        m013 = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m013)

        with caplog.at_level(logging.WARNING, logger="alembic.versions.013_timescaledb_hypertable"):
            m013.downgrade()  # hata atmamalı

        assert any(
            "downgrade" in r.message.lower() or "manuel" in r.message.lower()
            for r in caplog.records
        )

    def test_startup_check_logs_error_for_incompatible_index(self, tmp_db, caplog):
        """_check_hypertable_schema() uyumsuz index varsa logger.error üretmeli."""
        import logging
        from unittest.mock import patch, MagicMock

        fake_row = {"indexdef": "CREATE UNIQUE INDEX idx_norm_log_id ON normalized_logs(log_id)"}

        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = fake_row

        from contextlib import contextmanager

        @contextmanager
        def _fake_connect():
            yield mock_conn

        with patch.object(tmp_db, "_connect", _fake_connect):
            with caplog.at_level(logging.ERROR):
                tmp_db._check_hypertable_schema()

        assert any("partition-uyumsuz" in r.message for r in caplog.records)
