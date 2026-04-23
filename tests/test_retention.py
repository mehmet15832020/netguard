"""
Log Retention Manager testleri.
"""

import gzip
import json
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


@pytest.fixture
def retention_env(tmp_path, monkeypatch):
    """Kısa retention süreleri ve geçici arşiv dizini ile test ortamı."""
    monkeypatch.setenv("NETGUARD_RETAIN_NORMALIZED_DAYS", "1")
    monkeypatch.setenv("NETGUARD_RETAIN_SECURITY_DAYS", "1")
    monkeypatch.setenv("NETGUARD_RETAIN_CORRELATED_DAYS", "7")
    monkeypatch.setenv("NETGUARD_RETAIN_ALERTS_DAYS", "1")
    monkeypatch.setenv("NETGUARD_ARCHIVE_DIR", str(tmp_path / "archive"))
    monkeypatch.setenv("NETGUARD_ARCHIVE_TOTAL_DAYS", "365")

    import importlib
    import server.retention as ret
    importlib.reload(ret)
    return ret, tmp_path / "archive"


def _old_ts(days=5):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def _new_ts():
    return datetime.now(timezone.utc).isoformat()


class TestRetentionCleanup:
    def test_cleanup_archives_old_rows(self, tmp_db, retention_env):
        ret, archive_dir = retention_env
        from server.database import db

        old_ts = _old_ts(5)
        new_ts = _new_ts()

        with db._connect() as conn:
            conn.execute(
                "INSERT INTO normalized_logs (log_id, raw_id, source_type, source_host, timestamp, received_at, severity, category, event_type, src_ip, dst_ip, src_port, dst_port, username, message, tags, processed_at) "
                "VALUES (?, 'r1', 'syslog', 'h', ?, ?, 'info', 'system', 'test', NULL, NULL, NULL, NULL, NULL, 'old', '[]', ?)",
                ("old-1", old_ts, old_ts, old_ts),
            )
            conn.execute(
                "INSERT INTO normalized_logs (log_id, raw_id, source_type, source_host, timestamp, received_at, severity, category, event_type, src_ip, dst_ip, src_port, dst_port, username, message, tags, processed_at) "
                "VALUES (?, 'r2', 'syslog', 'h', ?, ?, 'info', 'system', 'test', NULL, NULL, NULL, NULL, NULL, 'new', '[]', ?)",
                ("new-1", new_ts, new_ts, new_ts),
            )

        report = ret.run_retention()

        assert report["tables"]["normalized_logs"]["archived"] == 1
        assert report["tables"]["normalized_logs"]["deleted"] == 1

        # Yeni kayıt DB'de kalmış olmalı
        with db._connect() as conn:
            remaining = conn.execute("SELECT COUNT(*) FROM normalized_logs").fetchone()[0]
        assert remaining == 1

    def test_archive_file_created(self, tmp_db, retention_env):
        ret, archive_dir = retention_env
        from server.database import db

        old_ts = _old_ts(5)
        with db._connect() as conn:
            conn.execute(
                "INSERT INTO normalized_logs (log_id, raw_id, source_type, source_host, timestamp, received_at, severity, category, event_type, src_ip, dst_ip, src_port, dst_port, username, message, tags, processed_at) "
                "VALUES (?, 'r3', 'syslog', 'h', ?, ?, 'info', 'system', 'test', NULL, NULL, NULL, NULL, NULL, 'msg', '[]', ?)",
                ("arch-1", old_ts, old_ts, old_ts),
            )

        ret.run_retention()

        gz_files = list(archive_dir.glob("normalized_logs_*.json.gz"))
        assert len(gz_files) == 1

        with gzip.open(gz_files[0], "rt") as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["message"] == "msg"

    def test_recent_rows_not_deleted(self, tmp_db, retention_env):
        ret, _ = retention_env
        from server.database import db

        new_ts = _new_ts()
        with db._connect() as conn:
            conn.execute(
                "INSERT INTO normalized_logs (log_id, raw_id, source_type, source_host, timestamp, received_at, severity, category, event_type, src_ip, dst_ip, src_port, dst_port, username, message, tags, processed_at) "
                "VALUES (?, 'r4', 'syslog', 'h', ?, ?, 'info', 'system', 'test', NULL, NULL, NULL, NULL, NULL, 'keep', '[]', ?)",
                ("keep-1", new_ts, new_ts, new_ts),
            )

        report = ret.run_retention()
        assert report["tables"]["normalized_logs"]["archived"] == 0

    def test_only_resolved_alerts_deleted(self, tmp_db, retention_env):
        ret, _ = retention_env
        from server.database import db

        old_ts = _old_ts(5)
        with db._connect() as conn:
            conn.execute(
                "INSERT INTO alerts (alert_id, agent_id, hostname, severity, status, metric, message, value, threshold, triggered_at) "
                "VALUES (?, 'a', 'h', 'warning', 'resolved', 'm', 'msg', 1.0, 0.0, ?)",
                ("old-resolved", old_ts),
            )
            conn.execute(
                "INSERT INTO alerts (alert_id, agent_id, hostname, severity, status, metric, message, value, threshold, triggered_at) "
                "VALUES (?, 'a', 'h', 'critical', 'active', 'm', 'msg', 1.0, 0.0, ?)",
                ("old-active", old_ts),
            )

        ret.run_retention()

        with db._connect() as conn:
            remaining = conn.execute(
                "SELECT alert_id FROM alerts"
            ).fetchall()
        ids = [r[0] for r in remaining]
        assert "old-active" in ids
        assert "old-resolved" not in ids

    def test_report_structure(self, tmp_db, retention_env):
        ret, _ = retention_env
        report = ret.run_retention()
        assert "started_at" in report
        assert "completed_at" in report
        assert "total_archived" in report
        assert "total_deleted" in report
        assert "tables" in report

    def test_purge_old_archives(self, tmp_path, monkeypatch):
        import server.retention as ret
        import importlib
        monkeypatch.setenv("NETGUARD_ARCHIVE_DIR", str(tmp_path / "archive"))
        monkeypatch.setenv("NETGUARD_ARCHIVE_TOTAL_DAYS", "1")
        importlib.reload(ret)

        archive_dir = tmp_path / "archive"
        archive_dir.mkdir()

        old_file = archive_dir / "normalized_logs_2020-01-01.json.gz"
        with gzip.open(old_file, "wt") as f:
            json.dump([], f)
        import os, time
        os.utime(old_file, (0, 0))

        purged = ret._purge_old_archives()
        assert purged == 1
        assert not old_file.exists()
