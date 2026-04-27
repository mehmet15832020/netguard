"""
FTS5 log arama testleri.
"""

import uuid
from datetime import datetime, timezone

import pytest

from server.database import DatabaseManager
from shared.models import (
    LogCategory, LogSourceType, NormalizedLog,
)


def _make_log(
    message="test message",
    src_ip=None,
    dst_ip=None,
    source_host="firewall",
    username=None,
    event_type="firewall_allow",
    source_type=LogSourceType.SYSLOG,
    category=LogCategory.NETWORK,
) -> NormalizedLog:
    now = datetime.now(timezone.utc)
    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=source_type,
        source_host=source_host,
        timestamp=now,
        received_at=now,
        severity="info",
        category=category,
        event_type=event_type,
        src_ip=src_ip,
        dst_ip=dst_ip,
        message=message,
        processed_at=now,
    )


class TestFTS5Search:
    def test_fts_finds_by_message_keyword(self, tmp_db):
        tmp_db.save_normalized_log(_make_log(message="failed login attempt detected"))
        tmp_db.save_normalized_log(_make_log(message="successful connection established"))

        results = tmp_db.search_logs("failed")
        assert len(results) == 1
        assert "failed" in results[0].message

    def test_fts_multiword_search(self, tmp_db):
        tmp_db.save_normalized_log(_make_log(message="port scan detected from external host"))
        tmp_db.save_normalized_log(_make_log(message="port opened on interface eth0"))
        tmp_db.save_normalized_log(_make_log(message="normal traffic allowed"))

        results = tmp_db.search_logs("port scan")
        assert len(results) == 1
        assert "port scan" in results[0].message

    def test_ip_search_uses_like(self, tmp_db):
        tmp_db.save_normalized_log(_make_log(src_ip="192.168.1.5",  message="traffic from attacker"))
        tmp_db.save_normalized_log(_make_log(src_ip="10.0.0.1",     message="internal traffic"))
        tmp_db.save_normalized_log(_make_log(dst_ip="192.168.1.5",  message="traffic to attacker"))

        results = tmp_db.search_logs("192.168.1.5")
        assert len(results) == 2

    def test_ip_prefix_search(self, tmp_db):
        tmp_db.save_normalized_log(_make_log(src_ip="192.168.1.5",  message="a"))
        tmp_db.save_normalized_log(_make_log(src_ip="192.168.1.10", message="b"))
        tmp_db.save_normalized_log(_make_log(src_ip="10.0.0.1",     message="c"))

        results = tmp_db.search_logs("192.168.1")
        assert len(results) == 2

    def test_empty_query_returns_normal_list(self, tmp_db):
        for i in range(3):
            tmp_db.save_normalized_log(_make_log(message=f"log {i}"))

        results = tmp_db.search_logs("")
        assert len(results) == 3

    def test_search_with_source_filter(self, tmp_db):
        tmp_db.save_normalized_log(_make_log(
            message="failed auth", source_type=LogSourceType.SYSLOG
        ))
        tmp_db.save_normalized_log(_make_log(
            message="failed auth", source_type=LogSourceType.NGINX
        ))

        results = tmp_db.search_logs("failed", source_type="syslog")
        assert len(results) == 1
        assert results[0].source_type == LogSourceType.SYSLOG

    def test_search_with_category_filter(self, tmp_db):
        tmp_db.save_normalized_log(_make_log(
            message="failed", category=LogCategory.AUTHENTICATION
        ))
        tmp_db.save_normalized_log(_make_log(
            message="failed", category=LogCategory.NETWORK
        ))

        results = tmp_db.search_logs("failed", category="authentication")
        assert len(results) == 1

    def test_no_results_returns_empty(self, tmp_db):
        tmp_db.save_normalized_log(_make_log(message="normal event"))
        results = tmp_db.search_logs("xyznonexistent")
        assert results == []

    def test_existing_logs_indexed_on_init(self, tmp_path):
        """DB'yi açmadan önce eklenmiş loglar FTS ile bulunabilmeli."""
        db_path = str(tmp_path / "prefill.db")

        db1 = DatabaseManager(db_path=db_path)
        db1.save_normalized_log(_make_log(message="ssh brute force attempt"))

        db2 = DatabaseManager(db_path=db_path)
        results = db2.search_logs("brute force")
        assert len(results) == 1

    def test_fts_invalid_query_returns_empty(self, tmp_db):
        """Hatalı FTS5 sözdizimi exception fırlatmak yerine boş liste döner."""
        tmp_db.save_normalized_log(_make_log(message="test"))
        results = tmp_db.search_logs('AND OR ""')
        assert isinstance(results, list)

    def test_limit_applied_to_search(self, tmp_db):
        for i in range(20):
            tmp_db.save_normalized_log(_make_log(message=f"failed event {i}"))
        results = tmp_db.search_logs("failed", limit=5)
        assert len(results) == 5
