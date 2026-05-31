"""
A2 — PostgreSQLLogStore.count_by_group() testleri.

OWASP A3 (Injection) gereği geçersiz kolon adı reddi,
NIST SP 800-94 §6.1 gereği window-based gruplama doğrulaması.
"""

import uuid
import pytest
from datetime import datetime, timezone, timedelta

from shared.models import NormalizedLog, LogSourceType, LogCategory


def _insert_log(conn, *, event_action, source_ip, severity="warning",
                tenant_id="default", minutes_ago=0, message="test"):
    ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    conn.execute(
        """
        INSERT INTO normalized_logs
          (log_id, raw_id, source_type, observer_hostname, timestamp,
           severity, event_category, event_action, source_ip, message,
           tenant_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            str(uuid.uuid4()), str(uuid.uuid4()), "netguard", "host",
            ts, severity, "network", event_action, source_ip, message, tenant_id,
        ),
    )
    conn.commit()


class TestCountByGroupBasic:
    def test_groups_by_event_action(self, tmp_db):
        with tmp_db._connect() as conn:
            _insert_log(conn, event_action="ssh_failure", source_ip="1.2.3.4")
            _insert_log(conn, event_action="ssh_failure", source_ip="1.2.3.5")
            _insert_log(conn, event_action="port_scan_attempt", source_ip="1.2.3.6")

        from server.log_store import log_store
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        results = log_store.count_by_group("event_action", since=since)

        result_map = dict(results)
        assert result_map["ssh_failure"] == 2
        assert result_map["port_scan_attempt"] == 1

    def test_groups_by_source_ip(self, tmp_db):
        with tmp_db._connect() as conn:
            for _ in range(3):
                _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.1")
            _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.2")

        from server.log_store import log_store
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        results = log_store.count_by_group("source_ip", since=since)

        result_map = dict(results)
        assert result_map["10.0.0.1"] == 3
        assert result_map["10.0.0.2"] == 1

    def test_ordered_by_count_descending(self, tmp_db):
        with tmp_db._connect() as conn:
            for _ in range(5):
                _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.1")
            for _ in range(2):
                _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.2")
            _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.3")

        from server.log_store import log_store
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        results = log_store.count_by_group("source_ip", since=since)

        counts = [cnt for _, cnt in results]
        assert counts == sorted(counts, reverse=True)

    def test_empty_table_returns_empty_list(self, tmp_db):
        from server.log_store import log_store
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        results = log_store.count_by_group("event_action", since=since)
        assert results == []


class TestCountByGroupFilters:
    def test_event_action_filter(self, tmp_db):
        with tmp_db._connect() as conn:
            for _ in range(3):
                _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.1")
            for _ in range(2):
                _insert_log(conn, event_action="port_scan_attempt", source_ip="10.0.0.2")

        from server.log_store import log_store
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        results = log_store.count_by_group(
            "source_ip", event_action="ssh_failure", since=since
        )

        result_map = dict(results)
        assert "10.0.0.1" in result_map
        assert "10.0.0.2" not in result_map

    def test_message_filter(self, tmp_db):
        with tmp_db._connect() as conn:
            _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.1",
                        message="SSH brute force from china")
            _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.2",
                        message="Normal SSH failure")

        from server.log_store import log_store
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        results = log_store.count_by_group(
            "source_ip", message_filter="brute force", since=since
        )

        result_map = dict(results)
        assert "10.0.0.1" in result_map
        assert "10.0.0.2" not in result_map

    def test_until_filter_excludes_future(self, tmp_db):
        with tmp_db._connect() as conn:
            _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.1",
                        minutes_ago=0)
            _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.2",
                        minutes_ago=60)

        from server.log_store import log_store
        since = datetime.now(timezone.utc) - timedelta(hours=2)
        until = datetime.now(timezone.utc) - timedelta(minutes=30)
        results = log_store.count_by_group("source_ip", since=since, until=until)

        result_map = dict(results)
        assert "10.0.0.2" in result_map
        assert "10.0.0.1" not in result_map

    def test_since_filter_excludes_old_logs(self, tmp_db):
        with tmp_db._connect() as conn:
            _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.1",
                        minutes_ago=120)

        from server.log_store import log_store
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        results = log_store.count_by_group("source_ip", since=since)
        assert results == []

    def test_tenant_isolation(self, tmp_db):
        with tmp_db._connect() as conn:
            _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.1",
                        tenant_id="tenant_a")
            _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.2",
                        tenant_id="tenant_b")

        from server.log_store import log_store
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        results = log_store.count_by_group(
            "source_ip", since=since, tenant_id="tenant_a"
        )

        result_map = dict(results)
        assert "10.0.0.1" in result_map
        assert "10.0.0.2" not in result_map


class TestCountByGroupEdgeCases:
    def test_null_group_values_excluded(self, tmp_db):
        """source_ip NULL olan satırlar sonuca dahil edilmemeli."""
        with tmp_db._connect() as conn:
            conn.execute(
                """
                INSERT INTO normalized_logs
                  (log_id, raw_id, source_type, observer_hostname, timestamp,
                   severity, event_category, event_action, source_ip, message, tenant_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NULL, %s, %s)
                """,
                (
                    str(uuid.uuid4()), str(uuid.uuid4()), "netguard", "host",
                    datetime.now(timezone.utc).isoformat(),
                    "warning", "network", "ssh_failure", "null ip row", "default",
                ),
            )
            conn.commit()

        from server.log_store import log_store
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        results = log_store.count_by_group("source_ip", since=since)
        assert all(val is not None and val != "None" for val, _ in results)

    def test_port_returned_as_string(self, tmp_db):
        """destination_port integer olsa da tuple[str, int] döndürmeli."""
        with tmp_db._connect() as conn:
            conn.execute(
                """
                INSERT INTO normalized_logs
                  (log_id, raw_id, source_type, observer_hostname, timestamp,
                   severity, event_category, event_action, source_ip,
                   destination_port, message, tenant_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(uuid.uuid4()), str(uuid.uuid4()), "netguard", "host",
                    datetime.now(timezone.utc).isoformat(),
                    "warning", "network", "ssh_failure", "10.0.0.1",
                    22, "ssh port", "default",
                ),
            )
            conn.commit()

        from server.log_store import log_store
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        results = log_store.count_by_group("destination_port", since=since)
        assert len(results) == 1
        val, cnt = results[0]
        assert isinstance(val, str)
        assert val == "22"

    def test_message_filter_ilike_wildcard_escaped(self, tmp_db):
        """message_filter içindeki % wildcard literal olarak eşleşmeli."""
        with tmp_db._connect() as conn:
            _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.1",
                        message="CPU usage 100%")
            _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.2",
                        message="CPU usage 50%")
            _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.3",
                        message="Normal log")

        from server.log_store import log_store
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        results = log_store.count_by_group(
            "source_ip", message_filter="CPU usage 100%", since=since
        )
        result_map = dict(results)
        assert "10.0.0.1" in result_map
        assert "10.0.0.2" not in result_map

    def test_message_filter_case_insensitive(self, tmp_db):
        """ILIKE büyük/küçük harf duyarsız eşleşmeli."""
        with tmp_db._connect() as conn:
            _insert_log(conn, event_action="ssh_failure", source_ip="10.0.0.1",
                        message="BRUTE FORCE ATTACK")

        from server.log_store import log_store
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        results = log_store.count_by_group(
            "source_ip", message_filter="brute force", since=since
        )
        assert len(results) == 1


class TestCountByGroupSecurity:
    def test_invalid_group_by_raises_value_error(self, tmp_db):
        from server.log_store import log_store
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        with pytest.raises(ValueError, match="Geçersiz group_by"):
            log_store.count_by_group("message; DROP TABLE normalized_logs; --", since=since)

    def test_unknown_column_raises_value_error(self, tmp_db):
        from server.log_store import log_store
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        with pytest.raises(ValueError):
            log_store.count_by_group("nonexistent_column", since=since)

    def test_all_valid_group_cols_accepted(self, tmp_db):
        from server.log_store import log_store, _VALID_LOG_GROUP_COLS
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        for col in _VALID_LOG_GROUP_COLS:
            results = log_store.count_by_group(col, since=since)
            assert isinstance(results, list)
