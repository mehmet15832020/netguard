"""
C2 — Alert bağlam pivot testi.

GET /api/v1/correlation/events/{corr_id}/context
DB: get_event_context_logs
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from server.main import app

client = TestClient(app)


def _now():
    return datetime.now(timezone.utc)


def _make_event(group_value="192.168.1.10", group_by_field="source_ip"):
    from shared.models import CorrelatedEvent
    return CorrelatedEvent(
        corr_id="test-corr-1",
        rule_id="ssh_brute",
        rule_name="SSH Brute Force",
        event_action="brute_force_detected",
        severity="warning",
        group_value=group_value,
        group_by_field=group_by_field,
        matched_count=5,
        window_seconds=60,
        first_seen=_now() - timedelta(minutes=10),
        last_seen=_now() - timedelta(minutes=5),
        message="SSH brute force from 192.168.1.10",
    )


def _make_log(source_type="zeek", cid=None):
    return {
        "log_id": "log-1",
        "source_type": source_type,
        "observer_hostname": "sensor1",
        "timestamp": _now().isoformat(),
        "severity": "info",
        "event_category": "network",
        "event_action": "ssh_auth_failure",
        "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.1",
        "source_port": 54321,
        "destination_port": 22,
        "network_protocol": "tcp",
        "message": "SSH auth failure",
        "tags": "[]",
        "community_id": cid,
    }


# ─── DB metodu ───────────────────────────────────────────────────────────────

class TestGetEventContextLogs:

    def test_returns_matching_logs(self, tmp_db):
        from shared.models import NormalizedLog, LogSourceType, LogCategory
        import uuid
        log = NormalizedLog(
            log_id=str(uuid.uuid4()),
            raw_id=str(uuid.uuid4()),
            source_type=LogSourceType.ZEEK,
            observer_hostname="zeek",
            timestamp=_now(),
            severity="info",
            event_category=LogCategory.NETWORK,
            event_action="ssh_auth_failure",
            source_ip="192.168.1.10",
            destination_ip="10.0.0.5",
            message="test",
        )
        tmp_db.save_normalized_log(log, tenant_id="default")
        since = _now() - timedelta(hours=1)
        until = _now() + timedelta(hours=1)
        result = tmp_db.get_event_context_logs("192.168.1.10", since, until, "default")
        assert isinstance(result, dict)
        assert "logs" in result
        assert "truncated" in result
        assert len(result["logs"]) >= 1
        assert any(r["source_ip"] == "192.168.1.10" for r in result["logs"])

    def test_destination_ip_also_matched(self, tmp_db):
        from shared.models import NormalizedLog, LogSourceType, LogCategory
        import uuid
        log = NormalizedLog(
            log_id=str(uuid.uuid4()),
            raw_id=str(uuid.uuid4()),
            source_type=LogSourceType.SURICATA,
            observer_hostname="suricata",
            timestamp=_now(),
            severity="warning",
            event_category=LogCategory.INTRUSION,
            event_action="suricata_alert",
            source_ip="10.0.0.1",
            destination_ip="192.168.1.99",
            message="alert",
        )
        tmp_db.save_normalized_log(log, tenant_id="default")
        since = _now() - timedelta(hours=1)
        until = _now() + timedelta(hours=1)
        result = tmp_db.get_event_context_logs("192.168.1.99", since, until, "default")
        assert any(r["destination_ip"] == "192.168.1.99" for r in result["logs"])

    def test_time_window_filters_old_logs(self, tmp_db):
        from shared.models import NormalizedLog, LogSourceType, LogCategory
        import uuid
        old_ts = _now() - timedelta(hours=5)
        log = NormalizedLog(
            log_id=str(uuid.uuid4()),
            raw_id=str(uuid.uuid4()),
            source_type=LogSourceType.ZEEK,
            observer_hostname="zeek",
            timestamp=old_ts,
            severity="info",
            event_category=LogCategory.NETWORK,
            event_action="test",
            source_ip="192.168.2.200",
            message="old log",
        )
        tmp_db.save_normalized_log(log, tenant_id="default")
        since = _now() - timedelta(minutes=30)
        until = _now()
        result = tmp_db.get_event_context_logs("192.168.2.200", since, until, "default")
        assert all(r["source_ip"] != "192.168.2.200" for r in result["logs"])

    def test_truncated_flag(self, tmp_db):
        from shared.models import NormalizedLog, LogSourceType, LogCategory
        import uuid
        for i in range(3):
            log = NormalizedLog(
                log_id=str(uuid.uuid4()),
                raw_id=str(uuid.uuid4()),
                source_type=LogSourceType.NETFLOW,
                observer_hostname="router",
                timestamp=_now(),
                severity="info",
                event_category=LogCategory.NETWORK,
                event_action="netflow_connection",
                source_ip="192.168.3.1",
                message=f"flow {i}",
            )
            tmp_db.save_normalized_log(log, tenant_id="default")
        since = _now() - timedelta(hours=1)
        until = _now() + timedelta(hours=1)
        result = tmp_db.get_event_context_logs("192.168.3.1", since, until, "default", limit=2)
        assert result["truncated"] is True
        assert len(result["logs"]) == 2

    def test_tenant_isolation(self, tmp_db):
        from shared.models import NormalizedLog, LogSourceType, LogCategory
        import uuid
        log = NormalizedLog(
            log_id=str(uuid.uuid4()),
            raw_id=str(uuid.uuid4()),
            source_type=LogSourceType.ZEEK,
            observer_hostname="zeek",
            timestamp=_now(),
            severity="info",
            event_category=LogCategory.NETWORK,
            event_action="test",
            source_ip="192.168.4.1",
            message="other tenant",
        )
        tmp_db.save_normalized_log(log, tenant_id="other")
        since = _now() - timedelta(hours=1)
        until = _now() + timedelta(hours=1)
        result = tmp_db.get_event_context_logs("192.168.4.1", since, until, "default")
        assert len(result["logs"]) == 0


# ─── Route testleri ───────────────────────────────────────────────────────────

class TestEventContextRoute:

    def test_requires_auth(self):
        r = client.get("/api/v1/correlation/events/test-1/context")
        assert r.status_code == 401

    def test_event_not_found(self, admin_token):
        with patch("server.routes.correlation.db") as mock_db:
            mock_db.get_correlated_event_by_id.return_value = None
            r = client.get(
                "/api/v1/correlation/events/nonexistent/context",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert r.status_code == 404

    def test_ip_based_event_returns_context(self, admin_token):
        event = _make_event(group_value="192.168.1.10", group_by_field="source_ip")
        with patch("server.routes.correlation.db") as mock_db:
            mock_db.get_correlated_event_by_id.return_value = event
            mock_db.get_event_context_logs.return_value = {
                "logs": [
                    _make_log("zeek", "1:abc123="),
                    _make_log("suricata", "1:abc123="),
                    _make_log("netflow", None),
                ],
                "truncated": False,
            }
            r = client.get(
                "/api/v1/correlation/events/test-corr-1/context",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert r.status_code == 200
        data = r.json()
        assert data["pivot_ip"] == "192.168.1.10"
        assert "zeek" in data["logs_by_source"]
        assert "suricata" in data["logs_by_source"]
        assert "1:abc123=" in data["community_ids"]
        assert data["total_logs"] == 3
        assert data["truncated"] is False

    def test_non_ip_group_value(self, admin_token):
        event = _make_event(group_value="sensor-host", group_by_field="observer_hostname")
        with patch("server.routes.correlation.db") as mock_db:
            mock_db.get_correlated_event_by_id.return_value = event
            r = client.get(
                "/api/v1/correlation/events/test-corr-1/context",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert r.status_code == 200
        data = r.json()
        assert data["pivot_ip"] is None
        assert data["logs_by_source"] == {}

    def test_window_minutes_validation(self, admin_token):
        event = _make_event()
        with patch("server.routes.correlation.db") as mock_db:
            mock_db.get_correlated_event_by_id.return_value = event
            r = client.get(
                "/api/v1/correlation/events/test-corr-1/context?window_minutes=999",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert r.status_code == 400

    def test_community_ids_deduplicated(self, admin_token):
        event = _make_event()
        cid = "1:K2Z9rgZl/kbRXxTe32amzRohiJo="
        with patch("server.routes.correlation.db") as mock_db:
            mock_db.get_correlated_event_by_id.return_value = event
            mock_db.get_event_context_logs.return_value = {
                "logs": [_make_log("zeek", cid), _make_log("suricata", cid)],
                "truncated": False,
            }
            r = client.get(
                "/api/v1/correlation/events/test-corr-1/context",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert r.status_code == 200
        assert r.json()["community_ids"].count(cid) == 1

    def test_truncated_propagated(self, admin_token):
        event = _make_event()
        with patch("server.routes.correlation.db") as mock_db:
            mock_db.get_correlated_event_by_id.return_value = event
            mock_db.get_event_context_logs.return_value = {
                "logs": [_make_log() for _ in range(5)],
                "truncated": True,
            }
            r = client.get(
                "/api/v1/correlation/events/test-corr-1/context",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert r.status_code == 200
        assert r.json()["truncated"] is True
