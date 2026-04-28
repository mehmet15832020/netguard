"""
Metrik endpoint testleri — get_log_volume ve /metrics/agent, /metrics/log-volume.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from shared.models import LogCategory, LogSourceType, NormalizedLog


def _make_log(message="test") -> NormalizedLog:
    now = datetime.now(timezone.utc)
    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=LogSourceType.SYSLOG,
        source_host="firewall",
        timestamp=now,
        received_at=now,
        severity="info",
        category=LogCategory.NETWORK,
        event_type="firewall_allow",
        message=message,
        processed_at=now,
    )


class TestGetLogVolume:
    def test_empty_db_returns_empty_list(self, tmp_db):
        result = tmp_db.get_log_volume("24h")
        assert isinstance(result, list)
        assert result == []

    def test_logs_are_bucketed_by_hour(self, tmp_db):
        tmp_db.save_normalized_log(_make_log("a"))
        tmp_db.save_normalized_log(_make_log("b"))
        tmp_db.save_normalized_log(_make_log("c"))

        result = tmp_db.get_log_volume("1h")
        assert len(result) >= 1
        total = sum(r["c"] for r in result)
        assert total == 3

    def test_result_has_t_and_c_keys(self, tmp_db):
        tmp_db.save_normalized_log(_make_log())
        result = tmp_db.get_log_volume("24h")
        assert len(result) >= 1
        assert "t" in result[0]
        assert "c" in result[0]

    def test_invalid_range_falls_back_to_24h(self, tmp_db):
        tmp_db.save_normalized_log(_make_log())
        result = tmp_db.get_log_volume("invalid_range")
        assert isinstance(result, list)


class TestMetricsEndpoints:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_db):
        from server.main import app
        self.client = TestClient(app)

    def test_log_volume_endpoint_ok(self, admin_token):
        resp = self.client.get(
            "/api/v1/metrics/log-volume?range=24h",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "range" in data
        assert "data" in data
        assert isinstance(data["data"], list)

    def test_log_volume_invalid_range_returns_400(self, admin_token):
        resp = self.client.get(
            "/api/v1/metrics/log-volume?range=99h",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 400

    def test_agent_metrics_not_found_returns_404(self, admin_token):
        with patch("server.routes.metrics.storage") as mock_storage:
            mock_storage.get_agent.return_value = None
            resp = self.client.get(
                "/api/v1/metrics/agent/nonexistent-agent",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
        assert resp.status_code == 404

    def test_agent_metrics_influx_disabled_returns_available_false(self, superadmin_token):
        fake_agent = MagicMock()
        fake_agent.tenant_id = None
        with patch("server.routes.metrics.storage") as mock_storage, \
             patch("server.routes.metrics.influx_writer") as mock_influx:
            mock_storage.get_agent.return_value = fake_agent
            mock_influx.query_agent_metrics.return_value = None
            resp = self.client.get(
                "/api/v1/metrics/agent/test-agent?range=1h",
                headers={"Authorization": f"Bearer {superadmin_token}"},
            )
        assert resp.status_code == 200
        assert resp.json()["available"] is False

    def test_agent_metrics_influx_enabled_returns_data(self, superadmin_token):
        fake_agent = MagicMock()
        fake_agent.tenant_id = None
        mock_data = {
            "cpu":     [{"t": "2026-04-28T10:00:00+00:00", "v": 12.5}],
            "memory":  [{"t": "2026-04-28T10:00:00+00:00", "v": 55.0}],
            "net_in":  [{"t": "2026-04-28T10:00:00+00:00", "v": 1024.0}],
            "net_out": [{"t": "2026-04-28T10:00:00+00:00", "v": 512.0}],
        }
        with patch("server.routes.metrics.storage") as mock_storage, \
             patch("server.routes.metrics.influx_writer") as mock_influx:
            mock_storage.get_agent.return_value = fake_agent
            mock_influx.query_agent_metrics.return_value = mock_data
            resp = self.client.get(
                "/api/v1/metrics/agent/test-agent2?range=1h",
                headers={"Authorization": f"Bearer {superadmin_token}"},
            )
        assert resp.status_code == 200
        body = resp.json()
        assert body["available"] is True
        assert body["cpu"][0]["v"] == 12.5
