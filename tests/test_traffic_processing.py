"""
Traffic summary işleme testleri.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from shared.models import ProtocolStats, TrafficSummary


def _make_summary(suspicious=0, src_ips=None) -> TrafficSummary:
    return TrafficSummary(
        interface="eth0",
        duration_sec=10.0,
        total_packets=100,
        total_bytes=50000,
        protocols=[
            ProtocolStats(protocol="TCP", packet_count=60, byte_count=30000, percentage=60.0),
            ProtocolStats(protocol="UDP", packet_count=40, byte_count=20000, percentage=40.0),
        ],
        top_src_ips=src_ips or ["192.168.1.5", "10.0.0.1"],
        top_dst_ips=["8.8.8.8"],
        captured_at=datetime.now(timezone.utc),
        suspicious_packet_count=suspicious,
    )


class TestProcessTrafficSummary:
    def test_normal_traffic_no_log_created(self, tmp_db):
        from server.routes.agents import _process_traffic_summary
        with patch("server.routes.agents.influx_writer") as mock_influx:
            mock_influx.write_traffic.return_value = True
            _process_traffic_summary("agent-1", "host1", _make_summary(suspicious=0))
        logs = tmp_db.get_normalized_logs()
        assert not any(l.event_type == "suspicious_traffic" for l in logs)

    def test_suspicious_traffic_creates_warning_log(self, tmp_db):
        from server.routes.agents import _process_traffic_summary
        with patch("server.routes.agents.influx_writer") as mock_influx:
            mock_influx.write_traffic.return_value = True
            _process_traffic_summary("agent-1", "host1", _make_summary(suspicious=7))
        logs = tmp_db.get_normalized_logs()
        suspicious = [l for l in logs if l.event_type == "suspicious_traffic"]
        assert len(suspicious) == 1
        assert suspicious[0].severity == "warning"

    def test_high_suspicious_count_creates_critical_log(self, tmp_db):
        from server.routes.agents import _process_traffic_summary
        with patch("server.routes.agents.influx_writer") as mock_influx:
            mock_influx.write_traffic.return_value = True
            _process_traffic_summary("agent-1", "host1", _make_summary(suspicious=20))
        logs = tmp_db.get_normalized_logs()
        suspicious = [l for l in logs if l.event_type == "suspicious_traffic"]
        assert len(suspicious) == 1
        assert suspicious[0].severity == "critical"

    def test_suspicious_traffic_feeds_kill_chain(self, tmp_db):
        from server.routes.agents import _process_traffic_summary
        triggered = []
        with patch("server.routes.agents.influx_writer") as mock_influx, \
             patch("server.routes.agents.attack_chain_tracker") as mock_tracker:
            mock_influx.write_traffic.return_value = True
            mock_tracker.record.return_value = None
            _process_traffic_summary(
                "agent-1", "host1",
                _make_summary(suspicious=10, src_ips=["10.0.0.5"]),
            )
            mock_tracker.record.assert_called_with(
                src_ip="10.0.0.5",
                event_type="port_scan",
                occurred_at=mock_tracker.record.call_args.kwargs["occurred_at"],
            )

    def test_influx_write_called(self, tmp_db):
        from server.routes.agents import _process_traffic_summary
        with patch("server.routes.agents.influx_writer") as mock_influx:
            mock_influx.write_traffic.return_value = True
            _process_traffic_summary("agent-1", "host1", _make_summary(suspicious=0))
        mock_influx.write_traffic.assert_called_once()


class TestReceiveMetricsWithTraffic:
    @pytest.fixture(autouse=True)
    def setup(self, tmp_db):
        from server.main import app
        self.client = TestClient(app)

    def _snapshot_payload(self, with_traffic=False, suspicious=0):
        now = datetime.now(timezone.utc).isoformat()
        payload = {
            "agent_id": "test-agent",
            "hostname": "testhost",
            "collected_at": now,
            "status": "online",
            "cpu": {"usage_percent": 10.0, "core_count": 4, "load_avg_1m": 0.5},
            "memory": {
                "total_bytes": 8000000000,
                "used_bytes": 2000000000,
                "available_bytes": 6000000000,
                "usage_percent": 25.0,
            },
            "disks": [],
            "network_interfaces": [],
        }
        if with_traffic:
            payload["traffic_summary"] = {
                "interface": "eth0",
                "duration_sec": 10.0,
                "total_packets": 100,
                "total_bytes": 50000,
                "protocols": [],
                "top_src_ips": ["192.168.1.5"],
                "top_dst_ips": ["8.8.8.8"],
                "captured_at": now,
                "suspicious_packet_count": suspicious,
            }
        return payload

    def test_snapshot_without_traffic_accepted(self):
        with patch("server.routes.agents.influx_writer"):
            resp = self.client.post(
                "/api/v1/agents/metrics",
                json=self._snapshot_payload(with_traffic=False),
            )
        assert resp.status_code == 202

    def test_snapshot_with_traffic_accepted(self):
        with patch("server.routes.agents.influx_writer"):
            resp = self.client.post(
                "/api/v1/agents/metrics",
                json=self._snapshot_payload(with_traffic=True, suspicious=3),
            )
        assert resp.status_code == 202

    def test_suspicious_traffic_creates_log_via_endpoint(self, tmp_db):
        with patch("server.routes.agents.influx_writer"):
            self.client.post(
                "/api/v1/agents/metrics",
                json=self._snapshot_payload(with_traffic=True, suspicious=10),
            )
        logs = tmp_db.get_normalized_logs()
        assert any(l.event_type == "suspicious_traffic" for l in logs)
