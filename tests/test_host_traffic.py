"""
B4 — agent/traffic_collector.py (pyshark) kaldırıldı; server/host_traffic.py
aynı dashboard panelini Zeek conn.log + NetFlow kayıtlarından üretir.

Kapsam:
  - build_traffic_summary(): saf agregasyon mantığı
  - database.py::get_host_traffic_rows(): gerçek DB sorgusu
  - GET /agents/{id}/traffic: uçtan uca (register → IP kaydı → agregasyon)
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from server.auth import register_agent_key
from server.host_traffic import build_traffic_summary
from server.main import app
from shared.models import LogCategory, LogSourceType, NormalizedLog

client = TestClient(app)


def _row(source_ip=None, destination_ip=None, protocol="tcp", network_bytes=1000,
         severity="info", extra=None):
    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "network_protocol": protocol,
        "network_bytes": network_bytes,
        "extra": json.dumps(extra or {}),
        "severity": severity,
        "source_type": "netflow",
    }


class TestBuildTrafficSummaryAggregation:
    def test_empty_rows_returns_zeroed_summary(self):
        summary = build_traffic_summary("10.0.0.5", [], window_seconds=300)
        assert summary.total_packets == 0
        assert summary.total_bytes == 0
        assert summary.protocols == []
        assert summary.top_src_ips == []
        assert summary.top_dst_ips == []
        assert summary.interface == "Zeek + NetFlow"

    def test_sums_bytes_across_rows(self):
        rows = [
            _row(source_ip="10.0.0.5", destination_ip="8.8.8.8", network_bytes=1000),
            _row(source_ip="10.0.0.5", destination_ip="1.1.1.1", network_bytes=2000),
        ]
        summary = build_traffic_summary("10.0.0.5", rows, window_seconds=300)
        assert summary.total_bytes == 3000

    def test_netflow_packet_count_from_extra(self):
        rows = [_row(source_ip="10.0.0.5", destination_ip="8.8.8.8", extra={"packets": 42})]
        summary = build_traffic_summary("10.0.0.5", rows, window_seconds=300)
        assert summary.total_packets == 42

    def test_zeek_row_without_packets_counts_as_one_flow(self):
        rows = [_row(source_ip="10.0.0.5", destination_ip="8.8.8.8", extra={})]
        summary = build_traffic_summary("10.0.0.5", rows, window_seconds=300)
        assert summary.total_packets == 1

    def test_protocol_grouping_and_percentage(self):
        rows = [
            _row(source_ip="10.0.0.5", destination_ip="8.8.8.8", protocol="tcp", network_bytes=750),
            _row(source_ip="10.0.0.5", destination_ip="1.1.1.1", protocol="udp", network_bytes=250),
        ]
        summary = build_traffic_summary("10.0.0.5", rows, window_seconds=300)
        by_proto = {p.protocol: p for p in summary.protocols}
        assert by_proto["TCP"].percentage == 75.0
        assert by_proto["UDP"].percentage == 25.0

    def test_top_dst_ips_when_agent_is_source(self):
        rows = [
            _row(source_ip="10.0.0.5", destination_ip="8.8.8.8"),
            _row(source_ip="10.0.0.5", destination_ip="8.8.8.8"),
            _row(source_ip="10.0.0.5", destination_ip="1.1.1.1"),
        ]
        summary = build_traffic_summary("10.0.0.5", rows, window_seconds=300)
        assert summary.top_dst_ips[0] == "8.8.8.8"
        assert "1.1.1.1" in summary.top_dst_ips

    def test_top_src_ips_when_agent_is_destination(self):
        rows = [
            _row(source_ip="203.0.113.7", destination_ip="10.0.0.5"),
            _row(source_ip="203.0.113.7", destination_ip="10.0.0.5"),
        ]
        summary = build_traffic_summary("10.0.0.5", rows, window_seconds=300)
        assert summary.top_src_ips[0] == "203.0.113.7"

    def test_suspicious_count_from_severity(self):
        rows = [
            _row(source_ip="10.0.0.5", destination_ip="8.8.8.8", severity="info"),
            _row(source_ip="10.0.0.5", destination_ip="1.1.1.1", severity="warning"),
            _row(source_ip="10.0.0.5", destination_ip="9.9.9.9", severity="critical"),
        ]
        summary = build_traffic_summary("10.0.0.5", rows, window_seconds=300)
        assert summary.suspicious_packet_count == 2

    def test_self_loop_excluded_from_top_ip_lists(self):
        """Agent kendi kendine bağlanırsa (loopback benzeri) top listede görünmemeli."""
        rows = [_row(source_ip="10.0.0.5", destination_ip="10.0.0.5")]
        summary = build_traffic_summary("10.0.0.5", rows, window_seconds=300)
        assert summary.top_src_ips == []
        assert summary.top_dst_ips == []

    def test_malformed_extra_json_falls_back_to_one_packet(self):
        rows = [{
            "source_ip": "10.0.0.5", "destination_ip": "8.8.8.8",
            "network_protocol": "tcp", "network_bytes": 100,
            "extra": "{not valid json", "severity": "info", "source_type": "netflow",
        }]
        summary = build_traffic_summary("10.0.0.5", rows, window_seconds=300)
        assert summary.total_packets == 1

    def test_null_protocol_grouped_as_other(self):
        rows = [_row(source_ip="10.0.0.5", destination_ip="8.8.8.8", protocol=None)]
        summary = build_traffic_summary("10.0.0.5", rows, window_seconds=300)
        assert summary.protocols[0].protocol == "OTHER"

    def test_window_seconds_passed_through_as_duration(self):
        summary = build_traffic_summary("10.0.0.5", [], window_seconds=300)
        assert summary.duration_sec == 300


def _norm_log(source_ip, destination_ip, source_type, network_bytes=500, severity="info", extra=None):
    return NormalizedLog(
        log_id=str(uuid.uuid4()),
        raw_id=str(uuid.uuid4()),
        source_type=source_type,
        observer_hostname="test",
        timestamp=datetime.now(timezone.utc),
        severity=severity,
        event_category=LogCategory.NETWORK,
        event_action="network_connection",
        source_ip=source_ip,
        destination_ip=destination_ip,
        network_protocol="tcp",
        message="test",
        network_bytes=network_bytes,
        extra=extra or {},
    )


class TestGetHostTrafficRows:
    def test_finds_rows_where_ip_is_source_or_destination(self, tmp_db):
        tmp_db.save_normalized_log(_norm_log("10.0.0.9", "8.8.8.8", LogSourceType.NETFLOW))
        tmp_db.save_normalized_log(_norm_log("1.1.1.1", "10.0.0.9", LogSourceType.ZEEK))
        tmp_db.save_normalized_log(_norm_log("9.9.9.9", "8.8.4.4", LogSourceType.NETFLOW))  # ilgisiz

        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        rows = tmp_db.get_host_traffic_rows("10.0.0.9", since)
        assert len(rows) == 2

    def test_excludes_other_source_types(self, tmp_db):
        tmp_db.save_normalized_log(_norm_log("10.0.0.9", "8.8.8.8", LogSourceType.SURICATA))
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        rows = tmp_db.get_host_traffic_rows("10.0.0.9", since)
        assert rows == []

    def test_extra_and_network_bytes_preserved(self, tmp_db):
        """P5 bug'ı bypass eder — get_normalized_logs()'tan farklı olarak bu alanlar kaybolmaz."""
        tmp_db.save_normalized_log(
            _norm_log("10.0.0.9", "8.8.8.8", LogSourceType.NETFLOW, network_bytes=12345, extra={"packets": 7})
        )
        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        rows = tmp_db.get_host_traffic_rows("10.0.0.9", since)
        assert rows[0]["network_bytes"] == 12345
        assert json.loads(rows[0]["extra"])["packets"] == 7

    def test_respects_time_window(self, tmp_db):
        old_log = _norm_log("10.0.0.9", "8.8.8.8", LogSourceType.NETFLOW)
        old_log.received_at = datetime.now(timezone.utc) - timedelta(hours=2)
        tmp_db.save_normalized_log(old_log)

        since = datetime.now(timezone.utc) - timedelta(minutes=5)
        rows = tmp_db.get_host_traffic_rows("10.0.0.9", since)
        assert rows == []


class TestAgentTrafficEndpoint:
    def _register_and_get_key(self, agent_id):
        payload = {
            "agent_id": agent_id, "hostname": "test-host",
            "os_name": "Linux", "os_version": "6.8.0", "python_version": "3.12.3",
        }
        client.post("/api/v1/agents/register", json=payload)
        key = register_agent_key(agent_id)
        return key

    def test_unknown_agent_returns_404(self, tmp_db):
        resp = client.get("/api/v1/agents/never-seen/traffic")
        assert resp.status_code == 404

    def test_known_agent_without_ip_returns_404(self, tmp_db):
        """register hiç çağrılmadan storage'da kayıt yoksa IP de bilinmez."""
        resp = client.get("/api/v1/agents/no-ip-agent/traffic")
        assert resp.status_code == 404

    def test_registered_agent_with_traffic_returns_summary(self, tmp_db):
        agent_id = "agent-traffic-e2e"
        self._register_and_get_key(agent_id)
        # TestClient'ın request.client.host değeri "testclient" sabiti
        tmp_db.save_normalized_log(
            _norm_log("testclient", "8.8.8.8", LogSourceType.NETFLOW, network_bytes=5000)
        )

        resp = client.get(f"/api/v1/agents/{agent_id}/traffic")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_bytes"] == 5000
        assert data["interface"] == "Zeek + NetFlow"

    def test_registered_agent_without_traffic_returns_empty_summary(self, tmp_db):
        agent_id = "agent-traffic-empty"
        self._register_and_get_key(agent_id)
        resp = client.get(f"/api/v1/agents/{agent_id}/traffic")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_bytes"] == 0
        assert data["total_packets"] == 0
