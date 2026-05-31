"""
B1/B2/B3 için agent güvenlik olayı testleri.

POST /api/v1/agents/security-events → normalized_logs'a yazılmalı (B1)
GET  /api/v1/agents                 → rate limit korumalı (B2)
GET  /api/v1/agents/{id}/latest     → rate limit korumalı (B2)
Kill chain dispatch hatası → sessiz değil, loglanmalı (B3)
"""

import uuid
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from server.main import app
from server.auth import register_agent_key

client = TestClient(app)

AGENT_ID = "test-agent-b1"


@pytest.fixture
def agent_key(tmp_db):
    """Her test için temiz agent API anahtarı oluştur."""
    key = register_agent_key(AGENT_ID)
    assert key is not None
    return key


@pytest.fixture
def agent_headers(agent_key):
    return {"X-API-Key": agent_key}


def _post_event(agent_headers, event_action, severity="warning", source_ip="10.0.0.5"):
    return client.post(
        "/api/v1/agents/security-events",
        json={
            "hostname": "test-host",
            "events": [
                {
                    "event_action": event_action,
                    "severity": severity,
                    "source_ip": source_ip,
                    "message": f"Test event: {event_action}",
                    "occurred_at": datetime.now(timezone.utc).isoformat(),
                }
            ],
        },
        headers=agent_headers,
    )


class TestB1NormalizedLogPipeline:
    def test_ssh_failure_appears_in_normalized_logs(self, tmp_db, agent_headers):
        resp = _post_event(agent_headers, "ssh_failure")
        assert resp.status_code == 202
        assert resp.json()["saved"] == 1

        with tmp_db._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM normalized_logs WHERE event_action = %s",
                ("ssh_failure",),
            ).fetchall()
        assert len(rows) == 1
        assert rows[0]["source_type"] == "auth_log"
        assert rows[0]["event_category"] == "authentication"

    def test_brute_force_source_type_auth_log(self, tmp_db, agent_headers):
        _post_event(agent_headers, "brute_force")
        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT source_type, event_category FROM normalized_logs WHERE event_action = %s",
                ("brute_force",),
            ).fetchone()
        assert row["source_type"] == "auth_log"
        assert row["event_category"] == "authentication"

    def test_windows_logon_failure_source_type_windows(self, tmp_db, agent_headers):
        _post_event(agent_headers, "windows_logon_failure")
        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT source_type, event_category FROM normalized_logs WHERE event_action = %s",
                ("windows_logon_failure",),
            ).fetchone()
        assert row["source_type"] == "windows"
        assert row["event_category"] == "authentication"

    def test_windows_sysmon_process_category_system(self, tmp_db, agent_headers):
        _post_event(agent_headers, "windows_sysmon_process")
        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT source_type, event_category FROM normalized_logs WHERE event_action = %s",
                ("windows_sysmon_process",),
            ).fetchone()
        assert row["source_type"] == "windows"
        assert row["event_category"] == "system"

    def test_port_scan_category_intrusion(self, tmp_db, agent_headers):
        _post_event(agent_headers, "port_scan_attempt")
        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT source_type, event_category FROM normalized_logs WHERE event_action = %s",
                ("port_scan_attempt",),
            ).fetchone()
        assert row["source_type"] == "netguard"
        assert row["event_category"] == "intrusion"

    def test_arp_spoof_category_intrusion(self, tmp_db, agent_headers):
        _post_event(agent_headers, "arp_spoof")
        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT source_type, event_category FROM normalized_logs WHERE event_action = %s",
                ("arp_spoof",),
            ).fetchone()
        assert row["source_type"] == "netguard"
        assert row["event_category"] == "intrusion"

    def test_device_down_category_system(self, tmp_db, agent_headers):
        _post_event(agent_headers, "device_down")
        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT source_type, event_category FROM normalized_logs WHERE event_action = %s",
                ("device_down",),
            ).fetchone()
        assert row["source_type"] == "netguard"
        assert row["event_category"] == "system"

    def test_normalized_log_fields_populated(self, tmp_db, agent_headers):
        _post_event(agent_headers, "ssh_failure", source_ip="192.168.1.10")
        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT * FROM normalized_logs WHERE event_action = %s AND source_ip = %s",
                ("ssh_failure", "192.168.1.10"),
            ).fetchone()
        assert row is not None
        assert row["observer_hostname"] == "test-host"
        assert row["source_ip"] == "192.168.1.10"
        assert row["severity"] == "warning"
        assert row["message"] == "Test event: ssh_failure"

    def test_event_also_saved_to_security_events(self, tmp_db, agent_headers):
        _post_event(agent_headers, "brute_force")
        with tmp_db._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) AS c FROM security_events WHERE event_action = %s",
                ("brute_force",),
            ).fetchone()["c"]
        assert count == 1

    def test_batch_multiple_events(self, tmp_db, agent_headers):
        resp = client.post(
            "/api/v1/agents/security-events",
            json={
                "hostname": "batch-host",
                "events": [
                    {
                        "event_action": "ssh_failure",
                        "severity": "warning",
                        "message": "fail 1",
                        "occurred_at": datetime.now(timezone.utc).isoformat(),
                    },
                    {
                        "event_action": "sudo_usage",
                        "severity": "info",
                        "message": "sudo 1",
                        "occurred_at": datetime.now(timezone.utc).isoformat(),
                    },
                ],
            },
            headers=agent_headers,
        )
        assert resp.status_code == 202
        assert resp.json()["saved"] == 2

        with tmp_db._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) AS c FROM normalized_logs WHERE observer_hostname = %s",
                ("batch-host",),
            ).fetchone()["c"]
        assert count == 2

    def test_unauthenticated_returns_401(self):
        resp = client.post(
            "/api/v1/agents/security-events",
            json={"hostname": "h", "events": []},
        )
        assert resp.status_code == 401

    def test_invalid_event_action_returns_saved_zero(self, tmp_db, agent_headers):
        resp = client.post(
            "/api/v1/agents/security-events",
            json={
                "hostname": "test-host",
                "events": [
                    {
                        "event_action": "nonexistent_action",
                        "severity": "warning",
                        "message": "bad event",
                        "occurred_at": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            },
            headers=agent_headers,
        )
        assert resp.status_code == 202
        assert resp.json()["saved"] == 0

    def test_dns_anomaly_category_network(self, tmp_db, agent_headers):
        _post_event(agent_headers, "dns_anomaly")
        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT source_type, event_category FROM normalized_logs WHERE event_action = %s",
                ("dns_anomaly",),
            ).fetchone()
        assert row["source_type"] == "netguard"
        assert row["event_category"] == "network"

    def test_lateral_movement_category_intrusion(self, tmp_db, agent_headers):
        _post_event(agent_headers, "lateral_movement")
        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT source_type, event_category FROM normalized_logs WHERE event_action = %s",
                ("lateral_movement",),
            ).fetchone()
        assert row["source_type"] == "netguard"
        assert row["event_category"] == "intrusion"

    def test_windows_kerberos_tgt_category_authentication(self, tmp_db, agent_headers):
        _post_event(agent_headers, "windows_kerberos_tgt")
        with tmp_db._connect() as conn:
            row = conn.execute(
                "SELECT source_type, event_category FROM normalized_logs WHERE event_action = %s",
                ("windows_kerberos_tgt",),
            ).fetchone()
        assert row["source_type"] == "windows"
        assert row["event_category"] == "authentication"


class TestB2RateLimiting:
    def test_get_agents_requires_no_auth_but_is_rate_limited(self, tmp_db):
        resp = client.get("/api/v1/agents")
        assert resp.status_code == 200

    def test_get_agents_latest_404_for_unknown(self, tmp_db):
        resp = client.get("/api/v1/agents/nonexistent-agent/latest")
        assert resp.status_code == 404


class TestB3KillChainErrorLogged:
    def test_kill_chain_error_does_not_suppress_save(self, tmp_db, agent_headers, monkeypatch):
        """Kill chain dispatch hatası olsa bile normalized_log kaydı tamamlanmalı."""
        def _broken_record(*args, **kwargs):
            raise RuntimeError("Kill chain simulated failure")

        from server import attack_chain as ac_module
        monkeypatch.setattr(ac_module.attack_chain_tracker, "record", _broken_record)

        resp = _post_event(agent_headers, "ssh_failure", source_ip="10.1.2.3")
        assert resp.status_code == 202
        assert resp.json()["saved"] == 1

        with tmp_db._connect() as conn:
            count = conn.execute(
                "SELECT COUNT(*) AS c FROM normalized_logs WHERE source_ip = %s",
                ("10.1.2.3",),
            ).fetchone()["c"]
        assert count == 1

    def test_kill_chain_error_is_logged(self, tmp_db, agent_headers, monkeypatch, caplog):
        """B3: kill chain hatası logger.warning ile raporlanmalı."""
        import logging

        def _broken_record(*args, **kwargs):
            raise RuntimeError("dispatch error for test")

        from server import attack_chain as ac_module
        monkeypatch.setattr(ac_module.attack_chain_tracker, "record", _broken_record)

        with caplog.at_level(logging.WARNING, logger="server.routes.agents"):
            _post_event(agent_headers, "ssh_failure", source_ip="10.5.5.5")

        assert any("Kill chain dispatch" in r.message for r in caplog.records)
