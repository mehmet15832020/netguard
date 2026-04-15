"""
Security endpoint testleri.

GET  /api/v1/security/events
GET  /api/v1/security/events/summary
POST /api/v1/security/scan
"""

import pytest
from fastapi.testclient import TestClient
from server.main import app

client = TestClient(app)


@pytest.fixture
def auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


class TestSecurityEventsEndpoint:
    def test_unauthenticated_returns_401(self):
        assert client.get("/api/v1/security/events").status_code == 401

    def test_list_events_returns_list(self, auth):
        resp = client.get("/api/v1/security/events", headers=auth)
        assert resp.status_code == 200
        data = resp.json()
        assert "events" in data
        assert "count" in data
        assert isinstance(data["count"], int)
        assert isinstance(data["events"], list)

    def test_limit_too_small_returns_400(self, auth):
        resp = client.get("/api/v1/security/events?limit=0", headers=auth)
        assert resp.status_code == 400

    def test_limit_too_large_returns_400(self, auth):
        resp = client.get("/api/v1/security/events?limit=501", headers=auth)
        assert resp.status_code == 400

    def test_limit_valid(self, auth):
        resp = client.get("/api/v1/security/events?limit=50", headers=auth)
        assert resp.status_code == 200

    def test_filter_by_event_type(self, auth):
        resp = client.get("/api/v1/security/events?event_type=ssh_failure", headers=auth)
        assert resp.status_code == 200
        # Dönen tüm event'lar doğru tipte olmalı
        for ev in resp.json()["events"]:
            assert ev["event_type"] == "ssh_failure"

    def test_filter_by_source_ip(self, auth):
        resp = client.get("/api/v1/security/events?source_ip=1.2.3.4", headers=auth)
        assert resp.status_code == 200
        for ev in resp.json()["events"]:
            assert ev["source_ip"] == "1.2.3.4"


class TestSecuritySummaryEndpoint:
    def test_unauthenticated_returns_401(self):
        assert client.get("/api/v1/security/events/summary").status_code == 401

    def test_summary_returns_all_event_types(self, auth):
        from shared.models import SecurityEventType
        resp = client.get("/api/v1/security/events/summary", headers=auth)
        assert resp.status_code == 200
        data = resp.json()
        assert "summary" in data
        for et in SecurityEventType:
            assert et.value in data["summary"]
            assert isinstance(data["summary"][et.value], int)
            assert data["summary"][et.value] >= 0

    def test_summary_values_are_non_negative(self, auth):
        resp = client.get("/api/v1/security/events/summary", headers=auth)
        for count in resp.json()["summary"].values():
            assert count >= 0


class TestSecurityScanEndpoint:
    def test_unauthenticated_returns_401(self):
        assert client.post("/api/v1/security/scan").status_code == 401

    def test_scan_returns_correct_structure(self, auth):
        resp = client.post("/api/v1/security/scan", headers=auth)
        assert resp.status_code == 200
        data = resp.json()
        assert data["scanned"] is True
        assert "agent_id" in data
        assert "events_found" in data

    def test_scan_events_found_has_correct_keys(self, auth):
        resp = client.post("/api/v1/security/scan", headers=auth)
        ef = resp.json()["events_found"]
        assert "auth_log" in ef
        assert "port_changes" in ef
        assert "config_changes" in ef
        assert "total" in ef

    def test_scan_total_equals_sum(self, auth):
        resp = client.post("/api/v1/security/scan", headers=auth)
        ef = resp.json()["events_found"]
        assert ef["total"] == ef["auth_log"] + ef["port_changes"] + ef["config_changes"]

    def test_scan_with_custom_agent_id(self, auth):
        resp = client.post("/api/v1/security/scan?agent_id=test-agent-007", headers=auth)
        assert resp.status_code == 200
        assert resp.json()["agent_id"] == "test-agent-007"
