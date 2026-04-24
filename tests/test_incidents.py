"""Incident yönetimi testleri."""

import uuid
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from server.main import app
from server.auth import create_access_token
from shared.models import Incident, IncidentStatus, CorrelatedEvent

client = TestClient(app)


def _auth() -> dict:
    token = create_access_token(username="admin", role="admin")
    return {"Authorization": f"Bearer {token}"}


def _viewer_auth() -> dict:
    token = create_access_token(username="viewer", role="viewer")
    return {"Authorization": f"Bearer {token}"}


class TestCreateIncident:
    def test_create_basic(self, tmp_db):
        r = client.post("/api/v1/incidents", json={
            "title": "SSH Brute Force Tespit Edildi",
            "severity": "critical",
        }, headers=_auth())
        assert r.status_code == 201
        data = r.json()
        assert data["title"] == "SSH Brute Force Tespit Edildi"
        assert data["status"] == "open"
        assert data["severity"] == "critical"
        assert data["created_by"] == "admin"

    def test_create_with_all_fields(self, tmp_db):
        r = client.post("/api/v1/incidents", json={
            "title": "Port Scan",
            "description": "10.0.0.5 IP'sinden port tarama",
            "severity": "warning",
            "assigned_to": "analyst1",
            "notes": "İncelenecek",
        }, headers=_auth())
        assert r.status_code == 201
        data = r.json()
        assert data["assigned_to"] == "analyst1"
        assert data["description"] == "10.0.0.5 IP'sinden port tarama"

    def test_invalid_severity_rejected(self, tmp_db):
        r = client.post("/api/v1/incidents", json={
            "title": "Test", "severity": "extreme",
        }, headers=_auth())
        assert r.status_code == 400

    def test_unauthenticated_rejected(self, tmp_db):
        r = client.post("/api/v1/incidents", json={"title": "Test", "severity": "info"})
        assert r.status_code == 401


class TestListIncidents:
    def test_list_empty(self, tmp_db):
        r = client.get("/api/v1/incidents", headers=_auth())
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_list_after_create(self, tmp_db):
        client.post("/api/v1/incidents", json={"title": "Inc1", "severity": "info"}, headers=_auth())
        client.post("/api/v1/incidents", json={"title": "Inc2", "severity": "critical"}, headers=_auth())
        r = client.get("/api/v1/incidents", headers=_auth())
        assert r.json()["count"] == 2

    def test_filter_by_status(self, tmp_db):
        client.post("/api/v1/incidents", json={"title": "A", "severity": "info"}, headers=_auth())
        r = client.get("/api/v1/incidents?status=open", headers=_auth())
        assert r.json()["count"] == 1

    def test_filter_by_severity(self, tmp_db):
        client.post("/api/v1/incidents", json={"title": "A", "severity": "critical"}, headers=_auth())
        client.post("/api/v1/incidents", json={"title": "B", "severity": "info"}, headers=_auth())
        r = client.get("/api/v1/incidents?severity=critical", headers=_auth())
        assert r.json()["count"] == 1


class TestGetIncident:
    def test_get_existing(self, tmp_db):
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "warning"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        r2 = client.get(f"/api/v1/incidents/{inc_id}", headers=_auth())
        assert r2.status_code == 200
        assert r2.json()["incident_id"] == inc_id

    def test_get_nonexistent_returns_404(self, tmp_db):
        r = client.get("/api/v1/incidents/nonexistent-id", headers=_auth())
        assert r.status_code == 404


class TestUpdateIncident:
    def test_update_status_to_investigating(self, tmp_db):
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "warning"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        r2 = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "investigating"}, headers=_auth())
        assert r2.status_code == 200
        assert r2.json()["status"] == "investigating"

    def test_update_status_to_resolved(self, tmp_db):
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "info"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        r2 = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "resolved"}, headers=_auth())
        assert r2.status_code == 200
        assert r2.json()["status"] == "resolved"
        assert r2.json()["resolved_at"] is not None

    def test_assign_to_user(self, tmp_db):
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "info"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        r2 = client.patch(f"/api/v1/incidents/{inc_id}", json={"assigned_to": "analyst2"}, headers=_auth())
        assert r2.json()["assigned_to"] == "analyst2"

    def test_add_notes(self, tmp_db):
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "info"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        r2 = client.patch(f"/api/v1/incidents/{inc_id}", json={"notes": "Araştırma devam ediyor"}, headers=_auth())
        assert r2.json()["notes"] == "Araştırma devam ediyor"

    def test_invalid_status_rejected(self, tmp_db):
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "info"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        r2 = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "invalid"}, headers=_auth())
        assert r2.status_code == 400

    def test_update_nonexistent_returns_404(self, tmp_db):
        r = client.patch("/api/v1/incidents/nonexistent", json={"status": "resolved"}, headers=_auth())
        assert r.status_code == 404


class TestDeleteIncident:
    def test_admin_can_delete(self, tmp_db):
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "info"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        r2 = client.delete(f"/api/v1/incidents/{inc_id}", headers=_auth())
        assert r2.status_code == 204
        r3 = client.get(f"/api/v1/incidents/{inc_id}", headers=_auth())
        assert r3.status_code == 404

    def test_viewer_cannot_delete(self, tmp_db):
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "info"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        r2 = client.delete(f"/api/v1/incidents/{inc_id}", headers=_viewer_auth())
        assert r2.status_code == 403


class TestSummary:
    def test_summary_counts(self, tmp_db):
        client.post("/api/v1/incidents", json={"title": "A", "severity": "critical"}, headers=_auth())
        client.post("/api/v1/incidents", json={"title": "B", "severity": "warning"}, headers=_auth())
        r_a = client.post("/api/v1/incidents", json={"title": "C", "severity": "info"}, headers=_auth())
        inc_id = r_a.json()["incident_id"]
        client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "resolved"}, headers=_auth())

        r = client.get("/api/v1/incidents/summary", headers=_auth())
        data = r.json()
        assert data["total"] == 3
        assert data["open"] == 2
        assert data["resolved"] == 1


class TestIncidentEvents:
    def test_get_events_empty(self, tmp_db):
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "warning"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        r2 = client.get(f"/api/v1/incidents/{inc_id}/events", headers=_auth())
        assert r2.status_code == 200
        assert r2.json()["count"] == 0

    def test_get_events_nonexistent_returns_404(self, tmp_db):
        r = client.get("/api/v1/incidents/nonexistent/events", headers=_auth())
        assert r.status_code == 404

    def test_add_and_retrieve_event(self, tmp_db):
        from server.database import db as _db
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "warning"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        now = datetime.now(timezone.utc).isoformat()
        _db.add_incident_event(inc_id, "evt-1", "brute_force", "critical", "5 deneme", now)
        r2 = client.get(f"/api/v1/incidents/{inc_id}/events", headers=_auth())
        assert r2.json()["count"] == 1
        assert r2.json()["events"][0]["event_id"] == "evt-1"


class TestAutoIncidentCreation:
    def _make_corr_event(self, rule_id="rule-ssh", group_value="10.0.0.1", severity="warning"):
        now = datetime.now(timezone.utc).isoformat()
        return CorrelatedEvent(
            corr_id=str(uuid.uuid4()),
            event_id=str(uuid.uuid4()),
            rule_id=rule_id,
            rule_name="SSH Brute Force",
            event_type="ssh_brute_force",
            severity=severity,
            group_value=group_value,
            matched_count=5,
            window_seconds=60,
            message=f"{group_value} — 5 başarısız giriş",
            first_seen=now,
            last_seen=now,
        )

    def test_auto_creates_incident(self, tmp_db):
        from server.database import db as _db
        from server.correlator import correlator
        event = self._make_corr_event()
        correlator._create_incident_from_corr(event)
        incidents = _db.get_incidents()
        assert len(incidents) == 1
        assert incidents[0]["rule_id"] == "rule-ssh"
        assert incidents[0]["group_value"] == "10.0.0.1"

    def test_duplicate_merges_into_same_incident(self, tmp_db):
        from server.database import db as _db
        from server.correlator import correlator
        event1 = self._make_corr_event()
        event2 = self._make_corr_event()
        correlator._create_incident_from_corr(event1)
        correlator._create_incident_from_corr(event2)
        incidents = _db.get_incidents()
        assert len(incidents) == 1
        events = _db.get_incident_events(incidents[0]["incident_id"])
        assert len(events) == 2

    def test_severity_escalation(self, tmp_db):
        from server.database import db as _db
        from server.correlator import correlator
        event_warn = self._make_corr_event(severity="warning")
        event_crit = self._make_corr_event(severity="critical")
        correlator._create_incident_from_corr(event_warn)
        correlator._create_incident_from_corr(event_crit)
        incidents = _db.get_incidents()
        assert incidents[0]["severity"] == "critical"

    def test_different_groups_create_separate_incidents(self, tmp_db):
        from server.database import db as _db
        from server.correlator import correlator
        correlator._create_incident_from_corr(self._make_corr_event(group_value="10.0.0.1"))
        correlator._create_incident_from_corr(self._make_corr_event(group_value="10.0.0.2"))
        assert len(_db.get_incidents()) == 2
