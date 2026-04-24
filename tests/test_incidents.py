"""Incident yönetimi testleri."""

import pytest
from fastapi.testclient import TestClient
from server.main import app
from server.auth import create_access_token

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
