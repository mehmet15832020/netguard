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
        r2 = client.patch(f"/api/v1/incidents/{inc_id}",
                          json={"status": "resolved", "closure_note": "Sorun çözüldü"}, headers=_auth())
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

    # --- FSM geçiş doğrulaması ---

    def test_fsm_open_to_investigating(self, tmp_db):
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "info"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        r2 = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "investigating"}, headers=_auth())
        assert r2.status_code == 200
        assert r2.json()["status"] == "investigating"

    def test_fsm_investigating_to_resolved(self, tmp_db):
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "info"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "investigating"}, headers=_auth())
        r2 = client.patch(f"/api/v1/incidents/{inc_id}",
                          json={"status": "resolved", "closure_note": "İnceleme tamamlandı"}, headers=_auth())
        assert r2.status_code == 200
        assert r2.json()["status"] == "resolved"

    def test_fsm_resolved_to_open_allowed(self, tmp_db):
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "info"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        client.patch(f"/api/v1/incidents/{inc_id}",
                     json={"status": "resolved", "closure_note": "Çözüldü"}, headers=_auth())
        r2 = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "open"}, headers=_auth())
        assert r2.status_code == 200
        assert r2.json()["status"] == "open"

    def test_fsm_resolved_to_investigating_rejected(self, tmp_db):
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "info"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        client.patch(f"/api/v1/incidents/{inc_id}",
                     json={"status": "resolved", "closure_note": "Çözüldü"}, headers=_auth())
        r2 = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "investigating"}, headers=_auth())
        assert r2.status_code == 400
        assert "Geçersiz geçiş" in r2.json()["detail"]

    def test_fsm_open_to_open_rejected(self, tmp_db):
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "info"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        r2 = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "open"}, headers=_auth())
        assert r2.status_code == 400

    # --- V1-4: closure_note zorunluluğu ---

    def test_resolve_without_closure_note_rejected(self, tmp_db):
        """closure_note olmadan resolved geçişi 422 döner."""
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "warning"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        r2 = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "resolved"}, headers=_auth())
        assert r2.status_code == 422
        assert "closure_note" in r2.json()["detail"].lower() or "kapatma" in r2.json()["detail"].lower()

    def test_resolve_with_empty_closure_note_rejected(self, tmp_db):
        """Boş closure_note da reddedilmeli."""
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "warning"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        r2 = client.patch(f"/api/v1/incidents/{inc_id}",
                          json={"status": "resolved", "closure_note": "   "}, headers=_auth())
        assert r2.status_code == 422

    def test_resolve_with_closure_note_succeeds(self, tmp_db):
        """Geçerli closure_note ile resolved geçişi 200 döner."""
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "warning"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        r2 = client.patch(f"/api/v1/incidents/{inc_id}",
                          json={"status": "resolved", "closure_note": "False positive. Whitelist'e alındı."}, headers=_auth())
        assert r2.status_code == 200
        assert r2.json()["status"] == "resolved"

    def test_closure_note_persisted(self, tmp_db):
        """closure_note DB'ye kaydediliyor mu?"""
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "info"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        note = "Zararlı değil, yetkili tarama."
        client.patch(f"/api/v1/incidents/{inc_id}",
                     json={"status": "resolved", "closure_note": note}, headers=_auth())
        detail = client.get(f"/api/v1/incidents/{inc_id}", headers=_auth())
        assert detail.json()["closure_note"] == note

    # --- V1-4: acknowledged_at ---

    def test_acknowledged_at_set_on_investigating(self, tmp_db):
        """open → investigating geçişinde acknowledged_at set edilmeli."""
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "warning"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        assert r.json()["acknowledged_at"] is None
        r2 = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "investigating"}, headers=_auth())
        assert r2.status_code == 200
        assert r2.json()["acknowledged_at"] is not None

    def test_acknowledged_at_not_overwritten_on_second_transition(self, tmp_db):
        """İnceleme → açık → inceleme döngüsünde acknowledged_at ilk değerini korumalı."""
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "warning"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        r2 = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "investigating"}, headers=_auth())
        first_ack = r2.json()["acknowledged_at"]
        client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "open"}, headers=_auth())
        r3 = client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "investigating"}, headers=_auth())
        assert r3.json()["acknowledged_at"] == first_ack

    # --- V1-4: priority_score ---

    def test_priority_score_default_zero(self, tmp_db):
        """Manuel oluşturulan incident'ın priority_score'u 0."""
        r = client.post("/api/v1/incidents", json={"title": "Inc", "severity": "critical"}, headers=_auth())
        assert r.json()["priority_score"] == 0

    def test_priority_score_in_list_response(self, tmp_db):
        """Liste endpoint'i priority_score alanını döner."""
        client.post("/api/v1/incidents", json={"title": "Inc", "severity": "warning"}, headers=_auth())
        r = client.get("/api/v1/incidents", headers=_auth())
        for inc in r.json()["incidents"]:
            assert "priority_score" in inc


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
        client.patch(f"/api/v1/incidents/{inc_id}",
                     json={"status": "resolved", "closure_note": "Çözüldü"}, headers=_auth())

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
            event_action="ssh_brute_force",
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

    # --- V1-4 entegrasyon: correlator → priority_score ---

    def test_priority_score_set_on_auto_create(self, tmp_db):
        """Correlator otomatik incident oluştururken priority_score > 0 olmalı."""
        from server.database import db as _db
        from server.correlator import correlator
        event = self._make_corr_event(severity="critical")
        correlator._create_incident_from_corr(event)
        incidents = _db.get_incidents()
        assert incidents[0]["priority_score"] > 0

    def test_priority_score_critical_higher_than_warning(self, tmp_db):
        """critical incident'ın öncelik skoru warning'den yüksek olmalı."""
        from server.database import db as _db
        from server.correlator import correlator
        correlator._create_incident_from_corr(self._make_corr_event(group_value="1.1.1.1", severity="critical"))
        correlator._create_incident_from_corr(self._make_corr_event(group_value="2.2.2.2", severity="warning"))
        incidents = {i["group_value"]: i for i in _db.get_incidents()}
        assert incidents["1.1.1.1"]["priority_score"] > incidents["2.2.2.2"]["priority_score"]


class TestIncidentLifecycleIntegration:
    """
    Uçtan uca incident yaşam döngüsü testleri.
    create → investigate → resolve zincirini ve V1-4 alanlarını doğrular.
    """

    def test_full_lifecycle_open_investigate_resolve(self, tmp_db):
        """Tam yaşam döngüsü: oluştur → araştır → kapat."""
        r = client.post("/api/v1/incidents",
                        json={"title": "Test Incident", "severity": "warning"},
                        headers=_auth())
        assert r.status_code == 201
        inc_id = r.json()["incident_id"]
        assert r.json()["acknowledged_at"] is None
        assert r.json()["closure_note"] == ""

        # Araştırmaya al → acknowledged_at set edilmeli
        r2 = client.patch(f"/api/v1/incidents/{inc_id}",
                          json={"status": "investigating"}, headers=_auth())
        assert r2.status_code == 200
        ack_time = r2.json()["acknowledged_at"]
        assert ack_time is not None

        # Kapatma notu olmadan resolve → reddedilmeli
        r3 = client.patch(f"/api/v1/incidents/{inc_id}",
                          json={"status": "resolved"}, headers=_auth())
        assert r3.status_code == 422

        # Kapatma notuyla resolve → başarılı
        note = "Yetkili port taraması. IT onayladı."
        r4 = client.patch(f"/api/v1/incidents/{inc_id}",
                          json={"status": "resolved", "closure_note": note},
                          headers=_auth())
        assert r4.status_code == 200
        body = r4.json()
        assert body["status"] == "resolved"
        assert body["resolved_at"] is not None
        assert body["acknowledged_at"] == ack_time  # ilk değer korunmalı
        assert body["closure_note"] == note

    def test_full_lifecycle_fields_via_get(self, tmp_db):
        """GET endpoint'i tüm V1-4 alanlarını döner."""
        r = client.post("/api/v1/incidents",
                        json={"title": "Enriched Inc", "severity": "critical"},
                        headers=_auth())
        inc_id = r.json()["incident_id"]
        client.patch(f"/api/v1/incidents/{inc_id}",
                     json={"status": "investigating"}, headers=_auth())
        client.patch(f"/api/v1/incidents/{inc_id}",
                     json={"status": "resolved", "closure_note": "Root cause: misconfiguration."},
                     headers=_auth())

        detail = client.get(f"/api/v1/incidents/{inc_id}", headers=_auth())
        assert detail.status_code == 200
        body = detail.json()
        assert "priority_score" in body
        assert "closure_note" in body
        assert "acknowledged_at" in body
        assert body["closure_note"] == "Root cause: misconfiguration."
        assert body["resolved_at"] is not None
        assert body["acknowledged_at"] is not None

    def test_resolve_then_reopen_closure_note_preserved(self, tmp_db):
        """Çözüldü → tekrar açıldığında closure_note silinmemeli."""
        r = client.post("/api/v1/incidents",
                        json={"title": "Inc", "severity": "info"}, headers=_auth())
        inc_id = r.json()["incident_id"]
        note = "False positive."
        client.patch(f"/api/v1/incidents/{inc_id}",
                     json={"status": "resolved", "closure_note": note}, headers=_auth())
        client.patch(f"/api/v1/incidents/{inc_id}", json={"status": "open"}, headers=_auth())
        detail = client.get(f"/api/v1/incidents/{inc_id}", headers=_auth())
        assert detail.json()["closure_note"] == note
