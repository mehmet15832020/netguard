"""
Incident zenginleştirme testleri.

Pozitif: MITRE, related_logs, threat_intel doğru doldurulur.
Negatif: Eksik veri → enrichment boş/None döner, hata fırlatmaz.
"""

import uuid
from datetime import datetime, timezone

import pytest

from server.database import DatabaseManager
from server.incident_enricher import enrich_incident
from shared.models import (
    CorrelatedEvent,
    LogCategory,
    LogSourceType,
    NormalizedLog,
)


def _make_normalized_log(source_ip: str = "1.2.3.4", event_action: str = "port_scan_attempt") -> NormalizedLog:
    return NormalizedLog(
        log_id      = str(uuid.uuid4()),
        raw_id      = str(uuid.uuid4()),
        source_type = LogSourceType.NETGUARD,
        observer_hostname = "test-host",
        timestamp   = datetime.now(timezone.utc),
        severity    = "warning",
        event_category    = LogCategory.INTRUSION,
        event_action  = event_action,
        source_ip      = source_ip,
        message     = f"Test event from {source_ip}",
    )


def _make_correlated_event(
    rule_id: str = "port_scan_detected",
    group_value: str = "1.2.3.4",
    mitre_techniques: list[str] | None = None,
    mitre_tactics: list[str] | None = None,
) -> CorrelatedEvent:
    now = datetime.now(timezone.utc)
    return CorrelatedEvent(
        corr_id         = str(uuid.uuid4()),
        rule_id         = rule_id,
        rule_name       = "Port Scan Detected",
        event_action      = "port_scan_detected",
        severity        = "warning",
        group_value     = group_value,
        matched_count   = 5,
        window_seconds  = 60,
        first_seen      = now,
        last_seen       = now,
        message         = "Port scan from 1.2.3.4",
        mitre_techniques = mitre_techniques or ["T1046"],
        mitre_tactics    = mitre_tactics or ["discovery"],
    )


class TestEnrichIncidentBasic:
    def test_empty_incident_returns_empty_enrichment(self, tmp_db):
        result = enrich_incident({"incident_id": "x", "title": "T", "source_event_id": None, "group_value": None, "created_at": None})
        assert "enrichment" in result
        assert result["enrichment"]["mitre_techniques"] == []
        assert result["enrichment"]["mitre_tactics"] == []
        assert result["enrichment"]["related_logs"] == []
        assert result["enrichment"]["threat_intel"] is None

    def test_original_dict_not_mutated(self, tmp_db):
        original = {"incident_id": "x", "title": "T", "source_event_id": None, "group_value": None, "created_at": None}
        enrich_incident(original)
        assert "enrichment" not in original

    def test_existing_fields_preserved(self, tmp_db):
        inc = {"incident_id": "abc", "title": "Test", "severity": "critical",
               "source_event_id": None, "group_value": None, "created_at": None}
        result = enrich_incident(inc)
        assert result["incident_id"] == "abc"
        assert result["title"] == "Test"
        assert result["severity"] == "critical"


class TestEnrichMitre:
    def test_mitre_filled_from_correlated_event(self, tmp_db, monkeypatch):
        ce = _make_correlated_event(mitre_techniques=["T1046"], mitre_tactics=["discovery"])
        tmp_db.save_correlated_event(ce)

        result = enrich_incident({
            "source_event_id": ce.corr_id,
            "group_value": None,
            "created_at": None,
        })
        assert result["enrichment"]["mitre_techniques"] == ["T1046"]
        assert result["enrichment"]["mitre_tactics"] == ["discovery"]

    def test_no_mitre_when_source_event_missing(self, tmp_db):
        result = enrich_incident({
            "source_event_id": "nonexistent-corr-id",
            "group_value": None,
            "created_at": None,
        })
        assert result["enrichment"]["mitre_techniques"] == []
        assert result["enrichment"]["mitre_tactics"] == []

    def test_multiple_mitre_techniques(self, tmp_db):
        ce = _make_correlated_event(
            mitre_techniques=["T1046", "T1110.001"],
            mitre_tactics=["discovery", "credential_access"],
        )
        tmp_db.save_correlated_event(ce)
        result = enrich_incident({
            "source_event_id": ce.corr_id,
            "group_value": None,
            "created_at": None,
        })
        assert "T1046" in result["enrichment"]["mitre_techniques"]
        assert "T1110.001" in result["enrichment"]["mitre_techniques"]


class TestEnrichRelatedLogs:
    def test_related_logs_fetched_for_group_value(self, tmp_db):
        log = _make_normalized_log(source_ip="1.2.3.4")
        tmp_db.save_normalized_log(log)

        now_iso = datetime.now(timezone.utc).isoformat()
        result = enrich_incident({
            "source_event_id": None,
            "group_value": "1.2.3.4",
            "created_at": now_iso,
        })
        logs = result["enrichment"]["related_logs"]
        assert len(logs) == 1
        assert logs[0]["source_ip"] == "1.2.3.4"
        assert logs[0]["event_action"] == "port_scan_attempt"

    def test_no_related_logs_for_different_ip(self, tmp_db):
        log = _make_normalized_log(source_ip="5.6.7.8")
        tmp_db.save_normalized_log(log)

        now_iso = datetime.now(timezone.utc).isoformat()
        result = enrich_incident({
            "source_event_id": None,
            "group_value": "1.2.3.4",
            "created_at": now_iso,
        })
        assert result["enrichment"]["related_logs"] == []

    def test_message_truncated_to_200_chars(self, tmp_db):
        log = NormalizedLog(
            log_id      = str(uuid.uuid4()),
            raw_id      = str(uuid.uuid4()),
            source_type = LogSourceType.NETGUARD,
            observer_hostname = "host",
            timestamp   = datetime.now(timezone.utc),
            severity    = "info",
            event_category    = LogCategory.NETWORK,
            event_action  = "test_event",
            source_ip      = "1.2.3.4",
            message     = "A" * 300,
        )
        tmp_db.save_normalized_log(log)

        now_iso = datetime.now(timezone.utc).isoformat()
        result = enrich_incident({
            "source_event_id": None,
            "group_value": "1.2.3.4",
            "created_at": now_iso,
        })
        assert len(result["enrichment"]["related_logs"][0]["message"]) <= 200

    def test_no_logs_when_group_value_missing(self, tmp_db):
        log = _make_normalized_log(source_ip="1.2.3.4")
        tmp_db.save_normalized_log(log)

        result = enrich_incident({
            "source_event_id": None,
            "group_value": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        assert result["enrichment"]["related_logs"] == []


class TestEnrichThreatIntel:
    def test_threat_intel_returned_when_cached(self, tmp_db, monkeypatch):
        import server.incident_enricher as module
        monkeypatch.setattr(
            module.threat_intel,
            "lookup",
            lambda ip: {"score": 85, "total_reports": 12, "country_code": "CN", "isp": "Test ISP"},
        )
        result = enrich_incident({
            "source_event_id": None,
            "group_value": "1.2.3.4",
            "created_at": None,
        })
        ti = result["enrichment"]["threat_intel"]
        assert ti is not None
        assert ti["score"] == 85
        assert ti["country_code"] == "CN"

    def test_threat_intel_none_when_no_data(self, tmp_db, monkeypatch):
        import server.incident_enricher as module
        monkeypatch.setattr(module.threat_intel, "lookup", lambda ip: None)
        result = enrich_incident({
            "source_event_id": None,
            "group_value": "1.2.3.4",
            "created_at": None,
        })
        assert result["enrichment"]["threat_intel"] is None

    def test_threat_intel_none_when_group_value_missing(self, tmp_db, monkeypatch):
        import server.incident_enricher as module
        calls = []
        monkeypatch.setattr(module.threat_intel, "lookup", lambda ip: calls.append(ip) or {"score": 50})
        enrich_incident({
            "source_event_id": None,
            "group_value": None,
            "created_at": None,
        })
        assert calls == []


class TestGetIncidentAPIEnriched:
    """GET /incidents/{id} endpoint'inin enrichment döndürdüğünü doğrular."""

    def test_get_incident_has_enrichment_key(self, tmp_db):
        from fastapi.testclient import TestClient
        from server.main import app
        from server.auth import create_access_token

        client = TestClient(app)
        token = create_access_token(username="admin", role="admin")
        headers = {"Authorization": f"Bearer {token}"}

        r = client.post("/api/v1/incidents", json={
            "title": "Enrichment Test",
            "severity": "warning",
        }, headers=headers)
        assert r.status_code == 201
        inc_id = r.json()["incident_id"]

        r2 = client.get(f"/api/v1/incidents/{inc_id}", headers=headers)
        assert r2.status_code == 200
        data = r2.json()
        assert "enrichment" in data
        assert "mitre_techniques" in data["enrichment"]
        assert "mitre_tactics" in data["enrichment"]
        assert "related_logs" in data["enrichment"]
        assert "threat_intel" in data["enrichment"]

    def test_get_incident_enrichment_populated_with_correlated_event(self, tmp_db):
        from fastapi.testclient import TestClient
        from server.main import app
        from server.auth import create_access_token

        ce = _make_correlated_event(mitre_techniques=["T1595"], mitre_tactics=["reconnaissance"])
        tmp_db.save_correlated_event(ce)

        client = TestClient(app)
        token = create_access_token(username="admin", role="admin")
        headers = {"Authorization": f"Bearer {token}"}

        r = client.post("/api/v1/incidents", json={
            "title": "MITRE Enrichment Test",
            "severity": "critical",
            "source_event_id": ce.corr_id,
            "group_value": "1.2.3.4",
        }, headers=headers)
        inc_id = r.json()["incident_id"]

        r2 = client.get(f"/api/v1/incidents/{inc_id}", headers=headers)
        data = r2.json()
        assert data["enrichment"]["mitre_techniques"] == ["T1595"]
        assert data["enrichment"]["mitre_tactics"] == ["reconnaissance"]
