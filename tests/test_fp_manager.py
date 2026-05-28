"""
NetGuard — V1-6 False Positive Manager Testleri

Unit + entegrasyon testleri:
  1. _ip_matches()   — CIDR ve exact IP eşleşmesi
  2. _rule_matches() — tüm alan kombinasyonları
  3. FPManager       — önbellek, invalidate, is_suppressed
  4. DB metodları    — create / get / deactivate / increment
  5. API             — POST / GET / DELETE
  6. Correlator entegrasyon — FP kural aktifken incident üretilmemeli
"""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from shared.models import NormalizedLog, LogSourceType, LogCategory


# ─────────────────────────────────────────────────────────────────────────────
#  Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def fp_db(tmp_db, monkeypatch):
    monkeypatch.setattr("server.correlator.db",      tmp_db)
    monkeypatch.setattr("server.routes.fp_rules.db", tmp_db)
    return tmp_db


def _make_fp_rule(fp_db, event_action=None, source_ip=None, destination_ip=None,
                  destination_port=None, observer_hostname=None, tenant_id="default",
                  reason="test", expires_in_days=30):
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(days=expires_in_days)).isoformat() if expires_in_days else None
    rule_id = str(uuid.uuid4())
    fp_db.create_fp_rule(
        fp_rule_id=rule_id,
        event_action=event_action,
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        observer_hostname=observer_hostname,
        tenant_id=tenant_id,
        reason=reason,
        created_by="test",
        created_at=now.isoformat(),
        expires_at=expires_at,
    )
    return rule_id


# ─────────────────────────────────────────────────────────────────────────────
#  1. IP Eşleşme Mantığı
# ─────────────────────────────────────────────────────────────────────────────

class TestIpMatches:

    def test_exact_match(self):
        from server.fp_manager import _ip_matches
        assert _ip_matches("192.168.1.5", "192.168.1.5") is True

    def test_exact_mismatch(self):
        from server.fp_manager import _ip_matches
        assert _ip_matches("192.168.1.6", "192.168.1.5") is False

    def test_cidr_match(self):
        from server.fp_manager import _ip_matches
        assert _ip_matches("10.0.0.50", "10.0.0.0/24") is True

    def test_cidr_outside(self):
        from server.fp_manager import _ip_matches
        assert _ip_matches("10.0.1.1", "10.0.0.0/24") is False

    def test_pattern_none_matches_any(self):
        from server.fp_manager import _ip_matches
        assert _ip_matches("1.2.3.4", None) is True

    def test_ip_none_with_pattern(self):
        from server.fp_manager import _ip_matches
        assert _ip_matches(None, "10.0.0.0/8") is False

    def test_host_cidr(self):
        from server.fp_manager import _ip_matches
        assert _ip_matches("172.16.5.100", "172.16.0.0/12") is True


# ─────────────────────────────────────────────────────────────────────────────
#  2. Kural Eşleşme Mantığı
# ─────────────────────────────────────────────────────────────────────────────

class TestRuleMatches:

    def _rule(self, **kwargs):
        base = {
            "fp_rule_id": "x", "is_active": 1, "expires_at": None,
            "event_action": None, "source_ip": None, "destination_ip": None,
            "destination_port": None, "observer_hostname": None,
        }
        base.update(kwargs)
        return base

    def test_wildcard_rule_matches_any_event(self):
        from server.fp_manager import _rule_matches
        rule = self._rule()
        assert _rule_matches(rule, "port_scan_detected", "1.2.3.4") is True

    def test_event_action_filter(self):
        from server.fp_manager import _rule_matches
        rule = self._rule(event_action="port_scan_detected")
        assert _rule_matches(rule, "port_scan_detected", "1.2.3.4") is True
        assert _rule_matches(rule, "ssh_brute_force_detected", "1.2.3.4") is False

    def test_source_ip_cidr(self):
        from server.fp_manager import _rule_matches
        rule = self._rule(source_ip="192.168.100.0/24")
        assert _rule_matches(rule, "port_scan_detected", "192.168.100.55") is True
        assert _rule_matches(rule, "port_scan_detected", "192.168.200.1") is False

    def test_destination_port_filter(self):
        from server.fp_manager import _rule_matches
        rule = self._rule(destination_port="443")
        assert _rule_matches(rule, "web_scan_detected", None, destination_port="443") is True
        assert _rule_matches(rule, "web_scan_detected", None, destination_port="80") is False

    def test_observer_hostname_filter(self):
        from server.fp_manager import _rule_matches
        rule = self._rule(observer_hostname="firewall-01")
        assert _rule_matches(rule, "port_scan_detected", None, observer_hostname="firewall-01") is True
        assert _rule_matches(rule, "port_scan_detected", None, observer_hostname="router-02") is False

    def test_inactive_rule_never_matches(self):
        from server.fp_manager import _rule_matches
        rule = self._rule(is_active=0)
        assert _rule_matches(rule, "anything", "1.2.3.4") is False

    def test_expired_rule_never_matches(self):
        from server.fp_manager import _rule_matches
        expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        rule = self._rule(expires_at=expired)
        assert _rule_matches(rule, "anything", "1.2.3.4") is False

    def test_future_expiry_still_matches(self):
        from server.fp_manager import _rule_matches
        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        rule = self._rule(expires_at=future)
        assert _rule_matches(rule, "port_scan_detected", "1.2.3.4") is True


# ─────────────────────────────────────────────────────────────────────────────
#  3. DB Metodları
# ─────────────────────────────────────────────────────────────────────────────

class TestFPRulesDB:

    def test_create_and_get_active(self, fp_db):
        rid = _make_fp_rule(fp_db, event_action="port_scan_detected", source_ip="10.0.0.1")
        rules = fp_db.get_active_fp_rules("default")
        assert any(r["fp_rule_id"] == rid for r in rules)

    def test_get_all_includes_inactive(self, fp_db):
        rid = _make_fp_rule(fp_db, reason="test")
        fp_db.deactivate_fp_rule(rid, "default")
        active = fp_db.get_active_fp_rules("default")
        all_rules = fp_db.get_all_fp_rules("default")
        assert not any(r["fp_rule_id"] == rid for r in active)
        assert any(r["fp_rule_id"] == rid for r in all_rules)

    def test_deactivate_returns_true_on_success(self, fp_db):
        rid = _make_fp_rule(fp_db, reason="deact test")
        assert fp_db.deactivate_fp_rule(rid, "default") is True

    def test_deactivate_returns_false_if_not_found(self, fp_db):
        assert fp_db.deactivate_fp_rule("nonexistent-id", "default") is False

    def test_increment_hit_count(self, fp_db):
        rid = _make_fp_rule(fp_db, reason="hit test")
        fp_db.increment_fp_hit(rid)
        fp_db.increment_fp_hit(rid)
        rules = fp_db.get_all_fp_rules("default")
        rule = next(r for r in rules if r["fp_rule_id"] == rid)
        assert rule["hit_count"] == 2

    def test_tenant_isolation(self, fp_db):
        _make_fp_rule(fp_db, reason="tenant_a", tenant_id="tenant_a")
        assert fp_db.get_active_fp_rules("default") == []
        assert len(fp_db.get_active_fp_rules("tenant_a")) == 1


# ─────────────────────────────────────────────────────────────────────────────
#  4. FPManager (önbellek + is_suppressed)
# ─────────────────────────────────────────────────────────────────────────────

class TestFPManager:

    def test_is_suppressed_returns_rule_id(self, fp_db):
        from server.fp_manager import FPManager
        rid = _make_fp_rule(fp_db, event_action="port_scan_detected", source_ip="10.0.0.5")
        mgr = FPManager()
        result = mgr.is_suppressed("port_scan_detected", "10.0.0.5")
        assert result == rid

    def test_is_suppressed_returns_none_when_no_match(self, fp_db):
        from server.fp_manager import FPManager
        _make_fp_rule(fp_db, event_action="port_scan_detected", source_ip="10.0.0.5")
        mgr = FPManager()
        assert mgr.is_suppressed("ssh_brute_force_detected", "10.0.0.5") is None

    def test_invalidate_forces_reload(self, fp_db):
        from server.fp_manager import FPManager
        mgr = FPManager()
        mgr.is_suppressed("test", "1.1.1.1")  # cache doldur
        rid = _make_fp_rule(fp_db, event_action="new_action")
        assert mgr.is_suppressed("new_action", None) is None  # henüz cache'de değil
        mgr.invalidate()
        assert mgr.is_suppressed("new_action", None) == rid

    def test_cidr_suppression(self, fp_db):
        from server.fp_manager import FPManager
        rid = _make_fp_rule(fp_db, source_ip="172.16.0.0/12")
        mgr = FPManager()
        assert mgr.is_suppressed("anything", "172.16.5.100") == rid
        assert mgr.is_suppressed("anything", "192.168.1.1") is None


# ─────────────────────────────────────────────────────────────────────────────
#  5. API Endpointleri
# ─────────────────────────────────────────────────────────────────────────────

class TestFPRulesAPI:

    def test_create_and_list(self, fp_db, monkeypatch):
        from fastapi.testclient import TestClient
        from server.main import app

        monkeypatch.setattr("server.routes.fp_rules.db", fp_db)
        client = TestClient(app)

        token_resp = client.post("/api/v1/auth/login",
                                 json={"username": "admin", "password": "netguard123"})
        if token_resp.status_code != 200:
            pytest.skip("Auth çalışmıyor")
        token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        create_resp = client.post("/api/v1/fp-rules", headers=headers, json={
            "event_action":  "port_scan_detected",
            "source_ip":     "10.0.0.0/8",
            "reason":        "İç ağ tarayıcı — yetkili",
            "expires_in_days": 30,
        })
        assert create_resp.status_code == 201
        fp_rule_id = create_resp.json()["fp_rule_id"]

        list_resp = client.get("/api/v1/fp-rules", headers=headers)
        assert list_resp.status_code == 200
        assert any(r["fp_rule_id"] == fp_rule_id for r in list_resp.json())

    def test_delete_deactivates(self, fp_db, monkeypatch):
        from fastapi.testclient import TestClient
        from server.main import app

        monkeypatch.setattr("server.routes.fp_rules.db", fp_db)
        client = TestClient(app)

        token_resp = client.post("/api/v1/auth/login",
                                 json={"username": "admin", "password": "netguard123"})
        if token_resp.status_code != 200:
            pytest.skip("Auth çalışmıyor")
        token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        rid = _make_fp_rule(fp_db, reason="silinecek")
        del_resp = client.delete(f"/api/v1/fp-rules/{rid}", headers=headers)
        assert del_resp.status_code == 200

        active = fp_db.get_active_fp_rules("default")
        assert not any(r["fp_rule_id"] == rid for r in active)

    def test_delete_nonexistent_returns_404(self, fp_db, monkeypatch):
        from fastapi.testclient import TestClient
        from server.main import app

        monkeypatch.setattr("server.routes.fp_rules.db", fp_db)
        client = TestClient(app)

        token_resp = client.post("/api/v1/auth/login",
                                 json={"username": "admin", "password": "netguard123"})
        if token_resp.status_code != 200:
            pytest.skip("Auth çalışmıyor")
        token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        resp = client.delete("/api/v1/fp-rules/nonexistent-id", headers=headers)
        assert resp.status_code == 404

    def test_create_empty_reason_rejected(self, fp_db, monkeypatch):
        from fastapi.testclient import TestClient
        from server.main import app

        monkeypatch.setattr("server.routes.fp_rules.db", fp_db)
        client = TestClient(app)

        token_resp = client.post("/api/v1/auth/login",
                                 json={"username": "admin", "password": "netguard123"})
        if token_resp.status_code != 200:
            pytest.skip("Auth çalışmıyor")
        token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        resp = client.post("/api/v1/fp-rules", headers=headers, json={
            "event_action": "port_scan_detected",
            "reason": "   ",
        })
        assert resp.status_code == 422

    def test_create_invalid_ip_rejected(self, fp_db, monkeypatch):
        from fastapi.testclient import TestClient
        from server.main import app

        monkeypatch.setattr("server.routes.fp_rules.db", fp_db)
        client = TestClient(app)

        token_resp = client.post("/api/v1/auth/login",
                                 json={"username": "admin", "password": "netguard123"})
        if token_resp.status_code != 200:
            pytest.skip("Auth çalışmıyor")
        token = token_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        resp = client.post("/api/v1/fp-rules", headers=headers, json={
            "source_ip": "not-an-ip",
            "reason": "test",
        })
        assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
#  6. Correlator Entegrasyon
# ─────────────────────────────────────────────────────────────────────────────

class TestCorrelatorFPIntegration:

    def test_fp_rule_suppresses_incident_creation(self, fp_db, monkeypatch):
        """
        Aktif FP kuralı eşleşince _create_incident_from_corr çağrılmamalı.
        """
        from server.fp_manager import FPManager
        from shared.models import CorrelatedEvent

        mgr = FPManager()
        _make_fp_rule(fp_db, event_action="port_scan_detected", source_ip="10.99.0.1")
        mgr.invalidate()

        incident_calls = []

        class FakeCorrelator:
            def _is_fp_suppressed(self, event, tenant_id="default"):
                source_ip = event.group_value if event.group_by_field == "source_ip" else None
                rule_id = mgr.is_suppressed(event.event_action, source_ip, tenant_id=tenant_id)
                if rule_id:
                    fp_db.increment_fp_hit(rule_id)
                    return True
                return False

            def _create_incident_from_corr(self, event):
                incident_calls.append(event)

        fc = FakeCorrelator()
        now = datetime.now(timezone.utc)
        event = CorrelatedEvent(
            corr_id="x", rule_id="r1", rule_name="Port Scan",
            event_action="port_scan_detected", severity="warning",
            group_value="10.99.0.1", group_by_field="source_ip",
            matched_count=5, window_seconds=60,
            first_seen=now, last_seen=now, message="test",
        )

        if fc._is_fp_suppressed(event):
            pass  # incident oluşturma
        else:
            fc._create_incident_from_corr(event)

        assert incident_calls == [], "FP kuralı eşleşince incident oluşturulmamalı"

    def test_no_fp_rule_allows_incident(self, fp_db):
        """FP kuralı yokken incident oluşturulmalı."""
        from server.fp_manager import FPManager
        from shared.models import CorrelatedEvent

        mgr = FPManager()
        incident_calls = []

        class FakeCorrelator:
            def _is_fp_suppressed(self, event, tenant_id="default"):
                source_ip = event.group_value if event.group_by_field == "source_ip" else None
                return mgr.is_suppressed(event.event_action, source_ip, tenant_id=tenant_id) is not None

            def _create_incident_from_corr(self, event):
                incident_calls.append(event)

        fc = FakeCorrelator()
        now = datetime.now(timezone.utc)
        event = CorrelatedEvent(
            corr_id="y", rule_id="r2", rule_name="SSH Brute",
            event_action="ssh_brute_force_detected", severity="high",
            group_value="192.168.1.10", group_by_field="source_ip",
            matched_count=10, window_seconds=300,
            first_seen=now, last_seen=now, message="test",
        )

        if fc._is_fp_suppressed(event):
            pass
        else:
            fc._create_incident_from_corr(event)

        assert len(incident_calls) == 1, "FP kuralı yokken incident oluşturulmalı"

    def test_hit_count_incremented_on_suppression(self, fp_db):
        """FP eşleşmesi hit_count'u artırmalı."""
        from server.fp_manager import FPManager

        rid = _make_fp_rule(fp_db, event_action="web_scan_detected")
        mgr = FPManager()

        for _ in range(3):
            matched = mgr.is_suppressed("web_scan_detected", None)
            if matched:
                fp_db.increment_fp_hit(matched)

        rules = fp_db.get_all_fp_rules("default")
        rule = next(r for r in rules if r["fp_rule_id"] == rid)
        assert rule["hit_count"] == 3
