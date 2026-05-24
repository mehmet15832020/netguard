"""
R1 — Korelasyon Kuralları CRUD endpoint testleri.

GET    /correlation/rules/{rule_id}
POST   /correlation/rules
PUT    /correlation/rules/{rule_id}
DELETE /correlation/rules/{rule_id}
PATCH  /correlation/rules/{rule_id}/toggle
"""

import json
import pytest
from fastapi.testclient import TestClient
from server.main import app
import server.routes.correlation as _corr_route
from server.correlator import correlator as _correlator

client = TestClient(app)

_RULE_A = {
    "rule_id": "ssh_brute",
    "name": "SSH Brute Force",
    "description": "SSH başarısız giriş tespiti",
    "match_event_action": "ssh_failure",
    "group_by": "source_ip",
    "distinct_by": None,
    "window_seconds": 300,
    "threshold": 5,
    "severity": "high",
    "output_event_action": "ssh_brute_force_detected",
    "enabled": True,
    "match_severity": None,
    "keywords": None,
    "tags": ["attack.t1110"],
}

_RULE_B = {
    "rule_id": "port_sweep",
    "name": "Port Sweep",
    "description": "",
    "match_event_action": "port_scan",
    "group_by": "destination_ip",
    "distinct_by": "destination_port",
    "window_seconds": 60,
    "threshold": 10,
    "severity": "warning",
    "output_event_action": "port_sweep_detected",
    "enabled": True,
    "match_severity": None,
    "keywords": None,
    "tags": [],
}


@pytest.fixture()
def rules_file(tmp_path, monkeypatch):
    """Kuralları izole geçici dosyaya yönlendir."""
    path = tmp_path / "correlation_rules.json"
    path.write_text(json.dumps([dict(_RULE_A)]), encoding="utf-8")
    monkeypatch.setattr(_corr_route, "RULES_PATH", str(path))
    monkeypatch.setattr(_correlator, "_rules_path", str(path))
    return path


# ─── GET /rules/{rule_id} ─────────────────────────────────────────────────────

class TestGetRule:
    def test_get_existing_rule(self, rules_file, admin_token):
        r = client.get(
            "/api/v1/correlation/rules/ssh_brute",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert r.json()["rule_id"] == "ssh_brute"
        assert r.json()["name"] == "SSH Brute Force"

    def test_get_missing_rule_returns_404(self, rules_file, admin_token):
        r = client.get(
            "/api/v1/correlation/rules/nonexistent",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 404

    def test_get_rule_requires_auth(self, rules_file):
        r = client.get("/api/v1/correlation/rules/ssh_brute")
        assert r.status_code == 401


# ─── POST /rules ──────────────────────────────────────────────────────────────

class TestCreateRule:
    def test_create_new_rule(self, rules_file, admin_token):
        r = client.post(
            "/api/v1/correlation/rules",
            json=dict(_RULE_B),
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 201
        assert r.json()["rule_id"] == "port_sweep"

    def test_create_rule_persists_to_file(self, rules_file, admin_token):
        client.post(
            "/api/v1/correlation/rules",
            json=dict(_RULE_B),
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        saved = json.loads(rules_file.read_text())
        assert any(r["rule_id"] == "port_sweep" for r in saved)

    def test_create_duplicate_rule_id_returns_409(self, rules_file, admin_token):
        r = client.post(
            "/api/v1/correlation/rules",
            json=dict(_RULE_A),
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 409

    def test_create_rule_requires_admin(self, rules_file, admin_token):
        r = client.post(
            "/api/v1/correlation/rules",
            json=dict(_RULE_B),
        )
        assert r.status_code == 401

    def test_create_rule_invalid_severity_returns_422(self, rules_file, admin_token):
        bad = dict(_RULE_B, rule_id="bad_sev", severity="extreme")
        r = client.post(
            "/api/v1/correlation/rules",
            json=bad,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 422

    def test_create_rule_invalid_rule_id_slug_returns_422(self, rules_file, admin_token):
        bad = dict(_RULE_B, rule_id="Bad Rule ID!")
        r = client.post(
            "/api/v1/correlation/rules",
            json=bad,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 422

    def test_create_rule_invalid_group_by_returns_422(self, rules_file, admin_token):
        bad = dict(_RULE_B, rule_id="bad_grp", group_by="nonexistent_column")
        r = client.post(
            "/api/v1/correlation/rules",
            json=bad,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 422

    def test_create_rule_window_out_of_range_returns_422(self, rules_file, admin_token):
        bad = dict(_RULE_B, rule_id="bad_win", window_seconds=9)
        r = client.post(
            "/api/v1/correlation/rules",
            json=bad,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 422

    def test_create_rule_threshold_out_of_range_returns_422(self, rules_file, admin_token):
        bad = dict(_RULE_B, rule_id="bad_thr", threshold=0)
        r = client.post(
            "/api/v1/correlation/rules",
            json=bad,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 422

    def test_create_rule_with_optional_fields(self, rules_file, admin_token):
        full = dict(_RULE_B, rule_id="full_rule",
                    match_severity="high",
                    keywords=["exploit", "payload"],
                    distinct_by="destination_port")
        r = client.post(
            "/api/v1/correlation/rules",
            json=full,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 201

    def test_create_rule_list_grows(self, rules_file, admin_token):
        before = client.get(
            "/api/v1/correlation/rules",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).json()["count"]
        client.post(
            "/api/v1/correlation/rules",
            json=dict(_RULE_B),
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        after = client.get(
            "/api/v1/correlation/rules",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).json()["count"]
        assert after == before + 1


# ─── PUT /rules/{rule_id} ─────────────────────────────────────────────────────

class TestUpdateRule:
    def test_update_existing_rule(self, rules_file, admin_token):
        updated = dict(_RULE_A, threshold=10, severity="critical")
        r = client.put(
            "/api/v1/correlation/rules/ssh_brute",
            json=updated,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200

    def test_update_persists_changes(self, rules_file, admin_token):
        updated = dict(_RULE_A, threshold=99)
        client.put(
            "/api/v1/correlation/rules/ssh_brute",
            json=updated,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        saved = json.loads(rules_file.read_text())
        rule = next(r for r in saved if r["rule_id"] == "ssh_brute")
        assert rule["threshold"] == 99

    def test_update_missing_rule_returns_404(self, rules_file, admin_token):
        r = client.put(
            "/api/v1/correlation/rules/ghost_rule",
            json=dict(_RULE_A, rule_id="ghost_rule"),
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 404

    def test_update_requires_admin(self, rules_file):
        r = client.put(
            "/api/v1/correlation/rules/ssh_brute",
            json=dict(_RULE_A),
        )
        assert r.status_code == 401

    def test_update_rule_id_conflict_returns_409(self, rules_file, admin_token):
        # Add a second rule first
        client.post(
            "/api/v1/correlation/rules",
            json=dict(_RULE_B),
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        # Try to rename ssh_brute to port_sweep (conflict)
        conflict = dict(_RULE_A, rule_id="port_sweep")
        r = client.put(
            "/api/v1/correlation/rules/ssh_brute",
            json=conflict,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 409


# ─── DELETE /rules/{rule_id} ──────────────────────────────────────────────────

class TestDeleteRule:
    def test_delete_existing_rule(self, rules_file, admin_token):
        r = client.delete(
            "/api/v1/correlation/rules/ssh_brute",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert r.json()["deleted"] == "ssh_brute"

    def test_delete_removes_from_file(self, rules_file, admin_token):
        client.delete(
            "/api/v1/correlation/rules/ssh_brute",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        saved = json.loads(rules_file.read_text())
        assert not any(r["rule_id"] == "ssh_brute" for r in saved)

    def test_delete_missing_rule_returns_404(self, rules_file, admin_token):
        r = client.delete(
            "/api/v1/correlation/rules/nonexistent",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 404

    def test_delete_requires_admin(self, rules_file):
        r = client.delete("/api/v1/correlation/rules/ssh_brute")
        assert r.status_code == 401

    def test_delete_reduces_list_count(self, rules_file, admin_token):
        before = client.get(
            "/api/v1/correlation/rules",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).json()["count"]
        client.delete(
            "/api/v1/correlation/rules/ssh_brute",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        after = client.get(
            "/api/v1/correlation/rules",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).json()["count"]
        assert after == before - 1


# ─── PATCH /rules/{rule_id}/toggle ───────────────────────────────────────────

class TestToggleRule:
    def test_toggle_enabled_to_disabled(self, rules_file, admin_token):
        r = client.patch(
            "/api/v1/correlation/rules/ssh_brute/toggle",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert r.json()["enabled"] is False

    def test_toggle_disabled_to_enabled(self, rules_file, admin_token):
        # Disable first
        client.patch(
            "/api/v1/correlation/rules/ssh_brute/toggle",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        # Enable again
        r = client.patch(
            "/api/v1/correlation/rules/ssh_brute/toggle",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.json()["enabled"] is True

    def test_toggle_persists_to_file(self, rules_file, admin_token):
        client.patch(
            "/api/v1/correlation/rules/ssh_brute/toggle",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        saved = json.loads(rules_file.read_text())
        rule = next(r for r in saved if r["rule_id"] == "ssh_brute")
        assert rule["enabled"] is False

    def test_toggle_missing_rule_returns_404(self, rules_file, admin_token):
        r = client.patch(
            "/api/v1/correlation/rules/ghost/toggle",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 404

    def test_toggle_requires_admin(self, rules_file):
        r = client.patch("/api/v1/correlation/rules/ssh_brute/toggle")
        assert r.status_code == 401

    def test_list_rules_includes_disabled(self, rules_file, admin_token):
        """GET /rules tüm kuralları döner, disabled olanlar dahil."""
        client.patch(
            "/api/v1/correlation/rules/ssh_brute/toggle",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        rules = client.get(
            "/api/v1/correlation/rules",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).json()["rules"]
        disabled = [r for r in rules if not r["enabled"]]
        assert len(disabled) >= 1
