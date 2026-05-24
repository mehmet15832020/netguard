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
    """Kuralları izole geçici dosyaya yönlendir.
    Route, correlator._rules_path'i tek kaynak olarak kullanır."""
    path = tmp_path / "correlation_rules.json"
    path.write_text(json.dumps([dict(_RULE_A)]), encoding="utf-8")
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

    def test_toggle_reflects_in_correlator_rules(self, rules_file, admin_token):
        """Toggle sonrası correlator.rules enabled=False kuralı listesinden çıkarır."""
        from server.correlator import correlator as _corr
        client.patch(
            "/api/v1/correlation/rules/ssh_brute/toggle",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        active_ids = [r.rule_id for r in _corr.rules]
        assert "ssh_brute" not in active_ids


# ─── Boundary değerleri ───────────────────────────────────────────────────────

class TestBoundaryValues:
    @pytest.mark.parametrize("window,expected", [
        (9, 422), (10, 201), (86400, 201), (86401, 422),
    ])
    def test_window_seconds_boundary(self, rules_file, admin_token, window, expected):
        rule = dict(_RULE_B, rule_id=f"bnd_win_{window}", window_seconds=window)
        r = client.post(
            "/api/v1/correlation/rules",
            json=rule,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == expected

    @pytest.mark.parametrize("threshold,expected", [
        (0, 422), (1, 201), (10000, 201), (10001, 422),
    ])
    def test_threshold_boundary(self, rules_file, admin_token, threshold, expected):
        rule = dict(_RULE_B, rule_id=f"bnd_thr_{threshold}", threshold=threshold)
        r = client.post(
            "/api/v1/correlation/rules",
            json=rule,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == expected

    @pytest.mark.parametrize("rule_id,expected", [
        ("a", 422),       # 1 karakter — çok kısa
        ("ab", 201),      # 2 karakter — minimum
        ("a" * 64, 201),  # 64 karakter — maximum
        ("a" * 65, 422),  # 65 karakter — çok uzun
    ])
    def test_rule_id_length_boundary(self, rules_file, admin_token, rule_id, expected):
        rule = dict(_RULE_B, rule_id=rule_id)
        r = client.post(
            "/api/v1/correlation/rules",
            json=rule,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == expected

    def test_distinct_by_invalid_column_returns_422(self, rules_file, admin_token):
        rule = dict(_RULE_B, rule_id="bnd_dst", distinct_by="nonexistent_column")
        r = client.post(
            "/api/v1/correlation/rules",
            json=rule,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 422

    def test_description_max_length(self, rules_file, admin_token):
        rule = dict(_RULE_B, rule_id="bnd_desc", description="x" * 501)
        r = client.post(
            "/api/v1/correlation/rules",
            json=rule,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 422

    def test_match_event_action_max_length(self, rules_file, admin_token):
        rule = dict(_RULE_B, rule_id="bnd_mea", match_event_action="x" * 121)
        r = client.post(
            "/api/v1/correlation/rules",
            json=rule,
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 422


# ─── Bulk PUT validasyon ──────────────────────────────────────────────────────

class TestBulkPutValidation:
    def test_bulk_put_validates_each_rule(self, rules_file, admin_token):
        """Bulk PUT artık CorrelationRuleIn ile tam validasyon yapar."""
        invalid_rule = dict(_RULE_B, severity="extreme")
        r = client.put(
            "/api/v1/correlation/rules",
            json={"rules": [dict(_RULE_A), invalid_rule]},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 422

    def test_bulk_put_valid_rules_succeed(self, rules_file, admin_token):
        r = client.put(
            "/api/v1/correlation/rules",
            json={"rules": [dict(_RULE_A), dict(_RULE_B)]},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert r.json()["saved"] == 2

    def test_bulk_put_invalid_group_by_returns_422(self, rules_file, admin_token):
        bad = dict(_RULE_B, group_by="bad_column")
        r = client.put(
            "/api/v1/correlation/rules",
            json={"rules": [bad]},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 422


# ─── Unified path testi ───────────────────────────────────────────────────────

class TestUnifiedPath:
    def test_write_and_reload_use_same_path(self, rules_file, admin_token):
        """Route yazması correlator'ın okuduğu aynı dosyaya gitmelidir.
        POST sonrası correlator.load_rules() çağrılır; yeni kural correlator.rules'ta görünür."""
        from server.correlator import correlator as _corr
        client.post(
            "/api/v1/correlation/rules",
            json=dict(_RULE_B),
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        active_ids = [r.rule_id for r in _corr.rules]
        assert "port_sweep" in active_ids
