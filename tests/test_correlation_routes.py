"""
Korelasyon route testleri — PUT /correlation/rules endpoint dahil.
"""

import json
import pytest
from fastapi.testclient import TestClient
from server.main import app

client = TestClient(app)

VALID_RULE = {
    "rule_id": "test_rule",
    "name": "Test Kuralı",
    "description": "Test amaçlı",
    "match_event_type": "ssh_failure",
    "group_by": "src_ip",
    "window_seconds": 60,
    "threshold": 3,
    "severity": "warning",
    "output_event_type": "test_detected",
    "enabled": True,
}


class TestCorrelationRoutes:
    def test_list_rules_requires_auth(self):
        r = client.get("/api/v1/correlation/rules")
        assert r.status_code == 401

    def test_list_rules_returns_list(self, admin_token):
        r = client.get("/api/v1/correlation/rules", headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        assert "rules" in r.json()
        assert "count" in r.json()

    def test_list_events_returns_list(self, admin_token):
        r = client.get("/api/v1/correlation/events", headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        assert "events" in r.json()

    def test_update_rules_requires_admin(self, admin_token):
        r = client.put(
            "/api/v1/correlation/rules",
            json={"rules": [VALID_RULE]},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["saved"] == 1
        assert data["loaded"] == 1

    def test_update_rules_rejects_missing_field(self, admin_token):
        bad_rule = {k: v for k, v in VALID_RULE.items() if k != "output_event_type"}
        r = client.put(
            "/api/v1/correlation/rules",
            json={"rules": [bad_rule]},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 422

    def test_update_rules_requires_auth(self):
        r = client.put("/api/v1/correlation/rules", json={"rules": [VALID_RULE]})
        assert r.status_code == 401

    def test_reload_rules_returns_count(self, admin_token):
        r = client.post(
            "/api/v1/correlation/rules/reload",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert "loaded" in r.json()
