"""
F5 — Threat Hunt Workbench endpoint testleri.

GET/POST /api/v1/hunts
GET/PUT/DELETE /api/v1/hunts/{id}
PATCH /api/v1/hunts/{id}/favorite
POST /api/v1/hunts/{id}/execute
POST /api/v1/hunts/execute
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from server.main import app

client = TestClient(app, raise_server_exceptions=False)


# ── Yardımcılar ───────────────────────────────────────────────────────────────

VALID_FILTERS = {
    "source_ip": None,
    "destination_ip": None,
    "event_action": None,
    "event_category": None,
    "severity": None,
    "source_type": None,
    "network_protocol": None,
    "keyword": None,
    "hours": 24,
    "limit": 200,
}


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _create_hunt(token, name="Test Hunt", filters=None):
    payload = {
        "name": name,
        "description": "A test hunt",
        "filters": filters or VALID_FILTERS,
        "tags": ["test"],
        "is_favorite": False,
    }
    return client.post("/api/v1/hunts", json=payload, headers=_auth(token))


def _seed_log(tmp_db, tenant_id="default"):
    log_id = str(uuid.uuid4())
    with tmp_db._connect() as conn:
        conn.execute(
            """INSERT INTO normalized_logs
               (log_id, tenant_id, source_type, observer_hostname, timestamp,
                severity, event_category, event_action, source_ip,
                destination_ip, message, received_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                log_id, tenant_id, "suricata", "sensor1",
                datetime.now(timezone.utc).isoformat(),
                "warning", "network", "dns_query",
                "10.0.0.1", "8.8.8.8", "test log entry",
                datetime.now(timezone.utc),
            ),
        )
    return log_id


# ── List ──────────────────────────────────────────────────────────────────────

class TestListHunts:
    def test_unauthenticated(self):
        r = client.get("/api/v1/hunts")
        assert r.status_code == 401

    def test_empty_list(self, tmp_db, admin_token):
        r = client.get("/api/v1/hunts", headers=_auth(admin_token))
        assert r.status_code == 200
        assert r.json()["count"] == 0
        assert r.json()["hunts"] == []

    def test_lists_created_hunts(self, tmp_db, admin_token):
        _create_hunt(admin_token, "Hunt Alpha")
        _create_hunt(admin_token, "Hunt Beta")
        r = client.get("/api/v1/hunts", headers=_auth(admin_token))
        assert r.status_code == 200
        assert r.json()["count"] == 2
        names = {h["name"] for h in r.json()["hunts"]}
        assert names == {"Hunt Alpha", "Hunt Beta"}


# ── Create ────────────────────────────────────────────────────────────────────

class TestCreateHunt:
    def test_unauthenticated(self):
        r = client.post("/api/v1/hunts", json={"name": "x", "filters": VALID_FILTERS})
        assert r.status_code == 401

    def test_create_basic(self, tmp_db, admin_token):
        r = _create_hunt(admin_token)
        assert r.status_code == 201
        body = r.json()
        assert "hunt_id" in body
        assert body["name"] == "Test Hunt"

    def test_create_with_favorite(self, tmp_db, admin_token):
        payload = {
            "name": "Fav Hunt",
            "filters": VALID_FILTERS,
            "is_favorite": True,
        }
        r = client.post("/api/v1/hunts", json=payload, headers=_auth(admin_token))
        assert r.status_code == 201
        hunt_id = r.json()["hunt_id"]
        detail = client.get(f"/api/v1/hunts/{hunt_id}", headers=_auth(admin_token))
        assert detail.json()["is_favorite"] is True

    def test_invalid_severity(self, tmp_db, admin_token):
        filters = {**VALID_FILTERS, "severity": "extreme"}
        r = client.post(
            "/api/v1/hunts",
            json={"name": "Bad", "filters": filters},
            headers=_auth(admin_token),
        )
        assert r.status_code == 422

    def test_invalid_source_type(self, tmp_db, admin_token):
        filters = {**VALID_FILTERS, "source_type": "unknown_source"}
        r = client.post(
            "/api/v1/hunts",
            json={"name": "Bad", "filters": filters},
            headers=_auth(admin_token),
        )
        assert r.status_code == 422

    def test_invalid_category(self, tmp_db, admin_token):
        filters = {**VALID_FILTERS, "event_category": "financial"}
        r = client.post(
            "/api/v1/hunts",
            json={"name": "Bad", "filters": filters},
            headers=_auth(admin_token),
        )
        assert r.status_code == 422

    def test_missing_name(self, tmp_db, admin_token):
        r = client.post(
            "/api/v1/hunts",
            json={"filters": VALID_FILTERS},
            headers=_auth(admin_token),
        )
        assert r.status_code == 422

    def test_filter_params_persisted(self, tmp_db, admin_token):
        filters = {**VALID_FILTERS, "source_ip": "192.168.1.1", "hours": 48}
        r = _create_hunt(admin_token, filters=filters)
        assert r.status_code == 201
        hunt_id = r.json()["hunt_id"]
        detail = client.get(f"/api/v1/hunts/{hunt_id}", headers=_auth(admin_token))
        fp = detail.json()["filter_params"]
        assert fp["source_ip"] == "192.168.1.1"
        assert fp["hours"] == 48


# ── Get / Update / Delete ─────────────────────────────────────────────────────

class TestHuntCRUD:
    def test_get_not_found(self, tmp_db, admin_token):
        r = client.get(f"/api/v1/hunts/{uuid.uuid4()}", headers=_auth(admin_token))
        assert r.status_code == 404

    def test_get_existing(self, tmp_db, admin_token):
        hunt_id = _create_hunt(admin_token).json()["hunt_id"]
        r = client.get(f"/api/v1/hunts/{hunt_id}", headers=_auth(admin_token))
        assert r.status_code == 200
        assert r.json()["name"] == "Test Hunt"

    def test_update_hunt(self, tmp_db, admin_token):
        hunt_id = _create_hunt(admin_token).json()["hunt_id"]
        payload = {
            "name": "Updated Hunt",
            "description": "Updated desc",
            "filters": {**VALID_FILTERS, "hours": 6},
            "tags": ["updated"],
            "is_favorite": True,
        }
        r = client.put(f"/api/v1/hunts/{hunt_id}", json=payload, headers=_auth(admin_token))
        assert r.status_code == 200
        assert r.json()["updated"] is True
        detail = client.get(f"/api/v1/hunts/{hunt_id}", headers=_auth(admin_token))
        assert detail.json()["name"] == "Updated Hunt"
        assert detail.json()["is_favorite"] is True

    def test_update_not_found(self, tmp_db, admin_token):
        payload = {
            "name": "X",
            "filters": VALID_FILTERS,
            "is_favorite": False,
        }
        r = client.put(
            f"/api/v1/hunts/{uuid.uuid4()}",
            json=payload,
            headers=_auth(admin_token),
        )
        assert r.status_code == 404

    def test_delete_hunt(self, tmp_db, admin_token):
        hunt_id = _create_hunt(admin_token).json()["hunt_id"]
        r = client.delete(f"/api/v1/hunts/{hunt_id}", headers=_auth(admin_token))
        assert r.status_code == 204
        assert client.get(f"/api/v1/hunts/{hunt_id}", headers=_auth(admin_token)).status_code == 404

    def test_delete_not_found(self, tmp_db, admin_token):
        r = client.delete(f"/api/v1/hunts/{uuid.uuid4()}", headers=_auth(admin_token))
        assert r.status_code == 404


# ── Favorite ──────────────────────────────────────────────────────────────────

class TestFavoriteToggle:
    def test_toggle_favorite(self, tmp_db, admin_token):
        hunt_id = _create_hunt(admin_token).json()["hunt_id"]
        r = client.patch(f"/api/v1/hunts/{hunt_id}/favorite", headers=_auth(admin_token))
        assert r.status_code == 200
        assert r.json()["is_favorite"] is True
        r2 = client.patch(f"/api/v1/hunts/{hunt_id}/favorite", headers=_auth(admin_token))
        assert r2.json()["is_favorite"] is False

    def test_toggle_not_found(self, tmp_db, admin_token):
        r = client.patch(f"/api/v1/hunts/{uuid.uuid4()}/favorite", headers=_auth(admin_token))
        assert r.status_code == 404


# ── Execute saved hunt ────────────────────────────────────────────────────────

class TestExecuteHunt:
    def test_execute_not_found(self, tmp_db, admin_token):
        r = client.post(f"/api/v1/hunts/{uuid.uuid4()}/execute", headers=_auth(admin_token))
        assert r.status_code == 404

    def test_execute_returns_result_shape(self, tmp_db, admin_token):
        hunt_id = _create_hunt(admin_token).json()["hunt_id"]
        r = client.post(f"/api/v1/hunts/{hunt_id}/execute", headers=_auth(admin_token))
        assert r.status_code == 200
        body = r.json()
        assert "count" in body
        assert "logs" in body
        assert "stats" in body
        for col in ("source_ip", "event_action", "event_category", "severity"):
            assert col in body["stats"]

    def test_execute_increments_run_count(self, tmp_db, admin_token):
        hunt_id = _create_hunt(admin_token).json()["hunt_id"]
        client.post(f"/api/v1/hunts/{hunt_id}/execute", headers=_auth(admin_token))
        client.post(f"/api/v1/hunts/{hunt_id}/execute", headers=_auth(admin_token))
        detail = client.get(f"/api/v1/hunts/{hunt_id}", headers=_auth(admin_token))
        assert detail.json()["run_count"] == 2

    def test_execute_with_matching_logs(self, tmp_db, admin_token):
        _seed_log(tmp_db)
        hunt_id = _create_hunt(
            admin_token,
            filters={**VALID_FILTERS, "source_type": "suricata"},
        ).json()["hunt_id"]
        r = client.post(f"/api/v1/hunts/{hunt_id}/execute", headers=_auth(admin_token))
        assert r.status_code == 200
        assert r.json()["count"] >= 1


# ── Ad-hoc execute ────────────────────────────────────────────────────────────

class TestAdhocExecute:
    def test_unauthenticated(self):
        r = client.post("/api/v1/hunts/execute", json=VALID_FILTERS)
        assert r.status_code == 401

    def test_execute_empty(self, tmp_db, admin_token):
        r = client.post("/api/v1/hunts/execute", json=VALID_FILTERS, headers=_auth(admin_token))
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 0
        assert body["logs"] == []

    def test_execute_with_log(self, tmp_db, admin_token):
        _seed_log(tmp_db)
        r = client.post("/api/v1/hunts/execute", json=VALID_FILTERS, headers=_auth(admin_token))
        assert r.status_code == 200
        assert r.json()["count"] >= 1

    def test_execute_severity_filter(self, tmp_db, admin_token):
        _seed_log(tmp_db)
        filters = {**VALID_FILTERS, "severity": "critical"}
        r = client.post("/api/v1/hunts/execute", json=filters, headers=_auth(admin_token))
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_execute_source_type_filter(self, tmp_db, admin_token):
        _seed_log(tmp_db)
        filters_match = {**VALID_FILTERS, "source_type": "suricata"}
        r = client.post("/api/v1/hunts/execute", json=filters_match, headers=_auth(admin_token))
        assert r.status_code == 200
        assert r.json()["count"] >= 1

        filters_no_match = {**VALID_FILTERS, "source_type": "zeek"}
        r2 = client.post("/api/v1/hunts/execute", json=filters_no_match, headers=_auth(admin_token))
        assert r2.status_code == 200
        assert r2.json()["count"] == 0

    def test_stats_shape(self, tmp_db, admin_token):
        _seed_log(tmp_db)
        r = client.post("/api/v1/hunts/execute", json=VALID_FILTERS, headers=_auth(admin_token))
        stats = r.json()["stats"]
        assert isinstance(stats["source_ip"], list)
        if stats["source_ip"]:
            item = stats["source_ip"][0]
            assert "value" in item and "count" in item

    def test_invalid_severity_rejected(self, tmp_db, admin_token):
        filters = {**VALID_FILTERS, "severity": "ultra"}
        r = client.post("/api/v1/hunts/execute", json=filters, headers=_auth(admin_token))
        assert r.status_code == 422

    def test_hours_out_of_range(self, tmp_db, admin_token):
        filters = {**VALID_FILTERS, "hours": 9999}
        r = client.post("/api/v1/hunts/execute", json=filters, headers=_auth(admin_token))
        assert r.status_code == 422


# ── Tenant isolation ──────────────────────────────────────────────────────────

class TestTenantIsolation:
    def test_hunt_not_visible_across_tenants(self, tmp_db, admin_token):
        from server.auth import create_access_token
        with tmp_db._connect() as conn:
            conn.execute(
                "INSERT INTO tenants (id, name) VALUES ('other', 'Other') ON CONFLICT DO NOTHING"
            )
        other_token = create_access_token(username="other_user", role="admin", tenant_id="other")
        hunt_id = _create_hunt(admin_token).json()["hunt_id"]
        r = client.get(f"/api/v1/hunts/{hunt_id}", headers=_auth(other_token))
        assert r.status_code == 404

    def test_list_tenant_isolation(self, tmp_db, admin_token):
        from server.auth import create_access_token
        with tmp_db._connect() as conn:
            conn.execute(
                "INSERT INTO tenants (id, name) VALUES ('other', 'Other') ON CONFLICT DO NOTHING"
            )
        other_token = create_access_token(username="other_user", role="admin", tenant_id="other")
        _create_hunt(admin_token)
        r = client.get("/api/v1/hunts", headers=_auth(other_token))
        assert r.json()["count"] == 0
