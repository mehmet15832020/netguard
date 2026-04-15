"""
SNMP endpoint testleri.

POST   /api/v1/snmp/poll
GET    /api/v1/snmp/devices
POST   /api/v1/snmp/devices
DELETE /api/v1/snmp/devices/{host}
"""

import pytest
from fastapi.testclient import TestClient
from server.main import app
from server.database import db

client = TestClient(app)


@pytest.fixture
def auth(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(autouse=True)
def clean_snmp_devices():
    """Her testten önce snmp_devices tablosunu temizle."""
    with db._connect() as conn:
        conn.execute("DELETE FROM snmp_devices")
    yield
    with db._connect() as conn:
        conn.execute("DELETE FROM snmp_devices")


class TestSNMPDeviceManagement:
    def test_list_devices_empty(self, auth):
        resp = client.get("/api/v1/snmp/devices", headers=auth)
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["devices"] == []

    def test_add_device_success(self, auth):
        resp = client.post(
            "/api/v1/snmp/devices",
            json={"host": "192.168.1.1", "community": "public", "label": "Router"},
            headers=auth,
        )
        assert resp.status_code == 201
        assert resp.json()["added"] is True
        assert resp.json()["host"] == "192.168.1.1"

    def test_add_duplicate_device_returns_409(self, auth):
        payload = {"host": "192.168.1.2", "community": "public"}
        client.post("/api/v1/snmp/devices", json=payload, headers=auth)
        resp = client.post("/api/v1/snmp/devices", json=payload, headers=auth)
        assert resp.status_code == 409

    def test_list_devices_after_add(self, auth):
        client.post(
            "/api/v1/snmp/devices",
            json={"host": "10.0.0.1", "community": "public", "label": "Switch"},
            headers=auth,
        )
        resp = client.get("/api/v1/snmp/devices", headers=auth)
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 1
        assert data["devices"][0]["host"] == "10.0.0.1"
        assert data["devices"][0]["label"] == "Switch"

    def test_remove_device_success(self, auth):
        client.post("/api/v1/snmp/devices", json={"host": "10.0.0.2"}, headers=auth)
        resp = client.delete("/api/v1/snmp/devices/10.0.0.2", headers=auth)
        assert resp.status_code == 200
        assert resp.json()["removed"] is True
        # Listede artık yok
        devices = client.get("/api/v1/snmp/devices", headers=auth).json()["devices"]
        assert all(d["host"] != "10.0.0.2" for d in devices)

    def test_remove_nonexistent_device_returns_404(self, auth):
        resp = client.delete("/api/v1/snmp/devices/99.99.99.99", headers=auth)
        assert resp.status_code == 404

    def test_list_count_after_remove(self, auth):
        for i in range(3):
            client.post("/api/v1/snmp/devices", json={"host": f"10.0.1.{i}"}, headers=auth)
        client.delete("/api/v1/snmp/devices/10.0.1.0", headers=auth)
        resp = client.get("/api/v1/snmp/devices", headers=auth)
        assert resp.json()["count"] == 2

    def test_unauthenticated_requests_return_401(self):
        assert client.get("/api/v1/snmp/devices").status_code == 401
        assert client.post("/api/v1/snmp/devices", json={"host": "1.1.1.1"}).status_code == 401
        assert client.delete("/api/v1/snmp/devices/1.1.1.1").status_code == 401

    def test_device_default_community_is_public(self, auth):
        client.post("/api/v1/snmp/devices", json={"host": "10.0.0.5"}, headers=auth)
        devices = client.get("/api/v1/snmp/devices", headers=auth).json()["devices"]
        device = next(d for d in devices if d["host"] == "10.0.0.5")
        assert device["community"] == "public"


class TestSNMPPollEndpoint:
    def test_poll_unreachable_host_returns_200(self, auth):
        """Erişilemeyen host exception değil sonuç döndürmeli."""
        resp = client.post(
            "/api/v1/snmp/poll",
            json={"host": "192.0.2.1", "community": "public"},
            headers=auth,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["host"] == "192.0.2.1"
        assert data["reachable"] is False

    def test_poll_response_has_required_fields(self, auth):
        resp = client.post(
            "/api/v1/snmp/poll",
            json={"host": "192.0.2.1"},
            headers=auth,
        )
        data = resp.json()
        for field in ["host", "community", "reachable", "sys_name", "uptime_ticks"]:
            assert field in data

    def test_poll_unauthenticated_returns_401(self):
        resp = client.post("/api/v1/snmp/poll", json={"host": "192.0.2.1"})
        assert resp.status_code == 401
