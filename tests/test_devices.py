"""
Unified Device Model testleri.
"""

import pytest
from fastapi.testclient import TestClient
from server.main import app
from server.database import DatabaseManager

client = TestClient(app)


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Her test için ayrı SQLite DB."""
    db_file = str(tmp_path / "test.db")
    test_db = DatabaseManager(db_path=db_file)
    monkeypatch.setattr("server.database.db", test_db)
    monkeypatch.setattr("server.routes.devices.db", test_db)
    monkeypatch.setattr("server.routes.agents.db", test_db)
    monkeypatch.setattr("server.routes.snmp.db", test_db)
    return test_db


class TestDevicesTable:
    def test_save_and_retrieve_agent(self, tmp_db):
        tmp_db.save_device(
            device_id="agent-uuid-1",
            name="web-server",
            device_type="agent",
            os_info="Linux 6.1",
            status="up",
        )
        device = tmp_db.get_device("agent-uuid-1")
        assert device is not None
        assert device["name"] == "web-server"
        assert device["type"] == "agent"
        assert device["status"] == "up"

    def test_save_and_retrieve_snmp(self, tmp_db):
        tmp_db.save_device(
            device_id="192.168.1.1",
            name="core-router",
            device_type="snmp",
            ip="192.168.1.1",
            snmp_community="public",
            status="unknown",
        )
        device = tmp_db.get_device("192.168.1.1")
        assert device["type"] == "snmp"
        assert device["snmp_community"] == "public"

    def test_upsert_updates_status(self, tmp_db):
        tmp_db.save_device("dev-1", "router", "snmp", status="unknown")
        tmp_db.update_device_status("dev-1", "up")
        assert tmp_db.get_device("dev-1")["status"] == "up"

    def test_get_devices_all(self, tmp_db):
        tmp_db.save_device("a1", "host1", "agent")
        tmp_db.save_device("192.168.1.1", "router", "snmp")
        devices = tmp_db.get_devices()
        assert len(devices) == 2

    def test_get_devices_filtered_by_type(self, tmp_db):
        tmp_db.save_device("a1", "host1", "agent")
        tmp_db.save_device("192.168.1.1", "router", "snmp")
        agents = tmp_db.get_devices(device_type="agent")
        assert len(agents) == 1
        assert agents[0]["type"] == "agent"

    def test_remove_device(self, tmp_db):
        tmp_db.save_device("dev-1", "host", "agent")
        assert tmp_db.remove_device("dev-1") is True
        assert tmp_db.get_device("dev-1") is None

    def test_remove_nonexistent_returns_false(self, tmp_db):
        assert tmp_db.remove_device("nonexistent") is False


class TestDevicesAPI:
    def test_list_devices_requires_auth(self):
        r = client.get("/api/v1/devices")
        assert r.status_code == 401

    def test_list_devices_empty(self, admin_token):
        r = client.get("/api/v1/devices", headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 200
        assert "devices" in r.json()

    def test_get_nonexistent_device(self, admin_token):
        r = client.get("/api/v1/devices/nonexistent-id", headers={"Authorization": f"Bearer {admin_token}"})
        assert r.status_code == 404

    def test_agent_register_creates_device(self, admin_token, tmp_db):
        payload = {
            "agent_id": "test-agent-001",
            "hostname": "test-host",
            "os_name": "Linux",
            "os_version": "6.1",
            "python_version": "3.12",
        }
        r = client.post("/api/v1/agents/register", json=payload)
        assert r.status_code == 201
        device = tmp_db.get_device("test-agent-001")
        assert device is not None
        assert device["type"] == "agent"
        assert device["name"] == "test-host"
        assert device["status"] == "up"

    def test_snmp_add_creates_device(self, admin_token, tmp_db):
        r = client.post(
            "/api/v1/snmp/devices",
            json={"host": "10.0.0.1", "community": "public", "label": "edge-router"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 201
        device = tmp_db.get_device("10.0.0.1")
        assert device is not None
        assert device["type"] == "snmp"
        assert device["name"] == "edge-router"

    def test_snmp_remove_deletes_device(self, admin_token, tmp_db):
        tmp_db.add_snmp_device("10.0.0.2", "public", "switch")
        tmp_db.save_device("10.0.0.2", "switch", "snmp", ip="10.0.0.2")
        r = client.delete(
            "/api/v1/snmp/devices/10.0.0.2",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert tmp_db.get_device("10.0.0.2") is None
