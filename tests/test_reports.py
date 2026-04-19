"""
Faz 8 — Reports API testleri.
"""

import pytest
from fastapi.testclient import TestClient
from server.auth import create_access_token


@pytest.fixture()
def client(tmp_db):
    import server.database as db_module
    db_module.db = tmp_db
    from server.main import app
    return TestClient(app)


@pytest.fixture()
def auth_headers():
    token = create_access_token(username="admin", role="admin")
    return {"Authorization": f"Bearer {token}"}


class TestReportSummary:
    def test_returns_200(self, client, auth_headers):
        resp = client.get("/api/v1/reports/summary", headers=auth_headers)
        assert resp.status_code == 200

    def test_has_required_keys(self, client, auth_headers):
        resp = client.get("/api/v1/reports/summary", headers=auth_headers)
        data = resp.json()
        assert "generated_at" in data
        assert "devices"      in data
        assert "alerts"       in data
        assert "security"     in data
        assert "topology"     in data

    def test_devices_struct(self, client, auth_headers):
        resp = client.get("/api/v1/reports/summary", headers=auth_headers)
        devices = resp.json()["devices"]
        assert "total"     in devices
        assert "by_type"   in devices
        assert "by_status" in devices

    def test_requires_auth(self, client):
        resp = client.get("/api/v1/reports/summary")
        assert resp.status_code == 401


class TestDevicesCSV:
    def test_returns_csv(self, client, auth_headers):
        resp = client.get("/api/v1/reports/devices.csv", headers=auth_headers)
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]

    def test_content_disposition(self, client, auth_headers):
        resp = client.get("/api/v1/reports/devices.csv", headers=auth_headers)
        assert "attachment"       in resp.headers.get("content-disposition", "")
        assert "netguard_devices" in resp.headers.get("content-disposition", "")

    def test_csv_has_header(self, client, auth_headers, tmp_db):
        tmp_db.save_device(
            device_id="rpt-test",
            name="Test Router",
            device_type="snmp",
            ip="10.0.0.99",
        )
        resp    = client.get("/api/v1/reports/devices.csv", headers=auth_headers)
        content = resp.text
        assert "device_id" in content
        assert "name"      in content

    def test_no_secret_keys_in_csv(self, client, auth_headers, tmp_db):
        tmp_db.save_device(
            device_id="rpt-v3",
            name="V3 Router",
            device_type="snmp",
            snmp_version="v3",
            snmp_v3_auth_key="supersecret",
            snmp_v3_priv_key="supersecret2",
        )
        resp = client.get("/api/v1/reports/devices.csv", headers=auth_headers)
        assert "supersecret" not in resp.text

    def test_requires_auth(self, client):
        resp = client.get("/api/v1/reports/devices.csv")
        assert resp.status_code == 401


class TestAlertsCSV:
    def test_returns_csv(self, client, auth_headers):
        resp = client.get("/api/v1/reports/alerts.csv", headers=auth_headers)
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]


class TestSecurityCSV:
    def test_returns_csv(self, client, auth_headers):
        resp = client.get("/api/v1/reports/security.csv", headers=auth_headers)
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]


class TestTopologyCSV:
    def test_returns_csv(self, client, auth_headers):
        resp = client.get("/api/v1/reports/topology.csv", headers=auth_headers)
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
