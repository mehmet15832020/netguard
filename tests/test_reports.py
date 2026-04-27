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


class TestSecurityStatus:
    def test_returns_200(self, client, auth_headers):
        resp = client.get("/api/v1/reports/security-status", headers=auth_headers)
        assert resp.status_code == 200

    def test_required_fields(self, client, auth_headers):
        data = client.get("/api/v1/reports/security-status", headers=auth_headers).json()
        for key in ("risk_score", "status", "label", "critical_alerts",
                    "open_incidents", "corr_events_24h", "anomalies_24h", "updated_at"):
            assert key in data, f"missing key: {key}"

    def test_safe_when_no_threats(self, client, auth_headers):
        data = client.get("/api/v1/reports/security-status", headers=auth_headers).json()
        assert data["status"] == "safe"
        assert data["risk_score"] == 0
        assert data["label"] == "Güvende"

    def _make_critical_alert(self, tmp_db):
        from shared.models import Alert, AlertSeverity, AlertStatus
        from datetime import datetime, timezone
        import uuid
        tmp_db.save_alert(Alert(
            alert_id=str(uuid.uuid4()),
            agent_id="ag1",
            hostname="host1",
            metric="cpu",
            severity=AlertSeverity.CRITICAL,
            message="cpu high",
            status=AlertStatus.ACTIVE,
            value=95.0,
            threshold=90.0,
            triggered_at=datetime.now(timezone.utc),
        ))

    def test_danger_with_critical_alerts(self, client, auth_headers, tmp_db):
        for _ in range(3):
            self._make_critical_alert(tmp_db)
        data = client.get("/api/v1/reports/security-status", headers=auth_headers).json()
        assert data["status"] == "danger"
        assert data["critical_alerts"] == 3
        assert data["risk_score"] >= 40

    def test_warning_range(self, client, auth_headers, tmp_db):
        self._make_critical_alert(tmp_db)
        data = client.get("/api/v1/reports/security-status", headers=auth_headers).json()
        assert data["status"] == "warning"
        assert data["risk_score"] == 20

    def test_score_capped_at_100(self, client, auth_headers, tmp_db):
        for _ in range(10):
            self._make_critical_alert(tmp_db)
        data = client.get("/api/v1/reports/security-status", headers=auth_headers).json()
        assert data["risk_score"] == 100

    def test_requires_auth(self, client):
        resp = client.get("/api/v1/reports/security-status")
        assert resp.status_code == 401


class TestCountCorrelatedEvents:
    def test_empty_returns_zero(self, tmp_db):
        result = tmp_db.count_correlated_events_since(hours=24)
        assert result["total"] == 0
        assert result["high_plus"] == 0

    def _make_corr_event(self, tmp_db, severity: str, triggered_at):
        from shared.models import CorrelatedEvent
        import uuid
        uid = str(uuid.uuid4())
        tmp_db.save_correlated_event(CorrelatedEvent(
            corr_id=uid,
            rule_name="test_rule",
            rule_id=uid,
            event_type="test_event",
            severity=severity,
            group_value="192.168.1.1",
            matched_count=5,
            window_seconds=300,
            first_seen=triggered_at,
            last_seen=triggered_at,
            message="test corr",
        ))

    def test_counts_recent_events(self, tmp_db):
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        for sev in ("high", "critical", "info"):
            self._make_corr_event(tmp_db, sev, now - timedelta(hours=1))
        result = tmp_db.count_correlated_events_since(hours=24)
        assert result["total"] == 3
        assert result["high_plus"] == 2

    def test_old_events_excluded(self, tmp_db):
        from datetime import datetime, timezone, timedelta
        import uuid, sqlite3
        old_iso = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        uid = str(uuid.uuid4())
        with tmp_db._connect() as conn:
            conn.execute(
                """INSERT INTO correlated_events
                   (corr_id, rule_id, rule_name, event_type, severity,
                    group_value, matched_count, window_seconds,
                    first_seen, last_seen, message, created_at,
                    mitre_techniques, mitre_tactics)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (uid, uid, "old_rule", "test", "high", "10.0.0.1",
                 1, 300, old_iso, old_iso, "old", old_iso, "[]", "[]"),
            )
        result = tmp_db.count_correlated_events_since(hours=24)
        assert result["total"] == 0
        assert result["high_plus"] == 0
