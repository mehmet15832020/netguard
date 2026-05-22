"""
Analytics API — birim + entegrasyon testleri.
GET /api/v1/analytics/top-talkers
GET /api/v1/analytics/alert-volume
GET /api/v1/analytics/protocol-distribution
GET /api/v1/analytics/traffic-volume
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from server.main import app

_client = TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
#  Fixture
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def client(tmp_db, admin_token):
    _client.headers.update({"Authorization": f"Bearer {admin_token}"})
    yield _client
    _client.headers.pop("Authorization", None)


@pytest.fixture
def superadmin_client(tmp_db, superadmin_token):
    _client.headers.update({"Authorization": f"Bearer {superadmin_token}"})
    yield _client
    _client.headers.pop("Authorization", None)


def _insert_log(
    tmp_db,
    source_ip="1.2.3.4",
    destination_ip="5.6.7.8",
    destination_port=None,
    minutes_ago=5,
    received_at_minutes_ago=None,
    tenant_id="default",
    network_protocol=None,
):
    ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    ra = (datetime.now(timezone.utc) - timedelta(minutes=received_at_minutes_ago or minutes_ago)).isoformat()
    with tmp_db._connect() as conn:
        conn.execute(
            """
            INSERT INTO normalized_logs
              (log_id, raw_id, source_type, observer_hostname,
               timestamp, received_at, processed_at,
               severity, event_category, event_action,
               source_ip, destination_ip, destination_port,
               message, tags, tenant_id, network_protocol)
            VALUES (?, ?, 'test', 'test',
                    ?, ?, ?,
                    'info', 'network', 'connection',
                    ?, ?, ?,
                    'test', '[]', ?, ?)
            """,
            (
                str(uuid.uuid4()), str(uuid.uuid4()),
                ts, ra, ra,
                source_ip, destination_ip, destination_port,
                tenant_id, network_protocol,
            ),
        )


# ─────────────────────────────────────────────────────────────────────────────
#  1. Temel yapı
# ─────────────────────────────────────────────────────────────────────────────

class TestTopTalkersBasic:
    def test_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/analytics/top-talkers")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        resp = client.get("/api/v1/analytics/top-talkers")
        data = resp.json()
        assert "hours" in data
        assert "top_sources" in data
        assert "top_destinations" in data
        assert "top_dst_ports" in data

    def test_empty_db_returns_empty_lists(self, client):
        resp = client.get("/api/v1/analytics/top-talkers")
        data = resp.json()
        assert data["top_sources"] == []
        assert data["top_destinations"] == []
        assert data["top_dst_ports"] == []

    def test_default_hours_is_24(self, client):
        resp = client.get("/api/v1/analytics/top-talkers")
        assert resp.json()["hours"] == 24

    def test_hours_param_reflected_in_response(self, client):
        for h in [1, 6, 48, 168]:
            resp = client.get(f"/api/v1/analytics/top-talkers?hours={h}")
            assert resp.status_code == 200
            assert resp.json()["hours"] == h


# ─────────────────────────────────────────────────────────────────────────────
#  2. Doğrulama — geçersiz parametre
# ─────────────────────────────────────────────────────────────────────────────

class TestTopTalkersValidation:
    def test_hours_zero_returns_422(self, client):
        resp = client.get("/api/v1/analytics/top-talkers?hours=0")
        assert resp.status_code == 422

    def test_hours_169_returns_422(self, client):
        resp = client.get("/api/v1/analytics/top-talkers?hours=169")
        assert resp.status_code == 422

    def test_limit_zero_returns_422(self, client):
        resp = client.get("/api/v1/analytics/top-talkers?limit=0")
        assert resp.status_code == 422

    def test_limit_101_returns_422(self, client):
        resp = client.get("/api/v1/analytics/top-talkers?limit=101")
        assert resp.status_code == 422

    def test_hours_string_returns_422(self, client):
        resp = client.get("/api/v1/analytics/top-talkers?hours=DROP+TABLE")
        assert resp.status_code == 422

    def test_hours_overflow_returns_422(self, client):
        resp = client.get("/api/v1/analytics/top-talkers?hours=9999999999")
        assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
#  3. Kimlik doğrulama
# ─────────────────────────────────────────────────────────────────────────────

class TestTopTalkersAuth:
    def test_requires_auth_returns_401(self):
        c = TestClient(app)
        resp = c.get("/api/v1/analytics/top-talkers")
        assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
#  4. Multi-tenant izolasyon
# ─────────────────────────────────────────────────────────────────────────────

class TestTopTalkersTenantIsolation:
    def test_admin_sees_only_own_tenant(self, client, tmp_db, admin_token):
        _insert_log(tmp_db, source_ip="10.0.0.1", tenant_id="default")
        _insert_log(tmp_db, source_ip="10.0.0.2", tenant_id="other-tenant")

        resp = client.get("/api/v1/analytics/top-talkers")
        ips = [s["ip"] for s in resp.json()["top_sources"]]
        assert "10.0.0.1" in ips
        assert "10.0.0.2" not in ips

    def test_superadmin_sees_all_tenants(self, superadmin_client, tmp_db):
        _insert_log(tmp_db, source_ip="11.0.0.1", tenant_id="default")
        _insert_log(tmp_db, source_ip="11.0.0.2", tenant_id="other-tenant")

        resp = superadmin_client.get("/api/v1/analytics/top-talkers")
        ips = [s["ip"] for s in resp.json()["top_sources"]]
        assert "11.0.0.1" in ips
        assert "11.0.0.2" in ips


# ─────────────────────────────────────────────────────────────────────────────
#  5. Sıralama doğruluğu
# ─────────────────────────────────────────────────────────────────────────────

class TestTopTalkersOrdering:
    def test_top_sources_ordered_by_count_desc(self, client, tmp_db):
        for _ in range(5):
            _insert_log(tmp_db, source_ip="10.0.0.1")
        for _ in range(2):
            _insert_log(tmp_db, source_ip="10.0.0.2")
        _insert_log(tmp_db, source_ip="10.0.0.3")

        resp = client.get("/api/v1/analytics/top-talkers")
        sources = resp.json()["top_sources"]
        counts = [s["count"] for s in sources]
        assert counts == sorted(counts, reverse=True)
        assert sources[0]["ip"] == "10.0.0.1"
        assert sources[0]["count"] == 5

    def test_top_destinations_ordered_by_count_desc(self, client, tmp_db):
        for _ in range(4):
            _insert_log(tmp_db, destination_ip="8.8.8.8")
        for _ in range(2):
            _insert_log(tmp_db, destination_ip="1.1.1.1")

        resp = client.get("/api/v1/analytics/top-talkers")
        dests = resp.json()["top_destinations"]
        assert dests[0]["ip"] == "8.8.8.8"
        assert dests[0]["count"] == 4

    def test_top_dst_ports_ordered_by_count_desc(self, client, tmp_db):
        for _ in range(6):
            _insert_log(tmp_db, destination_port=443)
        for _ in range(3):
            _insert_log(tmp_db, destination_port=80)
        _insert_log(tmp_db, destination_port=22)

        resp = client.get("/api/v1/analytics/top-talkers")
        ports = resp.json()["top_dst_ports"]
        assert ports[0]["port"] == 443
        assert ports[0]["count"] == 6


# ─────────────────────────────────────────────────────────────────────────────
#  6. Limit parametresi
# ─────────────────────────────────────────────────────────────────────────────

class TestTopTalkersLimit:
    def test_limit_restricts_result_count(self, client, tmp_db):
        for i in range(10):
            _insert_log(tmp_db, source_ip=f"10.0.{i}.1")

        resp = client.get("/api/v1/analytics/top-talkers?limit=3")
        sources = resp.json()["top_sources"]
        assert len(sources) <= 3

    def test_limit_100_accepted(self, client):
        resp = client.get("/api/v1/analytics/top-talkers?limit=100")
        assert resp.status_code == 200

    def test_limit_1_accepted(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="1.1.1.1")
        _insert_log(tmp_db, source_ip="2.2.2.2")

        resp = client.get("/api/v1/analytics/top-talkers?limit=1")
        assert resp.status_code == 200
        assert len(resp.json()["top_sources"]) == 1


# ─────────────────────────────────────────────────────────────────────────────
#  7. Timestamp filtresi
# ─────────────────────────────────────────────────────────────────────────────

class TestTopTalkersTimestampFilter:
    def test_old_logs_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="9.9.9.9", minutes_ago=200)

        resp = client.get("/api/v1/analytics/top-talkers?hours=1")
        sources = resp.json()["top_sources"]
        assert not any(s["ip"] == "9.9.9.9" for s in sources)

    def test_recent_logs_included(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="7.7.7.7", minutes_ago=10)

        resp = client.get("/api/v1/analytics/top-talkers?hours=1")
        sources = resp.json()["top_sources"]
        assert any(s["ip"] == "7.7.7.7" for s in sources)

    def test_null_source_ip_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip=None)

        resp = client.get("/api/v1/analytics/top-talkers")
        sources = resp.json()["top_sources"]
        assert not any(s["ip"] is None for s in sources)

    def test_null_destination_port_excluded(self, client, tmp_db):
        _insert_log(tmp_db, destination_port=None)

        resp = client.get("/api/v1/analytics/top-talkers")
        ports = resp.json()["top_dst_ports"]
        assert not any(p["port"] is None for p in ports)

    def test_invalid_port_zero_excluded(self, client, tmp_db):
        _insert_log(tmp_db, destination_port=0)

        resp = client.get("/api/v1/analytics/top-talkers")
        ports = resp.json()["top_dst_ports"]
        assert not any(p["port"] == 0 for p in ports)

    def test_invalid_port_above_65535_excluded(self, client, tmp_db):
        _insert_log(tmp_db, destination_port=65536)

        resp = client.get("/api/v1/analytics/top-talkers")
        ports = resp.json()["top_dst_ports"]
        assert not any(p["port"] == 65536 for p in ports)


# ─────────────────────────────────────────────────────────────────────────────
#  Alert Volume helpers
# ─────────────────────────────────────────────────────────────────────────────

def _insert_alert(
    tmp_db,
    severity="info",
    minutes_ago=5,
    tenant_id="default",
):
    ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
    with tmp_db._connect() as conn:
        conn.execute(
            """
            INSERT INTO alerts
              (alert_id, agent_id, hostname, severity, status,
               metric, message, value, threshold, triggered_at, tenant_id)
            VALUES (?, ?, 'test-host', ?, 'active',
                    'cpu', 'test', 80.0, 70.0, ?, ?)
            """,
            (str(uuid.uuid4()), str(uuid.uuid4()), severity, ts, tenant_id),
        )


# ─────────────────────────────────────────────────────────────────────────────
#  8. Alert Volume — temel yapı
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeBasic:
    def test_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/analytics/alert-volume")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        data = client.get("/api/v1/analytics/alert-volume").json()
        assert "hours" in data
        assert "series" in data
        for sev in ("critical", "high", "warning", "info"):
            assert sev in data["series"]

    def test_empty_db_returns_zero_counts(self, client):
        data = client.get("/api/v1/analytics/alert-volume").json()
        for sev in ("critical", "high", "warning", "info"):
            assert all(p["v"] == 0 for p in data["series"][sev])

    def test_default_hours_is_24(self, client):
        assert client.get("/api/v1/analytics/alert-volume").json()["hours"] == 24

    def test_hours_param_reflected(self, client):
        for h in [1, 6, 48, 168]:
            assert client.get(f"/api/v1/analytics/alert-volume?hours={h}").json()["hours"] == h


# ─────────────────────────────────────────────────────────────────────────────
#  9. Alert Volume — doğrulama
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeValidation:
    def test_hours_zero_returns_422(self, client):
        assert client.get("/api/v1/analytics/alert-volume?hours=0").status_code == 422

    def test_hours_169_returns_422(self, client):
        assert client.get("/api/v1/analytics/alert-volume?hours=169").status_code == 422

    def test_string_hours_returns_422(self, client):
        assert client.get("/api/v1/analytics/alert-volume?hours=abc").status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
#  10. Alert Volume — kimlik doğrulama
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeAuth:
    def test_requires_auth(self):
        c = TestClient(app)
        assert c.get("/api/v1/analytics/alert-volume").status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
#  11. Alert Volume — severity ayrımı
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeSeverity:
    def test_severity_separation(self, client, tmp_db):
        for sev in ("critical", "high", "warning", "info"):
            _insert_alert(tmp_db, severity=sev)

        data = client.get("/api/v1/analytics/alert-volume").json()
        for sev in ("critical", "high", "warning", "info"):
            assert sum(p["v"] for p in data["series"][sev]) == 1

    def test_all_series_same_length_when_data_exists(self, client, tmp_db):
        _insert_alert(tmp_db, severity="critical")
        _insert_alert(tmp_db, severity="high")

        data = client.get("/api/v1/analytics/alert-volume").json()
        lengths = [len(data["series"][s]) for s in ("critical", "high", "warning", "info")]
        assert len(set(lengths)) == 1

    def test_unknown_severity_excluded_from_series(self, client, tmp_db):
        ts = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        with tmp_db._connect() as conn:
            conn.execute(
                """INSERT INTO alerts
                     (alert_id, agent_id, hostname, severity, status,
                      metric, message, value, threshold, triggered_at, tenant_id)
                   VALUES (?, ?, 'host', 'unknown', 'active',
                           'cpu', 'test', 80, 70, ?, 'default')""",
                (str(uuid.uuid4()), str(uuid.uuid4()), ts),
            )

        data = client.get("/api/v1/analytics/alert-volume").json()
        assert "unknown" not in data["series"]

    def test_multiple_alerts_same_severity_aggregated(self, client, tmp_db):
        for _ in range(3):
            _insert_alert(tmp_db, severity="critical")

        data = client.get("/api/v1/analytics/alert-volume").json()
        assert sum(p["v"] for p in data["series"]["critical"]) == 3


# ─────────────────────────────────────────────────────────────────────────────
#  12. Alert Volume — timestamp filtresi
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeTimestamp:
    def test_old_alerts_excluded(self, client, tmp_db):
        _insert_alert(tmp_db, severity="critical", minutes_ago=200)

        data = client.get("/api/v1/analytics/alert-volume?hours=1").json()
        assert sum(p["v"] for p in data["series"]["critical"]) == 0

    def test_recent_alerts_included(self, client, tmp_db):
        _insert_alert(tmp_db, severity="high", minutes_ago=10)

        data = client.get("/api/v1/analytics/alert-volume?hours=1").json()
        assert sum(p["v"] for p in data["series"]["high"]) == 1


# ─────────────────────────────────────────────────────────────────────────────
#  13. Alert Volume — sıralama
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeOrdering:
    def test_series_points_ordered_by_time_asc(self, client, tmp_db):
        _insert_alert(tmp_db, severity="critical", minutes_ago=120)
        _insert_alert(tmp_db, severity="critical", minutes_ago=60)
        _insert_alert(tmp_db, severity="critical", minutes_ago=5)

        data = client.get("/api/v1/analytics/alert-volume?hours=24").json()
        times = [p["t"] for p in data["series"]["critical"] if p["v"] > 0]
        assert times == sorted(times)


# ─────────────────────────────────────────────────────────────────────────────
#  14. Alert Volume — multi-tenant izolasyon
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeTenantIsolation:
    def test_admin_sees_only_own_tenant(self, client, tmp_db):
        _insert_alert(tmp_db, severity="critical", tenant_id="default")
        _insert_alert(tmp_db, severity="critical", tenant_id="other-tenant")

        data = client.get("/api/v1/analytics/alert-volume").json()
        assert sum(p["v"] for p in data["series"]["critical"]) == 1

    def test_superadmin_sees_all_tenants(self, superadmin_client, tmp_db):
        _insert_alert(tmp_db, severity="high", tenant_id="default")
        _insert_alert(tmp_db, severity="high", tenant_id="other-tenant")

        data = superadmin_client.get("/api/v1/analytics/alert-volume").json()
        assert sum(p["v"] for p in data["series"]["high"]) == 2

    def test_missing_where_clause_would_fail(self, client, tmp_db):
        _insert_alert(tmp_db, severity="warning", tenant_id="default")
        _insert_alert(tmp_db, severity="warning", tenant_id="other-tenant")
        _insert_alert(tmp_db, severity="warning", tenant_id="third-tenant")

        data = client.get("/api/v1/analytics/alert-volume").json()
        assert sum(p["v"] for p in data["series"]["warning"]) == 1


# ─────────────────────────────────────────────────────────────────────────────
#  15. Alert Volume — zero-fill & bounds
# ─────────────────────────────────────────────────────────────────────────────

class TestAlertVolumeZeroFill:
    def test_empty_db_returns_equal_length_series(self, client):
        data = client.get("/api/v1/analytics/alert-volume?hours=2").json()
        lengths = [len(data["series"][s]) for s in ("critical", "high", "warning", "info")]
        assert len(set(lengths)) == 1
        assert lengths[0] >= 2

    def test_sparse_data_still_aligned(self, client, tmp_db):
        _insert_alert(tmp_db, severity="critical", minutes_ago=90)

        data = client.get("/api/v1/analytics/alert-volume?hours=3").json()
        lengths = [len(data["series"][s]) for s in ("critical", "high", "warning", "info")]
        assert len(set(lengths)) == 1

    def test_future_triggered_at_excluded(self, client, tmp_db):
        future_ts = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
        with tmp_db._connect() as conn:
            conn.execute(
                """INSERT INTO alerts
                     (alert_id, agent_id, hostname, severity, status,
                      metric, message, value, threshold, triggered_at, tenant_id)
                   VALUES (?, ?, 'host', 'critical', 'active',
                           'cpu', 'test', 80, 70, ?, 'default')""",
                (str(uuid.uuid4()), str(uuid.uuid4()), future_ts),
            )

        data = client.get("/api/v1/analytics/alert-volume?hours=1").json()
        assert sum(p["v"] for p in data["series"]["critical"]) == 0


# ─────────────────────────────────────────────────────────────────────────────
#  Protocol Distribution tests
# ─────────────────────────────────────────────────────────────────────────────

class TestProtocolDistributionBasic:
    def test_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/analytics/protocol-distribution")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        data = client.get("/api/v1/analytics/protocol-distribution").json()
        assert "hours" in data
        assert "total" in data
        assert "protocols" in data

    def test_empty_db_returns_zero_total(self, client):
        data = client.get("/api/v1/analytics/protocol-distribution").json()
        assert data["total"] == 0
        assert data["protocols"] == []

    def test_default_hours_is_24(self, client):
        assert client.get("/api/v1/analytics/protocol-distribution").json()["hours"] == 24

    def test_hours_param_reflected(self, client):
        for h in [1, 6, 48, 168]:
            data = client.get(f"/api/v1/analytics/protocol-distribution?hours={h}").json()
            assert data["hours"] == h


class TestProtocolDistributionValidation:
    def test_hours_zero_returns_422(self, client):
        assert client.get("/api/v1/analytics/protocol-distribution?hours=0").status_code == 422

    def test_hours_169_returns_422(self, client):
        assert client.get("/api/v1/analytics/protocol-distribution?hours=169").status_code == 422

    def test_string_hours_returns_422(self, client):
        assert client.get("/api/v1/analytics/protocol-distribution?hours=x").status_code == 422


class TestProtocolDistributionAuth:
    def test_requires_auth(self):
        c = TestClient(app)
        assert c.get("/api/v1/analytics/protocol-distribution").status_code == 401


class TestProtocolDistributionData:
    def test_protocol_counted(self, client, tmp_db):
        _insert_log(tmp_db, network_protocol="tcp")
        _insert_log(tmp_db, network_protocol="tcp")
        _insert_log(tmp_db, network_protocol="udp")

        data = client.get("/api/v1/analytics/protocol-distribution").json()
        protos = {p["protocol"]: p for p in data["protocols"]}
        assert protos["tcp"]["count"] == 2
        assert protos["udp"]["count"] == 1
        assert data["total"] == 3

    def test_pct_sums_to_100(self, client, tmp_db):
        for proto in ("tcp", "tcp", "udp", "icmp"):
            _insert_log(tmp_db, network_protocol=proto)

        data = client.get("/api/v1/analytics/protocol-distribution").json()
        total_pct = sum(p["pct"] for p in data["protocols"])
        assert abs(total_pct - 100.0) < 0.5

    def test_ordered_by_count_desc(self, client, tmp_db):
        for _ in range(5):
            _insert_log(tmp_db, network_protocol="tcp")
        for _ in range(2):
            _insert_log(tmp_db, network_protocol="udp")
        _insert_log(tmp_db, network_protocol="icmp")

        data = client.get("/api/v1/analytics/protocol-distribution").json()
        counts = [p["count"] for p in data["protocols"]]
        assert counts == sorted(counts, reverse=True)
        assert data["protocols"][0]["protocol"] == "tcp"

    def test_null_protocol_excluded(self, client, tmp_db):
        _insert_log(tmp_db, network_protocol=None)

        data = client.get("/api/v1/analytics/protocol-distribution").json()
        assert data["total"] == 0

    def test_empty_string_protocol_excluded(self, client, tmp_db):
        _insert_log(tmp_db, network_protocol="")

        data = client.get("/api/v1/analytics/protocol-distribution").json()
        assert data["total"] == 0

    def test_protocol_lowercased(self, client, tmp_db):
        _insert_log(tmp_db, network_protocol="TCP")
        _insert_log(tmp_db, network_protocol="tcp")

        data = client.get("/api/v1/analytics/protocol-distribution").json()
        protos = {p["protocol"] for p in data["protocols"]}
        assert "tcp" in protos
        assert "TCP" not in protos
        tcp_count = next(p["count"] for p in data["protocols"] if p["protocol"] == "tcp")
        assert tcp_count == 2

    def test_old_logs_excluded(self, client, tmp_db):
        _insert_log(tmp_db, network_protocol="tcp", minutes_ago=200)

        data = client.get("/api/v1/analytics/protocol-distribution?hours=1").json()
        assert data["total"] == 0

    def test_recent_logs_included(self, client, tmp_db):
        _insert_log(tmp_db, network_protocol="udp", minutes_ago=10)

        data = client.get("/api/v1/analytics/protocol-distribution?hours=1").json()
        assert data["total"] == 1


class TestProtocolDistributionTenantIsolation:
    def test_admin_sees_only_own_tenant(self, client, tmp_db):
        _insert_log(tmp_db, network_protocol="tcp", tenant_id="default")
        _insert_log(tmp_db, network_protocol="udp", tenant_id="other-tenant")

        data = client.get("/api/v1/analytics/protocol-distribution").json()
        assert data["total"] == 1
        assert data["protocols"][0]["protocol"] == "tcp"

    def test_superadmin_sees_all_tenants(self, superadmin_client, tmp_db):
        _insert_log(tmp_db, network_protocol="tcp", tenant_id="default")
        _insert_log(tmp_db, network_protocol="udp", tenant_id="other-tenant")

        data = superadmin_client.get("/api/v1/analytics/protocol-distribution").json()
        assert data["total"] == 2


# ─────────────────────────────────────────────────────────────────────────────
#  Traffic Volume tests
# ─────────────────────────────────────────────────────────────────────────────

class TestTrafficVolumeBasic:
    def test_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/analytics/traffic-volume")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert "hours" in data
        assert "series" in data
        assert "internal" in data["series"]
        assert "external" in data["series"]

    def test_empty_db_returns_aligned_series(self, client):
        data = client.get("/api/v1/analytics/traffic-volume?hours=2").json()
        assert len(data["series"]["internal"]) == len(data["series"]["external"])
        assert len(data["series"]["internal"]) >= 2

    def test_default_hours_is_24(self, client):
        assert client.get("/api/v1/analytics/traffic-volume").json()["hours"] == 24

    def test_hours_param_reflected(self, client):
        for h in [1, 6, 48, 168]:
            data = client.get(f"/api/v1/analytics/traffic-volume?hours={h}").json()
            assert data["hours"] == h


class TestTrafficVolumeValidation:
    def test_hours_zero_returns_422(self, client):
        assert client.get("/api/v1/analytics/traffic-volume?hours=0").status_code == 422

    def test_hours_169_returns_422(self, client):
        assert client.get("/api/v1/analytics/traffic-volume?hours=169").status_code == 422

    def test_string_hours_returns_422(self, client):
        assert client.get("/api/v1/analytics/traffic-volume?hours=x").status_code == 422


class TestTrafficVolumeAuth:
    def test_requires_auth(self):
        c = TestClient(app)
        assert c.get("/api/v1/analytics/traffic-volume").status_code == 401


class TestTrafficVolumeDirection:
    def test_rfc1918_10x_is_internal(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["internal"]) == 1
        assert sum(p["v"] for p in data["series"]["external"]) == 0

    def test_rfc1918_192168_is_internal(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="192.168.1.100")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["internal"]) == 1

    def test_rfc1918_172_is_internal(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="172.16.0.1")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["internal"]) == 1

    def test_public_ip_is_external(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="8.8.8.8")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["external"]) == 1
        assert sum(p["v"] for p in data["series"]["internal"]) == 0

    def test_mixed_traffic_classified(self, client, tmp_db):
        for _ in range(3):
            _insert_log(tmp_db, source_ip="10.0.0.1")
        for _ in range(2):
            _insert_log(tmp_db, source_ip="1.1.1.1")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["internal"]) == 3
        assert sum(p["v"] for p in data["series"]["external"]) == 2

    def test_null_source_ip_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip=None)

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["internal"]) == 0
        assert sum(p["v"] for p in data["series"]["external"]) == 0

    def test_series_always_same_length(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1")
        _insert_log(tmp_db, source_ip="8.8.8.8")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert len(data["series"]["internal"]) == len(data["series"]["external"])

    def test_loopback_is_internal(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="127.0.0.1")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["internal"]) == 1

    def test_rfc1918_172_upper_boundary_is_internal(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="172.31.255.254")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["internal"]) == 1
        assert sum(p["v"] for p in data["series"]["external"]) == 0

    def test_rfc1918_172_above_range_is_external(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="172.32.0.1")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["external"]) == 1
        assert sum(p["v"] for p in data["series"]["internal"]) == 0

    def test_rfc1918_172_below_range_is_external(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="172.15.255.255")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["external"]) == 1
        assert sum(p["v"] for p in data["series"]["internal"]) == 0


class TestTrafficVolumeTimestamp:
    def test_old_logs_excluded(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", minutes_ago=200)

        data = client.get("/api/v1/analytics/traffic-volume?hours=1").json()
        assert sum(p["v"] for p in data["series"]["internal"]) == 0

    def test_recent_logs_included(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="8.8.8.8", minutes_ago=10)

        data = client.get("/api/v1/analytics/traffic-volume?hours=1").json()
        assert sum(p["v"] for p in data["series"]["external"]) == 1

    def test_received_at_determines_bucket_not_timestamp(self, client, tmp_db):
        # timestamp=3 saat önce (pencere dışı), received_at=5 dakika önce (pencere içi)
        # Gruplama received_at üzerinden yapılmalı → log dahil edilmeli
        _insert_log(tmp_db, source_ip="10.0.0.1", minutes_ago=180, received_at_minutes_ago=5)

        data = client.get("/api/v1/analytics/traffic-volume?hours=1").json()
        assert sum(p["v"] for p in data["series"]["internal"]) == 1


class TestTrafficVolumeTenantIsolation:
    def test_admin_sees_only_own_tenant(self, client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", tenant_id="default")
        _insert_log(tmp_db, source_ip="10.0.0.2", tenant_id="other-tenant")

        data = client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["internal"]) == 1

    def test_superadmin_sees_all_tenants(self, superadmin_client, tmp_db):
        _insert_log(tmp_db, source_ip="10.0.0.1", tenant_id="default")
        _insert_log(tmp_db, source_ip="10.0.0.2", tenant_id="other-tenant")

        data = superadmin_client.get("/api/v1/analytics/traffic-volume").json()
        assert sum(p["v"] for p in data["series"]["internal"]) == 2
